//go:build routing

package awgconf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
)

// TestCoreFailClosed runs the real core on tunnel only's config with both
// tunnels dead, and dials through every group that must never go direct: at
// start, before the health check has said anything, and once it has found
// both tunnels down. A connection reaching the local server is one that
// went DIRECT.
//
// routing_test.go walks the rules and groups the way the core walks them,
// and takes on trust the two things this checks for real: a fallback with
// all its members down keeps the first one (the dial fails, it does not go
// direct), and a member counts as alive until the first check says it is
// not. Neither is promised by the core's documentation -- a core update can
// change them with every other test still green. build-mihomo.ps1 runs this
// after each build; by hand:
//
//	go test -tags routing -run TestCoreFailClosed ./internal/awgconf
//
// The core is dist\mihomo.exe, or DPISWITCH_CORE. ~20 s; skipped with -short.
func TestCoreFailClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the core for ~20 s")
	}
	core := coreBinary(t)

	setupRouting(t, ctl.ModeTunnel, "both on")
	// keys the core takes; the endpoints are TEST-NET addresses nothing
	// answers on, so both tunnels are dead from the start
	key := func(b byte) string { return strings.Repeat("A", 42) + string(b) + "=" }
	for path, body := range map[string]string{
		paths.SourceConf():  "[Interface]\nPrivateKey = " + key('E') + "\nAddress = 10.8.1.3/32\n[Peer]\nPublicKey = " + key('I') + "\nEndpoint = 198.51.100.7:51820\n",
		paths.SourceConf2(): "[Interface]\nPrivateKey = " + key('M') + "\nAddress = 10.9.1.3/32\n[Peer]\nPublicKey = " + key('Q') + "\nEndpoint = 198.51.100.8:51820\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c, err := ParseFile(paths.SourceConf())
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.Render()
	if err != nil {
		t.Fatal(err)
	}

	// what may never go direct in tunnel only: the strict groups, and the
	// select groups as tunnel only chooses their members. "tunnel" (the
	// first tunnel, then direct) is the control: once the check finds the
	// tunnel down it must go direct -- or this test sees no leak at all.
	strict := []string{ctl.TunnelOneGroup, ctl.TunnelAnyGroup, ctl.Tunnel2StrictGroup,
		ctl.TunnelListsGroup, ctl.Tunnel2Group, ctl.TunnelRestGroup}
	control := ctl.TunnelSoftGroup
	groups := append(append([]string{}, strict...), control)

	socks := map[string]int{}
	var ls strings.Builder
	ls.WriteString("listeners:\n")
	for _, g := range groups {
		socks[g] = freePort(t)
		fmt.Fprintf(&ls, "  - name: in-%s\n    type: socks\n    listen: 127.0.0.1\n    port: %d\n    proxy: %s\n", g, socks[g], g)
	}
	api := freePort(t)
	ctrl, _ := startCore(t, core, coreSafe(t, out, ls.String(), api, freePort(t)), api)

	// one local server per group: a connection it takes is a leak of that group
	servers := map[string]*sink{}
	for _, g := range groups {
		servers[g] = newSink(t)
	}
	dialAll := func(gs []string) {
		var wg sync.WaitGroup
		for _, g := range gs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				socksDial(socks[g], servers[g].port)
			}()
		}
		wg.Wait()
		time.Sleep(300 * time.Millisecond)
	}

	// at start: the check has not finished (its timeout is 15 s)
	dialAll(strict)
	for _, g := range strict {
		if n := servers[g].n.Load(); n > 0 {
			t.Errorf("at start: %s went direct (%d connections)", g, n)
		}
	}

	// the check finds both tunnels down: the control group turns direct
	deadline := time.Now().Add(45 * time.Second)
	for ctrl.now(control) != "DIRECT" {
		if time.Now().After(deadline) {
			t.Fatalf("the health check never found the tunnels down: %s is on %q", control, ctrl.now(control))
		}
		time.Sleep(500 * time.Millisecond)
	}
	dialAll(groups)
	if servers[control].n.Load() == 0 {
		t.Errorf("the control %s did not reach the local server: the test would see no leak", control)
	}
	for _, g := range strict {
		if n := servers[g].n.Load(); n > 0 {
			t.Errorf("both tunnels down: %s went direct (%d connections), it is on %q", g, n, ctrl.now(g))
		}
	}
	// and what the core says it is on: a tunnel or REJECT (a group left
	// with no member), never DIRECT or COMPATIBLE
	for _, g := range []string{ctl.TunnelOneGroup, ctl.TunnelAnyGroup, ctl.Tunnel2StrictGroup} {
		if now := ctrl.now(g); now != "awg" && now != "awg2" && now != "REJECT" {
			t.Errorf("both tunnels down: %s is on %q", g, now)
		}
	}
}

// coreBinary: the core the checks run, dist\mihomo.exe or DPISWITCH_CORE;
// with none there the test is skipped
func coreBinary(t *testing.T) string {
	t.Helper()
	core := os.Getenv("DPISWITCH_CORE")
	if core == "" {
		core, _ = filepath.Abs(filepath.Join("..", "..", "dist", "mihomo.exe"))
	}
	if _, err := os.Stat(core); err != nil {
		t.Skipf("no core to run (%v): build it with tools\\build-mihomo.ps1 or set DPISWITCH_CORE", err)
	}
	return core
}

// startCore writes cfg as the data directory's config, runs the core on it
// and waits for its controller on port api. The core is stopped when the
// test ends, its log shown if the test failed.
func startCore(t *testing.T, core, cfg string, api int) (*coreAPI, *coreLog) {
	t.Helper()
	secret := regexp.MustCompile(`(?m)^secret: '([^']*)'`).FindStringSubmatch(cfg)
	if secret == nil {
		t.Fatal("no secret in the config")
	}
	if err := os.WriteFile(paths.Config(), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	log := &coreLog{}
	cmd := exec.Command(core, "-d", paths.DataDir(), "-f", paths.Config())
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Logf("the core's log:\n%s", log.String())
		}
	})
	ctrl := &coreAPI{base: fmt.Sprintf("http://127.0.0.1:%d", api), secret: secret[1]}
	if !ctrl.wait(15 * time.Second) {
		t.Fatal("the core did not come up")
	}
	return ctrl, log
}

// coreLog: the core's output, read while it is written
type coreLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *coreLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *coreLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// coreSafe: the config made to run beside the service and without admin
// rights -- no TUN, the controller and the DNS listener on free ports, the
// listeners given in place of the prober's
func coreSafe(t *testing.T, out, listeners string, api, dns int) string {
	t.Helper()
	i, j := strings.Index(out, "\nlisteners:\n"), strings.Index(out, "\ntun:\n")
	if i < 0 || j < i {
		t.Fatal("no listeners or tun section in the config")
	}
	out = out[:i+1] + listeners + out[j:]
	for old, repl := range map[string]string{
		"external-controller: 127.0.0.1:9090\n": fmt.Sprintf("external-controller: 127.0.0.1:%d\n", api),
		"\ntun:\n  enable: true\n":              "\ntun:\n  enable: false\n",
		"  listen: 127.0.0.1:1053\n":            fmt.Sprintf("  listen: 127.0.0.1:%d\n", dns),
	} {
		if strings.Count(out, old) != 1 {
			t.Fatalf("the config no longer has %q once: coreSafe needs updating", old)
		}
		out = strings.Replace(out, old, repl, 1)
	}
	return out
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// sink: a local server counting the connections it takes
type sink struct {
	port int
	n    atomic.Int32
}

func newSink(t *testing.T) *sink {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	s := &sink{port: l.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			s.n.Add(1)
			c.Close()
		}
	}()
	return s
}

// socksDial: a SOCKS5 CONNECT to 127.0.0.1:port through the listener on
// socksPort. The outcome does not matter: the sink counts what arrives.
func socksDial(socksPort, port int) {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 2*time.Second)
	if err != nil {
		return
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		return
	}
	req := []byte{5, 1, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}
	if _, err := c.Write(req); err != nil {
		return
	}
	io.ReadFull(c, make([]byte, 10))
}

// coreAPI: the core's controller
type coreAPI struct{ base, secret string }

func (a *coreAPI) get(path string, v any) error {
	req, _ := http.NewRequest("GET", a.base+path, nil)
	req.Header.Set("Authorization", "Bearer "+a.secret)
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func (a *coreAPI) wait(d time.Duration) bool {
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		var v map[string]any
		if a.get("/version", &v) == nil {
			return true
		}
	}
	return false
}

// now: the member a group is on, as the core reports it
func (a *coreAPI) now(group string) string {
	var p struct{ Now string }
	if err := a.get("/proxies/"+group, &p); err != nil {
		return "(" + err.Error() + ")"
	}
	return p.Now
}
