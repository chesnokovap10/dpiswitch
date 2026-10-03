//go:build routing

package awgconf

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
)

// TestCoreTables: the tables of the help, cell by cell, on the real core.
// TestRouting walks the rules and groups as the core walks them; this runs
// the core on the same config, with each tunnel loaded made alive or dead
// for real, and asks it where a connection to each column's name goes: the
// rule and the group from the core's log, the member a group is on from its
// controller -- after the health check has had its say.
//
// An alive tunnel is a WireGuard peer on this machine (tools/wgpeer): it
// takes the tunnel and answers the health check, whatever address it asks.
// A dead one points at an address nothing answers on. The check's timeout
// is 3 s in place of 15, so a dead tunnel is found dead in seconds; the rest
// of the config is the service's. Direct, the check asks the internet, as
// the service's does: DIRECT is a member of the groups and checked too.
//
//	go test -tags routing -run TestCoreTables ./internal/awgconf
//
// ~2 min; skipped with -short. The core as in TestCoreFailClosed.
// WGPEER_DEBUG=1 shows what the peers do.
func TestCoreTables(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the core ~45 times")
	}
	core := coreBinary(t)
	peer := buildPeer(t)
	n := 0
	for _, mode := range []string{ctl.ModeOn, ctl.ModeObserve, ctl.ModeTunnel} {
		for _, r := range routingTables[mode] {
			for _, alive := range aliveSets(tunnelsOf(r.loaded)) {
				t.Run(fmt.Sprintf("%s/%s/%s", mode, r.loaded, aliveName(alive)), func(t *testing.T) {
					n += coreCells(t, core, peer, mode, r, alive)
				})
			}
		}
	}
	if !t.Failed() && n == 0 {
		t.Error("no cell checked")
	}
	t.Logf("%d cells checked on the core", n)
}

// tunnelsOf: the tunnels a table's row loads, by their proxy names
func tunnelsOf(loaded string) []string {
	var out []string
	if loaded == "awg1" || strings.HasPrefix(loaded, "both") {
		out = append(out, "awg1")
	}
	if strings.HasPrefix(loaded, "awg2") || strings.HasPrefix(loaded, "both") {
		out = append(out, "awg2")
	}
	return out
}

func aliveName(alive map[string]bool) string {
	var up []string
	for _, tn := range []string{"awg1", "awg2"} {
		if alive[tn] {
			up = append(up, tn)
		}
	}
	if len(up) == 0 {
		return "all down"
	}
	return strings.Join(up, "+") + " up"
}

// coreCells runs the core for one row of a table with the tunnels alive as
// given, and checks the row's cells; it returns how many
func coreCells(t *testing.T, core, peer, mode string, r row, alive map[string]bool) int {
	_, tunnels := setupRouting(t, mode, r.loaded)
	// the configs again, with keys the core takes and endpoints alive or dead
	for _, tn := range tunnels {
		path, dead, addr := paths.SourceConf(), "198.51.100.7", "10.8.1.3/32"
		if tn == "awg2" {
			path, dead, addr = paths.SourceConf2(), "198.51.100.8", "10.9.1.3/32"
		}
		cPriv, cPub := wgKeys(t)
		sPriv, sPub := wgKeys(t)
		endpoint := fmt.Sprintf("%s:51820", dead)
		if alive[tn] {
			port := startPeer(t, peer, sPriv, cPub)
			endpoint = fmt.Sprintf("127.0.0.1:%d", port)
		}
		conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\n[Peer]\nPublicKey = %s\nEndpoint = %s\n",
			b64(cPriv), addr, b64(sPub), endpoint)
		if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var out string
	var err error
	if slices.Contains(tunnels, "awg1") {
		c, err := ParseFile(paths.SourceConf())
		if err != nil {
			t.Fatal(err)
		}
		out, err = c.Render()
		if err != nil {
			t.Fatal(err)
		}
	} else if out, err = RenderNoFirst(); err != nil {
		t.Fatal(err)
	}

	// the health check quick to find a tunnel dead
	if len(tunnels) > 0 && !strings.Contains(out, "    timeout: 15000\n") {
		t.Fatal("the config no longer has the check's timeout of 15 s: the test needs updating")
	}
	out = strings.ReplaceAll(out, "    timeout: 15000\n", "    timeout: 3000\n")
	socks, api := freePort(t), freePort(t)
	ls := fmt.Sprintf("listeners:\n  - name: in-rules\n    type: socks\n    listen: 127.0.0.1\n    port: %d\n", socks)
	ctrl, log := startCore(t, core, coreSafe(t, out, ls, api, freePort(t)), api)

	// the check has had its say on every tunnel loaded
	for _, tn := range tunnels {
		deadline := time.Now().Add(20 * time.Second)
		for {
			up, checked := ctrl.alive(tn, ctl.HealthURL)
			if checked && up == alive[tn] {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: checked %v, alive %v, want alive %v", tn, checked, up, alive[tn])
			}
			time.Sleep(200 * time.Millisecond)
		}
	}

	// DIRECT alive too, as the tables take it: its check asks the internet
	// with the short timeout, and a slow answer would leave a group with
	// every member down on its first, a dead tunnel
	for i := 0; ; i++ {
		if up, checked := ctrl.alive("DIRECT", ctl.HealthURL); up || !checked {
			break
		}
		if i == 3 {
			t.Fatal("DIRECT's health check fails: the internet does not answer it")
		}
		var d map[string]any
		ctrl.get("/proxies/DIRECT/delay?timeout=10000&url="+url.QueryEscape(ctl.HealthURL), &d)
	}

	cells := []struct {
		col, host string
		want      route
	}{
		{"what no list names", hostUnnamed, r.unnamed},
		{"a clean site", hostClean, r.clean},
		{"a preset", hostPreset, r.preset},
		{"the awg2 list", hostAwg2, r.awg2},
		{"Always via tunnel", hostTunnel, r.tunnel},
		{"Always direct", hostDirect, r.direct},
		{"Forbidden", hostBlock, r.block},
	}
	var wg sync.WaitGroup
	for _, c := range cells {
		wg.Add(1)
		go func() {
			defer wg.Done()
			socksDialHost(socks, c.host, 80)
		}()
	}
	wg.Wait()
	for _, c := range cells {
		rule, target := routedBy(t, log, c.host)
		got, path := ctrl.resolve(target)
		// a tunnel down refuses: the core has nothing to send it by
		if (got == "awg1" || got == "awg2") && !alive[got] {
			got = "REJECT"
		}
		if want := c.want.want(alive); got != want {
			t.Errorf("%s (%s): %s, want %s -- rule %s, %s", c.col, c.want, got, want, rule, path)
			// what the core says of each hop, to see why
			for _, p := range strings.Split(path, " > ") {
				var raw map[string]any
				ctrl.get("/proxies/"+p, &raw)
				t.Logf("  %s: now %v, members %v, alive %v", p, raw["now"], raw["all"], raw["alive"])
			}
		}
	}
	return len(cells)
}

// routedBy: the rule that took the connection to host and where it sent it,
// from the core's log -- the chain when the dial went through, the proxy or
// group the rule names when it failed
var (
	usingRe = regexp.MustCompile(`--> (\S+) match (\S+) using ([^\s"]+)`)
	dialRe  = regexp.MustCompile(`dial (\S+) \(match ([^)]*)\) \S+ --> (\S+) error`)
)

func routedBy(t *testing.T, log *coreLog, host string) (rule, target string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		for _, l := range strings.Split(log.String(), "\n") {
			if m := usingRe.FindStringSubmatch(l); m != nil && m[1] == fmt.Sprintf("%s:80", host) {
				return m[2], m[3]
			}
			if m := dialRe.FindStringSubmatch(l); m != nil && m[3] == fmt.Sprintf("%s:80", host) {
				return m[2], m[1]
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the core logged nothing for %s", host)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// resolve: the proxy a chain or a group ends on. A chain as the log writes
// it, "tunnel2[tunnel2-soft][awg2]", ends on its last; a group is followed
// through the members the controller says it is on.
func (a *coreAPI) resolve(target string) (proxy, path string) {
	if i := strings.LastIndex(target, "["); i >= 0 {
		return strings.TrimSuffix(target[i+1:], "]"), target
	}
	name, hops := target, []string{target}
	for range 8 {
		switch name {
		case "awg1", "awg2", "DIRECT", "REJECT", "COMPATIBLE":
			return name, strings.Join(hops, " > ")
		}
		name = a.now(name)
		hops = append(hops, name)
	}
	return name, strings.Join(hops, " > ")
}

// alive: whether the health check at url found the proxy up, and whether it
// has checked it at all
func (a *coreAPI) alive(proxy, url string) (up, checked bool) {
	var p struct {
		Extra map[string]struct {
			Alive   bool
			History []any
		}
	}
	if err := a.get("/proxies/"+proxy, &p); err != nil {
		return false, false
	}
	e, ok := p.Extra[url]
	return e.Alive, ok && len(e.History) > 0
}

// socksDialHost: a SOCKS5 CONNECT to host:port by name, through the
// listener on socksPort, which routes by the rules
func socksDialHost(socksPort int, host string, port int) {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 2*time.Second)
	if err != nil {
		return
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		return
	}
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		return
	}
	io.ReadFull(c, make([]byte, 10))
}

// wgKeys: a WireGuard key pair
func wgKeys(t *testing.T) (priv, pub []byte) {
	t.Helper()
	priv = make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	priv[0] &= 248
	priv[31] = priv[31]&127 | 64
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func b64(k []byte) string { return base64.StdEncoding.EncodeToString(k) }

var (
	peerOnce sync.Once
	peerPath string
	peerErr  error
)

// buildPeer: tools/wgpeer, built once for the run
func buildPeer(t *testing.T) string {
	t.Helper()
	peerOnce.Do(func() {
		dir, err := os.MkdirTemp("", "wgpeer")
		if err != nil {
			peerErr = err
			return
		}
		peerPath = filepath.Join(dir, "wgpeer.exe")
		cmd := exec.Command("go", "build", "-o", peerPath, ".")
		cmd.Dir = filepath.Join("..", "..", "tools", "wgpeer")
		if out, err := cmd.CombinedOutput(); err != nil {
			peerErr = fmt.Errorf("building tools/wgpeer: %v\n%s", err, out)
		}
	})
	if peerErr != nil {
		t.Fatal(peerErr)
	}
	return peerPath
}

// startPeer runs a WireGuard peer that takes the client with public key
// cPub, and returns its UDP port. It stops when the test ends.
func startPeer(t *testing.T, peer string, sPriv, cPub []byte) int {
	t.Helper()
	port := freeUDPPort(t)
	cmd := exec.Command(peer, "-port", fmt.Sprint(port), "-key", hex.EncodeToString(sPriv), "-peer", hex.EncodeToString(cPub))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stdin.Close()
		cmd.Process.Kill()
		cmd.Wait()
	})
	ready := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if sc.Text() == "ready" {
				close(ready)
				continue
			}
			if os.Getenv("WGPEER_DEBUG") != "" {
				fmt.Fprintln(os.Stderr, "wgpeer:", sc.Text())
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(10 * time.Second):
		t.Fatal("wgpeer did not start")
	}
	return port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}
