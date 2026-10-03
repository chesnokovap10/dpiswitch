package dnscache

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The core asks the cache for the names it sends direct: its DNS client
// reaches 127.0.0.1 though its sockets are bound to the physical interface,
// as auto-detect-interface binds them under TUN. A core of the fork's
// (dist\mihomo.exe), without TUN, on ports of its own; the cache answers
// from a server of the tests'. Run with DPISWITCH_LIVE_CORE=1 and the
// interface's name in DPISWITCH_IFACE.
func TestLiveCore(t *testing.T) {
	iface := os.Getenv("DPISWITCH_IFACE")
	if os.Getenv("DPISWITCH_LIVE_CORE") == "" || iface == "" {
		t.Skip("runs the core: DPISWITCH_LIVE_CORE=1 DPISWITCH_IFACE=<interface>")
	}
	core, err := filepath.Abs(filepath.Join("..", "..", "dist", "mihomo.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(core); err != nil {
		t.Skip("no core built: ", err)
	}
	// a web server on this machine for the names asked: the core dials the
	// address the cache gives
	web, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer web.Close()
	go http.Serve(web, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "hello from ", r.Host) }))
	webPort := web.Addr().(*net.TCPAddr).Port

	srv := &fakeServer{answer: gives("127.0.0.1", 60)}
	fakeServers(t, map[string]*fakeServer{"udp://192.0.2.53": srv})
	old := listenAddr
	listenAddr = "127.0.0.1:0"
	defer func() { listenAddr = old }()
	s := newCache(t, "udp://192.0.2.53")
	if err := s.Serve(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	free := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	socks, api := free(), free()
	dir := t.TempDir()
	cfg := fmt.Sprintf(`mode: rule
log-level: debug
ipv6: false
interface-name: '%s'
external-controller: 127.0.0.1:%d
listeners:
  - name: in
    type: socks
    listen: 127.0.0.1
    port: %d
dns:
  enable: true
  ipv6: false
  nameserver:
    - 'udp://192.0.2.1'
  direct-nameserver:
    - 'udp://%s'
rules:
  - MATCH,DIRECT
`, iface, api, socks, Serving())
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(core, "-d", dir, "-f", filepath.Join(dir, "config.yaml"))
	out, _ := cmd.StdoutPipe()
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	var log strings.Builder
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			log.WriteString(sc.Text() + "\n")
		}
	}()
	defer func() {
		if t.Failed() {
			t.Logf("core's log:\n%s", log.String())
		}
	}()

	// the core's listener up
	var c net.Conn
	for end := time.Now().Add(10 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if c, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", socks)); err == nil {
			break
		}
		if time.Now().After(end) {
			t.Fatal("the core's listener did not come up")
		}
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	host := "cache-test.example"
	c.Write([]byte{5, 1, 0})
	io.ReadFull(c, make([]byte, 2))
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	c.Write(append(req, byte(webPort>>8), byte(webPort)))
	if _, err := io.ReadFull(c, make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	body, _ := io.ReadAll(c)
	if !strings.Contains(string(body), "hello from "+host) {
		t.Fatalf("through the core: %q", body)
	}
	if n := srv.asked.Load(); n != 1 {
		t.Errorf("the cache's server was asked %d times, want once", n)
	}
	t.Logf("the core resolved %s through the cache: %+v", host, s.stats().Counts)
}
