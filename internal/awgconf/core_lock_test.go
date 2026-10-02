//go:build routing

package awgconf

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/probe"
)

// TestCoreLockedDown runs the real core on the generated config and checks
// what it lets in from this machine's other programs, through the fork's own
// changes (listener/socks/assoc.go, hub/route/dpiswitch.go):
//
//   - the prober's direct listener takes its user alone, and UDP only from
//     a source an association of that user names;
//   - the API takes no config from outside the core's own file, and has no
//     download, upgrade or restart.
//
// build-mihomo.ps1 runs it after each build; by hand:
//
//	go test -tags routing -run TestCoreLockedDown ./internal/awgconf
func TestCoreLockedDown(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the core")
	}
	core := coreBinary(t)
	setupRouting(t, ctl.ModeOn, "none")
	out, err := RenderNoFirst()
	if err != nil {
		t.Fatal(err)
	}
	// the prober's direct listener as generated, on a free port
	i := strings.Index(out, "  - name: probe-direct\n")
	if i < 0 {
		t.Fatal("no probe-direct listener")
	}
	// up to the next listener, or the end of the section
	block := out[i:]
	end := strings.Index(block, "\n\n") + 1
	if j := strings.Index(block[1:], "\n  - name:") + 2; j > 1 && j < end {
		end = j
	}
	block = block[:end]
	port := freePort(t)
	block = strings.Replace(block, "    port: 7892\n", fmt.Sprintf("    port: %d\n", port), 1)
	if !strings.Contains(block, "    users:\n") {
		t.Fatalf("the listener has no users:\n%s", block)
	}
	api := freePort(t)
	ctrl, _ := startCore(t, core, coreSafe(t, out, "listeners:\n"+block, api, freePort(t)), api)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	d := probe.Dialer{Addr: addr, Timeout: 3 * time.Second, Pass: ctrl.secret}

	// TCP: the prober's user only
	sink := newSink(t)
	probe.RunTCP(probe.Dialer{Addr: addr, Timeout: 3 * time.Second}, "127.0.0.1", sink.port)
	probe.RunTCP(probe.Dialer{Addr: addr, Timeout: 3 * time.Second, Pass: "wrong"}, "127.0.0.1", sink.port)
	time.Sleep(300 * time.Millisecond)
	if n := sink.n.Load(); n != 0 {
		t.Errorf("TCP without the password: %d connections through", n)
	}
	probe.RunTCP(d, "127.0.0.1", sink.port)
	time.Sleep(300 * time.Millisecond)
	if n := sink.n.Load(); n != 1 {
		t.Errorf("TCP with the password: %d connections through, want 1", n)
	}

	// UDP: only what an association names
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	got := make(chan string, 8)
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			got <- string(buf[:n])
			echo.WriteToUDP(buf[:n], from)
		}
	}()
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port
	stray, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer stray.Close()
	hdr := []byte{0, 0, 0, 1, 127, 0, 0, 1, byte(echoPort >> 8), byte(echoPort)}
	stray.WriteToUDP(append(hdr, "stray"...), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	select {
	case s := <-got:
		t.Errorf("a datagram no association named went through: %q", s)
	case <-time.After(time.Second):
	}
	u, err := d.DialUDP()
	if err != nil {
		t.Fatalf("UDP associate with the password: %v", err)
	}
	defer u.Close()
	if _, err := u.WriteTo([]byte("probe"), echo.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-got:
		if s != "probe" {
			t.Errorf("the association's datagram arrived as %q", s)
		}
	case <-time.After(3 * time.Second):
		t.Error("the association's datagram did not go through")
	}
	u.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	if n, _, err := u.ReadFrom(buf); err != nil || string(buf[:n]) != "probe" {
		t.Errorf("the answer back: %q %v", buf[:n], err)
	}

	// the API
	ask := func(method, path, body string) int {
		req, _ := http.NewRequest(method, ctrl.base+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+ctrl.secret)
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for _, c := range []struct {
		method, path, body string
		want               int
	}{
		{"PUT", "/configs?force=true", `{"payload":"mode: global"}`, http.StatusForbidden},
		{"PUT", "/configs?force=true", `{"path":"C:\\Windows\\win.ini"}`, http.StatusForbidden},
		{"PATCH", "/configs", `{"allow-lan":true}`, http.StatusForbidden},
		// The routes gone are asked with GET, never with the POST they take:
		// a core that still has them answers 405 and does nothing. A POST
		// /upgrade sent to such a core, the one in dist, had it download an
		// upstream release over its own file and start that.
		{"GET", "/upgrade", "", http.StatusNotFound},
		{"GET", "/upgrade/ui", "", http.StatusNotFound},
		{"GET", "/upgrade/geo", "", http.StatusNotFound},
		{"GET", "/restart", "", http.StatusNotFound},
		{"GET", "/configs/geo", "", http.StatusNotFound},
	} {
		if code := ask(c.method, c.path, c.body); code != c.want {
			t.Errorf("%s %s %s: HTTP %d, want %d", c.method, c.path, c.body, code, c.want)
		}
	}
}
