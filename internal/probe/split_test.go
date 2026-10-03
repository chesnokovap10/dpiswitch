package probe

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// forwardStub: a SOCKS5 listener with no password that takes a CONNECT to
// anywhere to target. cut: it drops the connection once the client sends
// anything -- the DPI box on a path that does not let the hello through.
func forwardStub(t *testing.T, target string, cut bool) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 512)
				if _, err := io.ReadFull(c, buf[:2]); err != nil {
					return
				}
				io.ReadFull(c, buf[:buf[1]])
				c.Write([]byte{5, 0})
				if _, err := io.ReadFull(c, buf[:10]); err != nil { // VER CMD RSV ATYP=1 ADDR PORT
					return
				}
				c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				if cut {
					c.Read(buf)
					return
				}
				up, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer up.Close()
				go io.Copy(up, c)
				io.Copy(c, up)
			}()
		}
	}()
	return ln.Addr().String()
}

// A name blocked by its hello is CLEAN_SPLIT when the cut path gets through
// as well as the tunnel; when the cut does not help, the verdict is the
// block the cut path met, on the same node the plain check probed.
func TestCheckSplit(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	}))
	defer srv.Close()
	target := srv.Listener.Addr().String()
	tunnel := Dialer{Addr: forwardStub(t, target, false), Timeout: 2 * time.Second}
	plain := Report{Domain: "ig.example.org", Port: 443, Verdict: BlockedTLS, TestedIP: "192.0.2.10"}

	ok := Dialer{Addr: forwardStub(t, target, false), Timeout: 2 * time.Second}
	r := CheckSplit(ok, tunnel, plain, 2, BlockedTLS)
	if r.Verdict != CleanSplit || r.TestedIP != "192.0.2.10" || r.Domain != "ig.example.org" {
		t.Fatalf("cut path clean: %s (%s) on %s", r.Verdict, r.Reason, r.TestedIP)
	}
	if r.Direct.HTTPStatus != 200 {
		t.Errorf("no request made through the cut path: %+v", r.Direct)
	}

	cut := Dialer{Addr: forwardStub(t, target, true), Timeout: 2 * time.Second}
	if r := CheckSplit(cut, tunnel, plain, 2, BlockedTLS); r.Verdict != BlockedTLS {
		t.Fatalf("cut path blocked too: %s (%s)", r.Verdict, r.Reason)
	}
}
