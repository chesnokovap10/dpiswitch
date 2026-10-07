package probe

import (
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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

// With no tunnel the cut path takes its place: a name cut on its hello
// direct is CLEAN_SPLIT when the cut gets a valid certificate and an
// answer, BLOCKED_TLS when it does not; one that works as it is, CLEAN.
func TestCheckAlone(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	chainRoots = pool
	defer func() { chainRoots = nil }()
	target := srv.Listener.Addr().String()
	// the name the test server's certificate has, resolved by the stub
	ip := func(d Dialer) Dialer {
		d.DNS = []Resolver{{Raw: "stub", Scheme: "stub"}}
		return d
	}
	oldLookup := lookupAnyFn
	lookupAnyFn = func(Dialer, []Resolver, string) ([]string, error) { return []string{"192.0.2.10"}, nil }
	defer func() { lookupAnyFn = oldLookup }()

	open := ip(Dialer{Addr: forwardStub(t, target, false), Timeout: 2 * time.Second})
	cut := ip(Dialer{Addr: forwardStub(t, target, true), Timeout: 2 * time.Second})

	if r := CheckAlone(cut, open, "example.com", 2, ""); r.Verdict != CleanSplit || r.TestedIP != "192.0.2.10" {
		t.Errorf("cut direct, the cut works: %s (%s)", r.Verdict, r.Reason)
	}
	if r := CheckAlone(cut, cut, "example.com", 2, ""); r.Verdict != BlockedTLS {
		t.Errorf("cut both ways: %s (%s)", r.Verdict, r.Reason)
	}
	if r := CheckAlone(open, cut, "example.com", 2, ""); r.Verdict != Clean {
		t.Errorf("works as it is: %s (%s)", r.Verdict, r.Reason)
	}
	// a certificate not of the name is no proof: the cut path's answer
	// may be anyone's
	if r := CheckAlone(cut, open, "other.example", 2, ""); r.Verdict != BlockedTLS {
		t.Errorf("a foreign certificate with the cut: %s (%s)", r.Verdict, r.Reason)
	}
}

// The cut gets the site's own answer and the tunnel another -- the server
// answering the tunnel's country (music.youtube.com: 200 here, 302 there).
// With a certificate that passes the chain check the ISP cannot have
// forged it: CLEAN_SPLIT. Without one the difference may be anyone's.
func TestCheckSplitServerDiffers(t *testing.T) {
	answer := func(code int) string {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if code == http.StatusFound {
				w.Header().Set("Location", "https://example.com/unavailable")
			}
			w.WriteHeader(code)
		}))
		t.Cleanup(srv.Close)
		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())
		if chainRoots == nil {
			chainRoots = pool
		} else {
			chainRoots.AddCert(srv.Certificate())
		}
		return srv.Listener.Addr().String()
	}
	defer func() { chainRoots = nil }()
	here, there := answer(http.StatusOK), answer(http.StatusFound)
	split := Dialer{Addr: forwardStub(t, here, false), Timeout: 2 * time.Second}
	tunnel := Dialer{Addr: forwardStub(t, there, false), Timeout: 2 * time.Second}
	plain := Report{Domain: "example.com", Port: 443, Verdict: BlockedTLS, TestedIP: "192.0.2.10"}
	if r := CheckSplit(split, tunnel, plain, 3, BlockedTLS); r.Verdict != CleanSplit || strings.Count(r.Note, serverOwn) != 1 {
		t.Errorf("verified answer, differing from the tunnel's: %s (%s), note %q", r.Verdict, r.Reason, r.Note)
	}
	chainRoots = x509.NewCertPool()
	if r := CheckSplit(split, tunnel, plain, 2, BlockedTLS); r.Verdict != ContentDiff {
		t.Errorf("unverified answer, differing from the tunnel's: %s (%s)", r.Verdict, r.Reason)
	}
}

// The cut gets the site's own answer and the tunnel none: the cut works,
// only the speed is not compared -- CLEAN_SPLIT, not the plain path's
// block. Without a verified answer the tunnel's silence decides nothing.
func TestCheckSplitTunnelSilent(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	chainRoots = pool
	defer func() { chainRoots = nil }()
	target := srv.Listener.Addr().String()
	split := Dialer{Addr: forwardStub(t, target, false), Timeout: 2 * time.Second}
	silent := Dialer{Addr: forwardStub(t, target, true), Timeout: 2 * time.Second}
	plain := Report{Domain: "example.com", Port: 443, Verdict: BlockedTLS, TestedIP: "192.0.2.10"}
	r := CheckSplit(split, silent, plain, 2, BlockedTLS)
	if r.Verdict != CleanSplit || strings.Count(r.Note, tunnelSilent) != 1 || r.Unmeasured {
		t.Fatalf("cut answers, tunnel silent: %s (%s), note %q", r.Verdict, r.Reason, r.Note)
	}
	if r.DirectMs != 0 || r.TunnelMs != 0 {
		t.Errorf("speed reported with nothing to compare: %d vs %d", r.DirectMs, r.TunnelMs)
	}
	chainRoots = x509.NewCertPool()
	if r := CheckSplit(split, silent, plain, 2, BlockedTLS); r.Verdict == CleanSplit {
		t.Errorf("an unverified answer with the tunnel silent: %s (%s)", r.Verdict, r.Reason)
	}
}
