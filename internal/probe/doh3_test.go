package probe

import (
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func doh3TestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, Resolver, func()) {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.EnableHTTP2 = true
	s.StartTLS()
	t.Cleanup(s.Close)
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	old := resolverRoots
	resolverRoots = roots
	t.Cleanup(func() {
		doh3Clients.Range(func(k, v any) bool {
			v.(*doh3Client).client.Transport.(*http3.Transport).Close()
			doh3Clients.Delete(k)
			return true
		})
		resolverRoots = old
	})
	r, err := ParseResolver(s.URL + "/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	startH3 := func() {
		pc, err := net.ListenPacket("udp", s.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		h3 := &http3.Server{TLSConfig: s.TLS.Clone(), Handler: handler}
		go h3.Serve(pc)
		t.Cleanup(func() { h3.Close(); pc.Close() })
	}
	return s, r, startH3
}

func dnsWireAnswer(w http.ResponseWriter, r *http.Request) {
	q, _ := io.ReadAll(r.Body)
	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(answerWith(q, binary.BigEndian.Uint16(q)))
}

func TestDoH3PreferredAndKept(t *testing.T) {
	var h3, tcp atomic.Int32
	var peers sync.Map
	_, r, start := doh3TestServer(t, func(w http.ResponseWriter, req *http.Request) {
		if req.ProtoMajor == 3 {
			h3.Add(1)
			peers.Store(req.RemoteAddr, true)
			time.Sleep(5 * time.Millisecond)
		} else {
			tcp.Add(1)
		}
		dnsWireAnswer(w, req)
	})
	start()
	d := Dialer{Direct: true, Timeout: 3 * time.Second}
	ips, _, used, kind, err := PingEitherProtocol(d, r.Raw, "a.example.org")
	if err != nil || kind != "DoH3" || used != r.Raw || len(ips) != 1 {
		t.Fatalf("%v %s %s %v", ips, used, kind, err)
	}
	q, _ := buildQuery("a.example.org", typeA)
	if _, err := r.Exchange(d, q); err != nil {
		t.Fatal(err)
	}
	if h3.Load() != 3 || tcp.Load() != 0 {
		t.Fatalf("h3=%d tcp=%d", h3.Load(), tcp.Load())
	}
	n := 0
	peers.Range(func(_, _ any) bool { n++; return true })
	if n != 1 {
		t.Fatalf("queries opened %d QUIC connections", n)
	}
}

func TestDoH3FallbackAndRecovery(t *testing.T) {
	_, r, start := doh3TestServer(t, dnsWireAnswer)
	d := Dialer{Direct: true, Timeout: 900 * time.Millisecond}
	q, _ := buildQuery("a.example.org", typeA)
	if _, kind, err := r.dohProtocol(d, q); err != nil || kind != "DoH" {
		t.Fatalf("fallback: %s %v", kind, err)
	}
	c := r.doh3Client(d)
	c.mu.Lock()
	retry := c.retryAfter
	c.mu.Unlock()
	if !retry.After(time.Now()) {
		t.Fatal("failed path is not backed off")
	}
	start()
	if _, kind, err := r.dohProtocol(d, q); err != nil || kind != "DoH" {
		t.Fatalf("cooldown: %s %v", kind, err)
	}
	c.mu.Lock()
	c.retryAfter = time.Time{}
	c.mu.Unlock()
	if _, kind, err := r.dohProtocol(d, q); err != nil || kind != "DoH3" {
		t.Fatalf("recovery: %s %v", kind, err)
	}
}

func TestDoH3BlockedUDPLeavesTimeForFallback(t *testing.T) {
	s, r, _ := doh3TestServer(t, dnsWireAnswer)
	blackhole, err := net.ListenPacket("udp", s.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	d := Dialer{Direct: true, Timeout: 900 * time.Millisecond}
	q, _ := buildQuery("a.example.org", typeA)
	start := time.Now()
	if _, kind, err := r.dohProtocol(d, q); err != nil || kind != "DoH" {
		t.Fatalf("blocked UDP fallback: %s %v", kind, err)
	}
	if time.Since(start) >= d.Timeout {
		t.Fatal("QUIC used up the fallback deadline")
	}
}

func TestDoH3PingReportsTimedRequest(t *testing.T) {
	var h3 atomic.Int32
	_, r, start := doh3TestServer(t, func(w http.ResponseWriter, req *http.Request) {
		if req.ProtoMajor == 3 && h3.Add(1) > 1 {
			http.Error(w, "temporary failure", 503)
			return
		}
		dnsWireAnswer(w, req)
	})
	start()
	_, _, _, kind, err := PingEitherProtocol(Dialer{Direct: true, Timeout: 3 * time.Second}, r.Raw, "a.example.org")
	if err != nil || kind != "DoH" || h3.Load() != 2 {
		t.Fatalf("warm-up is H3, timed query falls back: %s %v (%d H3 requests)", kind, err, h3.Load())
	}
}

func TestDoH3PathAlternative(t *testing.T) {
	_, r, start := doh3TestServer(t, func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/dns-query" {
			http.NotFound(w, req)
			return
		}
		dnsWireAnswer(w, req)
	})
	start()
	base := "https://" + net.JoinHostPort(r.Host, strconv.Itoa(r.Port))
	_, _, used, kind, err := PingEitherProtocol(Dialer{Direct: true, Timeout: 3 * time.Second}, base, "a.example.org")
	if err != nil || used != r.Raw || kind != "DoH3" {
		t.Fatalf("path fallback: %s %s %v", used, kind, err)
	}
}

func TestDoH3VerifiesCertificate(t *testing.T) {
	_, r, start := doh3TestServer(t, dnsWireAnswer)
	start()
	resolverRoots = x509.NewCertPool()
	q, _ := buildQuery("a.example.org", typeA)
	if _, _, err := r.dohProtocol(Dialer{Direct: true, Timeout: time.Second}, q); err == nil {
		t.Fatal("untrusted resolver certificate accepted")
	}
}

func TestDoH3ViaSOCKSHostname(t *testing.T) {
	s, r, start := doh3TestServer(t, dnsWireAnswer)
	start()
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: s.Listener.Addr().(*net.TCPAddr).Port}
	addr, names := doh3SOCKSRelay(t, target)
	// The certificate contains example.com. The SOCKS listener must resolve
	// this name; a system lookup would send QUIC somewhere other than here.
	r.Host = "example.com"
	r.Raw = "https://" + net.JoinHostPort(r.Host, strconv.Itoa(r.Port)) + r.Path
	d := Dialer{Addr: addr, Timeout: 3 * time.Second}
	ips, _, _, kind, err := PingEitherProtocol(d, r.Raw, "a.example.org")
	if err != nil || kind != "DoH3" || len(ips) != 1 {
		t.Fatalf("SOCKS hostname: %v %s %v", ips, kind, err)
	}
	select {
	case name := <-names:
		if name != "example.com" {
			t.Fatal(name)
		}
	default:
		t.Fatal("resolver name was not sent through SOCKS")
	}
	wrong := d
	wrong.Pass = "wrong credentials"
	if _, err := r.Lookup(wrong, "a.example.org"); err == nil {
		t.Fatal("QUIC association reused across different SOCKS credentials")
	}
}

func TestDoH3ConcurrentQueries(t *testing.T) {
	var h3 atomic.Int32
	_, r, start := doh3TestServer(t, func(w http.ResponseWriter, req *http.Request) {
		if req.ProtoMajor == 3 {
			h3.Add(1)
		}
		dnsWireAnswer(w, req)
	})
	start()
	errs := make(chan error, 16)
	for i := 0; i < cap(errs); i++ {
		go func() {
			ips, err := r.Lookup(Dialer{Direct: true, Timeout: 3 * time.Second}, "a.example.org")
			if err == nil && len(ips) != 1 {
				err = fmt.Errorf("unexpected DNS answer: %v", ips)
			}
			errs <- err
		}()
	}
	for i := 0; i < cap(errs); i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if h3.Load() != int32(cap(errs)) {
		t.Fatal("concurrent queries fell back despite working HTTP/3")
	}
}

// A real UDP relay: forwards QUIC packets instead of answering DNS itself.
func doh3SOCKSRelay(t *testing.T, target *net.UDPAddr) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	up, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		ln.Close()
		relay.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); relay.Close(); up.Close() })
	names := make(chan string, 64)
	var mu sync.Mutex
	var client *net.UDPAddr
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var buf [262]byte
				if _, err := io.ReadFull(c, buf[:2]); err != nil {
					return
				}
				if _, err := io.ReadFull(c, buf[:int(buf[1])]); err != nil {
					return
				}
				c.Write([]byte{5, 0})
				if _, err := io.ReadFull(c, buf[:10]); err != nil {
					return
				}
				if buf[1] != 3 {
					c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				port := relay.LocalAddr().(*net.UDPAddr).Port
				c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)})
				io.Copy(io.Discard, c)
			}()
		}
	}()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := relay.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 7 {
				continue
			}
			off := 10
			if buf[3] == 3 {
				l := int(buf[4])
				off = 5 + l + 2
				if n < off {
					continue
				}
				select {
				case names <- string(buf[5 : 5+l]):
				default:
				}
			} else if buf[3] == 4 {
				off = 22
			}
			if n < off {
				continue
			}
			mu.Lock()
			client = from
			mu.Unlock()
			up.WriteToUDP(buf[off:n], target)
		}
	}()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := up.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			to := client
			mu.Unlock()
			if to == nil {
				continue
			}
			header := []byte{0, 0, 0, 1, 127, 0, 0, 1, byte(target.Port >> 8), byte(target.Port)}
			relay.WriteToUDP(append(header, buf[:n]...), to)
		}
	}()
	return ln.Addr().String(), names
}
