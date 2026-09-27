package probe

import (
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseResolverIPv6(t *testing.T) {
	cases := map[string][2]string{ // input -> {host, scheme}
		"fd7a:a1c3:8b42::":                 {"fd7a:a1c3:8b42::", "udp"},
		"[fd7a:a1c3:8b42::]:53":            {"fd7a:a1c3:8b42::", "udp"},
		"tls://2606:4700:4700::1111":       {"2606:4700:4700::1111", "tls"},
		"https://2606:4700:4700::1111/dns": {"2606:4700:4700::1111", "https"},
		"10.8.1.0":                         {"10.8.1.0", "udp"},
		"https://77.88.8.8/dns-query":      {"77.88.8.8", "https"},
	}
	for in, want := range cases {
		r, err := ParseResolver(in)
		if err != nil || r.Host != want[0] || r.Scheme != want[1] {
			t.Errorf("%q: host=%q scheme=%q err=%v, want %v", in, r.Host, r.Scheme, err, want)
		}
	}
	if r, _ := ParseResolver("https://2606:4700:4700::1111/dns"); r.Path != "/dns" {
		t.Errorf("path lost: %q", r.Path)
	}
}

// A response carries both an A and an AAAA record for the same name; each
// query type must pick out its own and ignore the other. Before this the
// parser only knew type A, so an IPv6-only host looked like "no records".
func TestParseAnswerByType(t *testing.T) {
	name := "ipv6.example.com"
	for _, tc := range []struct {
		qtype uint16
		want  string
	}{
		{typeA, "192.0.2.7"},
		{typeAAAA, "2001:db8::7"},
	} {
		q, id := buildQuery(name, tc.qtype)
		resp := answerWith(q, id)
		got, err := parseAnswer(resp, id, tc.qtype)
		if err != nil {
			t.Fatalf("type %d: %v", tc.qtype, err)
		}
		if len(got) != 1 || got[0] != tc.want {
			t.Fatalf("type %d: got %v, want [%s]", tc.qtype, got, tc.want)
		}
	}
}

// answerWith echoes the question and appends one A and one AAAA record.
func answerWith(q []byte, id uint16) []byte {
	m := make([]byte, len(q))
	copy(m, q)
	m[2] = 0x81 // response, recursion desired
	m[3] = 0x80 // recursion available, rcode 0
	m[7] = 2    // two answers
	rr := func(typ uint16, data []byte) {
		m = append(m, 0xc0, 0x0c) // pointer to the name in the question
		m = append(m, byte(typ>>8), byte(typ), 0, 1, 0, 0, 0, 60,
			byte(len(data)>>8), byte(len(data)))
		m = append(m, data...)
	}
	rr(typeA, []byte{192, 0, 2, 7})
	v6 := make([]byte, 16)
	v6[0], v6[1], v6[15] = 0x20, 0x01, 0x07
	v6[2], v6[3] = 0x0d, 0xb8
	rr(typeAAAA, v6)
	return m
}

// socksStub: a SOCKS5 listener that forwards every CONNECT to target and
// counts the connections -- the core's listener, as far as a resolver sees.
type socksStub struct {
	ln     net.Listener
	conns  atomic.Int32
	mu     sync.Mutex
	opened []net.Conn
}

func newSocksStub(t *testing.T, target string) *socksStub {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &socksStub{ln: ln}
	t.Cleanup(func() { ln.Close(); s.drop() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			go s.serve(c, target)
		}
	}()
	return s
}

func (s *socksStub) serve(c net.Conn, target string) {
	buf := make([]byte, 262)
	// greeting, then CONNECT with an address of any kind
	if _, err := io.ReadFull(c, buf[:3]); err != nil {
		c.Close()
		return
	}
	c.Write([]byte{5, 0})
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		c.Close()
		return
	}
	skip := map[byte]int{1: 4, 4: 16}[buf[3]]
	if buf[3] == 3 {
		io.ReadFull(c, buf[:1])
		skip = int(buf[0])
	}
	io.ReadFull(c, buf[:skip+2])
	up, err := net.Dial("tcp", target)
	if err != nil {
		c.Close()
		return
	}
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	s.mu.Lock()
	s.opened = append(s.opened, c, up)
	s.mu.Unlock()
	go io.Copy(up, c)
	io.Copy(c, up)
	c.Close()
	up.Close()
}

// drop cuts every connection made so far, as a core restart does.
func (s *socksStub) drop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.opened {
		c.Close()
	}
	s.opened = nil
}

// The queries of a cycle share one connection to the resolver, and a kept
// connection that died is replaced without losing the query after it.
func TestDoHKeepsConnection(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(answerWith(q, binary.BigEndian.Uint16(q)))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	resolverRoots = roots
	defer func() { resolverRoots = nil }()

	socks := newSocksStub(t, srv.Listener.Addr().String())
	r, err := ParseResolver("https://127.0.0.1:" + strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port) + "/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	d := Dialer{Addr: socks.ln.Addr().String(), Timeout: 5 * time.Second}
	for i := 0; i < 5; i++ {
		ips, err := r.Lookup(d, "a.example.org")
		if err != nil || len(ips) != 1 || ips[0] != "192.0.2.7" {
			t.Fatalf("query %d: %v %v", i, ips, err)
		}
	}
	if n := socks.conns.Load(); n != 1 {
		t.Fatalf("five queries opened %d connections, want 1", n)
	}

	socks.drop()
	if ips, err := r.Lookup(d, "a.example.org"); err != nil || len(ips) != 1 {
		t.Fatalf("after the connection died: %v %v", ips, err)
	}
	if n := socks.conns.Load(); n != 2 {
		t.Fatalf("%d connections after the drop, want 2", n)
	}
}

// udpSocksStub: a SOCKS5 listener that takes UDP ASSOCIATE only and answers
// every DNS query that reaches its relay -- after dropping the first few,
// as a lossy network does.
func udpSocksStub(t *testing.T, drop int) (addr string, asked *atomic.Int32) {
	return udpSocksStubForged(t, drop, false)
}

// udpSocksStubForged: the same, and with forge each real answer comes after
// two forged ones carrying its ID -- one from another address, one to
// another question -- both saying 6.6.6.6.
func udpSocksStubForged(t *testing.T, drop int, forge bool) (addr string, asked *atomic.Int32) {
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); relay.Close() })
	asked = new(atomic.Int32)
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, from, err := relay.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 10 || buf[3] != 1 || int(asked.Add(1)) <= drop {
				continue
			}
			q := buf[10:n]
			if forge {
				bad := answerWith(q, binary.BigEndian.Uint16(q))
				copy(bad[len(bad)-4:], []byte{6, 6, 6, 6})
				other := append([]byte(nil), buf[:10]...)
				other[4] = 198 // from 198.x.x.x, not the resolver
				relay.WriteToUDP(append(other, bad...), from)
				wrongQ := append([]byte(nil), bad...)
				wrongQ[13] ^= 0x20 // another name in the question
				wrongQ[14]++
				relay.WriteToUDP(append(append([]byte(nil), buf[:10]...), wrongQ...), from)
			}
			out := append(append([]byte(nil), buf[:10]...), answerWith(q, binary.BigEndian.Uint16(q))...)
			relay.WriteToUDP(out, from)
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				b := make([]byte, 10)
				if _, err := io.ReadFull(c, b[:3]); err != nil {
					return
				}
				c.Write([]byte{5, 0})
				if _, err := io.ReadFull(c, b); err != nil || b[1] != 3 {
					return // not an ASSOCIATE: no TCP here
				}
				p := relay.LocalAddr().(*net.UDPAddr).Port
				c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, byte(p >> 8), byte(p)})
				io.Copy(io.Discard, c) // the association lives while this does
			}(c)
		}
	}()
	return ln.Addr().String(), asked
}

// udp:// is asked over UDP, as the core asks it -- it used to go over TCP,
// and a network dropping UDP/53 had the resolver pass -- and a lost
// datagram is sent again.
func TestLookupOverUDP(t *testing.T) {
	old := udpResend
	udpResend = 100 * time.Millisecond
	defer func() { udpResend = old }()
	addr, asked := udpSocksStub(t, 1)
	r, err := ParseResolver("udp://192.0.2.53")
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Lookup(Dialer{Addr: addr, Timeout: 3 * time.Second}, "example.com")
	if err != nil || len(got) != 1 || got[0] != "192.0.2.7" {
		t.Fatalf("got %v, %v", got, err)
	}
	if n := asked.Load(); n != 2 {
		t.Fatalf("%d datagrams, want the lost one sent again", n)
	}
}

// An answer counts only from the resolver asked, to the question asked: a
// datagram that guessed the 16-bit ID was taken for the answer.
func TestUDPAnswerForged(t *testing.T) {
	addr, _ := udpSocksStubForged(t, 0, true)
	r, err := ParseResolver("udp://192.0.2.53")
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Lookup(Dialer{Addr: addr, Timeout: 3 * time.Second}, "example.com")
	if err != nil || len(got) != 1 || got[0] != "192.0.2.7" {
		t.Fatalf("got %v, %v -- a forged answer was taken", got, err)
	}
}

// tcpDNS: a DNS server over TCP whose first answer on each connection comes
// late, as the handshake's does; with once it closes after that answer.
func tcpDNS(t *testing.T, once bool) string {
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
			go func(c net.Conn) {
				defer c.Close()
				for i := 0; ; i++ {
					var l [2]byte
					if _, err := io.ReadFull(c, l[:]); err != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(l[:]))
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					if i == 0 {
						time.Sleep(100 * time.Millisecond)
					}
					a := answerWith(q, binary.BigEndian.Uint16(q))
					c.Write(append([]byte{byte(len(a) >> 8), byte(len(a))}, a...))
					if once {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

// The DNS test shows a query's time on a connection already up: the first
// query's setup used to be counted, and a server looked three times slower
// than it answers. One connection carries both queries; a server that
// closes it after one answer is timed with the setup, and still answers.
func TestPingWarm(t *testing.T) {
	for _, once := range []bool{false, true} {
		srv := tcpDNS(t, once)
		socks := newSocksStub(t, srv)
		_, port, _ := net.SplitHostPort(srv)
		r, err := ParseResolver("tcp://127.0.0.1:" + port)
		if err != nil {
			t.Fatal(err)
		}
		ips, rtt, err := r.Ping(Dialer{Addr: socks.ln.Addr().String(), Timeout: 3 * time.Second}, "a.example.org")
		if err != nil || len(ips) != 1 || ips[0] != "192.0.2.7" {
			t.Fatalf("once=%v: %v %v", once, ips, err)
		}
		if n := socks.conns.Load(); n != 1 {
			t.Errorf("once=%v: %d connections, want 1", once, n)
		}
		if slow := rtt >= 100*time.Millisecond; slow != once {
			t.Errorf("once=%v: %v timed, the setup counted = %v", once, rtt, slow)
		}
	}
}
