package dnscache

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dpiswitch/internal/probe"
)

// query: an A query for name, its ID id
func query(name string, id uint16) []byte {
	b := binary.BigEndian.AppendUint16(nil, id)
	b = append(b, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0, 0, 1, 0, 1)
}

// answer: q answered with one A record, ip, at ttl
func answer(q []byte, ip net.IP, ttl uint32) []byte {
	m := append([]byte(nil), q...)
	m[2], m[3] = 0x81, 0x80
	binary.BigEndian.PutUint16(m[6:], 1)
	m = append(m, 0xc0, 0x0c, 0, 1, 0, 1)
	m = binary.BigEndian.AppendUint32(m, ttl)
	m = append(m, 0, 4)
	return append(m, ip.To4()...)
}

// firstTTL and firstIP: the answer's first record's
func firstTTL(t *testing.T, m []byte) uint32 {
	t.Helper()
	var ttl uint32
	found := false
	records(m, func(sec int, _ uint16, off int, _ []byte) {
		if sec == 0 && !found {
			ttl, found = binary.BigEndian.Uint32(m[off:]), true
		}
	})
	if !found {
		t.Fatalf("no answer record in %x", m)
	}
	return ttl
}

func firstIP(m []byte) string {
	ip := ""
	records(m, func(sec int, typ uint16, _ int, rdata []byte) {
		if sec == 0 && typ == 1 && ip == "" {
			ip = net.IP(rdata).String()
		}
	})
	return ip
}

// fakeServer: an upstream of the tests'. answer says what it gives to a
// query; delay, how long it takes.
type fakeServer struct {
	asked  atomic.Int32
	delay  time.Duration
	answer func(q []byte) ([]byte, error)
	block  chan struct{} // closed: answers; nil answers at once
}

// fakeServers: the upstreams the tests' cache asks, by their address
func fakeServers(t *testing.T, servers map[string]*fakeServer) {
	t.Helper()
	old := exchangeVia
	exchangeVia = func(r probe.Resolver, _ probe.Dialer, q []byte) ([]byte, error) {
		f := servers[r.Raw]
		if f == nil {
			return nil, errors.New("no such server")
		}
		f.asked.Add(1)
		if f.block != nil {
			<-f.block
		}
		time.Sleep(f.delay)
		return f.answer(q)
	}
	t.Cleanup(func() { exchangeVia = old })
}

func gives(ip string, ttl uint32) func([]byte) ([]byte, error) {
	return func(q []byte) ([]byte, error) { return answer(q, net.ParseIP(ip), ttl), nil }
}

func newCache(t *testing.T, list ...string) *Server {
	t.Helper()
	s := New(filepath.Join(t.TempDir(), "cache.json"), "")
	s.Configure(list, probe.Dialer{})
	s.SetNetwork("AS1")
	// the fetches behind stale answers end before the test's servers go
	t.Cleanup(func() {
		for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
			s.mu.Lock()
			n := len(s.flights)
			s.mu.Unlock()
			if n == 0 {
				return
			}
		}
	})
	return s
}

func ask(t *testing.T, s *Server, name string, id uint16) []byte {
	t.Helper()
	resp, err := s.Exchange(query(name, id))
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(resp) != id {
		t.Fatalf("answer ID %d, asked %d", binary.BigEndian.Uint16(resp), id)
	}
	return resp
}

// A name asked once is answered from memory after: no server is asked, the
// TTL counts down, and the name's case as asked comes back.
func TestKeptAnswer(t *testing.T) {
	srv := &fakeServer{answer: gives("192.0.2.1", 300)}
	fakeServers(t, map[string]*fakeServer{"udp://192.0.2.53": srv})
	s := newCache(t, "udp://192.0.2.53")

	if ip := firstIP(ask(t, s, "example.com", 1)); ip != "192.0.2.1" {
		t.Fatalf("first answer %s", ip)
	}
	s.mu.Lock()
	for _, e := range s.nets["AS1"] {
		e.At = e.At.Add(-100 * time.Second)
	}
	s.mu.Unlock()
	resp := ask(t, s, "Example.COM", 2)
	if n := srv.asked.Load(); n != 1 {
		t.Fatalf("the server was asked %d times, want once", n)
	}
	if ttl := firstTTL(t, resp); ttl != 200 {
		t.Errorf("TTL %d, want 200: 300 less the 100 s kept", ttl)
	}
	if _, end, _ := answerQuestion(resp); !strings.Contains(string(resp[12:end]), "Example") {
		t.Errorf("the question came back as %q", resp[12:end])
	}
}

// An answer past its TTL is given at once, with a short TTL, and fetched
// again behind it; one a week old is not given at all.
func TestStaleAnswer(t *testing.T) {
	srv := &fakeServer{answer: gives("192.0.2.1", 60)}
	fakeServers(t, map[string]*fakeServer{"udp://192.0.2.53": srv})
	s := newCache(t, "udp://192.0.2.53")
	ask(t, s, "example.com", 1)

	srv.answer = gives("192.0.2.2", 60)
	srv.block = make(chan struct{}) // the fetch behind it waits
	s.mu.Lock()
	for _, e := range s.nets["AS1"] {
		e.At = time.Now().Add(-2 * time.Hour)
	}
	s.mu.Unlock()
	start := time.Now()
	resp := ask(t, s, "example.com", 2)
	if took := time.Since(start); took > 50*time.Millisecond {
		t.Errorf("a stale answer took %v", took)
	}
	if ip, ttl := firstIP(resp), firstTTL(t, resp); ip != "192.0.2.1" || ttl != staleTTL {
		t.Errorf("stale answer %s at TTL %d, want the kept one at %d", ip, ttl, staleTTL)
	}
	close(srv.block)
	deadline := time.Now().Add(2 * time.Second)
	for firstIP(ask(t, s, "example.com", 3)) != "192.0.2.2" {
		if time.Now().After(deadline) {
			t.Fatal("the stale answer was not fetched again")
		}
		time.Sleep(10 * time.Millisecond)
	}

	s.mu.Lock()
	for _, e := range s.nets["AS1"] {
		e.At = time.Now().Add(-keepFor - time.Minute)
	}
	s.mu.Unlock()
	srv.answer = gives("192.0.2.3", 60)
	if ip := firstIP(ask(t, s, "example.com", 4)); ip != "192.0.2.3" {
		t.Errorf("an answer over a week old was given: %s", ip)
	}
}

// The fastest server is asked alone, once each one's time is known; a slow
// or failing one is left for when the fastest does not answer.
func TestFastestAsked(t *testing.T) {
	fast := &fakeServer{delay: time.Millisecond, answer: gives("192.0.2.1", 60)}
	slow := &fakeServer{delay: 60 * time.Millisecond, answer: gives("192.0.2.9", 60)}
	fakeServers(t, map[string]*fakeServer{"udp://192.0.2.53": slow, "tls://192.0.2.54": fast})
	s := newCache(t, "udp://192.0.2.53", "tls://192.0.2.54")

	// the first fetch asks both: neither is measured yet
	if ip := firstIP(ask(t, s, "a.example", 1)); ip != "192.0.2.1" {
		t.Fatalf("the race gave %s, want the fast server's", ip)
	}
	time.Sleep(100 * time.Millisecond) // the slow one's time measured too
	for i, name := range []string{"b.example", "c.example", "d.example"} {
		if ip := firstIP(ask(t, s, name, uint16(i+2))); ip != "192.0.2.1" {
			t.Fatalf("%s: %s", name, ip)
		}
	}
	if n := slow.asked.Load(); n != 1 {
		t.Errorf("the slow server was asked %d times, want only by the first race", n)
	}
	if n := fast.asked.Load(); n != 4 {
		t.Errorf("the fast server was asked %d times, want 4", n)
	}
}

// The fastest server silent, the others are asked within a few of its usual
// times, not after its timeout.
func TestHedge(t *testing.T) {
	first := &fakeServer{delay: time.Millisecond, answer: gives("192.0.2.1", 60)}
	second := &fakeServer{delay: 5 * time.Millisecond, answer: gives("192.0.2.2", 60)}
	fakeServers(t, map[string]*fakeServer{"udp://192.0.2.53": first, "udp://192.0.2.54": second})
	s := newCache(t, "udp://192.0.2.53", "udp://192.0.2.54")
	ask(t, s, "a.example", 1)
	time.Sleep(20 * time.Millisecond)

	first.block = make(chan struct{})
	defer close(first.block)
	start := time.Now()
	if ip := firstIP(ask(t, s, "b.example", 2)); ip != "192.0.2.2" {
		t.Fatalf("got %s, want the second server's", ip)
	}
	if took := time.Since(start); took > 300*time.Millisecond {
		t.Errorf("the second server answered after %v", took)
	}
}

// Many asking for one name at once make one query of it.
func TestOneFetchPerName(t *testing.T) {
	srv := &fakeServer{delay: 30 * time.Millisecond, answer: gives("192.0.2.1", 60)}
	fakeServers(t, map[string]*fakeServer{"udp://192.0.2.53": srv})
	s := newCache(t, "udp://192.0.2.53")
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ip := firstIP(ask(t, s, "example.com", uint16(i))); ip != "192.0.2.1" {
				t.Errorf("got %s", ip)
			}
		}()
	}
	wg.Wait()
	if n := srv.asked.Load(); n != 1 {
		t.Errorf("the server was asked %d times", n)
	}
}

// No server answering: SERVFAIL, and nothing kept; a kept answer outlives a
// failing server.
func TestFailure(t *testing.T) {
	srv := &fakeServer{answer: func([]byte) ([]byte, error) { return nil, errors.New("down") }}
	fakeServers(t, map[string]*fakeServer{"udp://192.0.2.53": srv})
	s := newCache(t, "udp://192.0.2.53")
	if rc := ask(t, s, "example.com", 1)[3] & 0x0f; rc != rcodeServFail {
		t.Fatalf("rcode %d, want SERVFAIL", rc)
	}
	srv.answer = func(q []byte) ([]byte, error) {
		m := answer(q, net.ParseIP("192.0.2.1"), 60)
		m[3] = 0x82 // SERVFAIL
		return m, nil
	}
	if rc := ask(t, s, "example.com", 2)[3] & 0x0f; rc != rcodeServFail {
		t.Fatalf("rcode %d, want SERVFAIL", rc)
	}
	if n := len(s.nets["AS1"]); n != 0 {
		t.Fatalf("%d answers kept after failures", n)
	}

	srv.answer = gives("192.0.2.1", 60)
	ask(t, s, "example.com", 3)
	srv.answer = func([]byte) ([]byte, error) { return nil, errors.New("down") }
	s.mu.Lock()
	for _, e := range s.nets["AS1"] {
		e.At = time.Now().Add(-time.Hour)
	}
	s.mu.Unlock()
	for i := range 3 {
		if ip := firstIP(ask(t, s, "example.com", uint16(10+i))); ip != "192.0.2.1" {
			t.Fatalf("the kept answer gone with the server down: %q", ip)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Answers are kept per network, and the file keeps them across a restart --
// unless the servers changed.
func TestNetworksAndFile(t *testing.T) {
	srv := &fakeServer{answer: gives("192.0.2.1", 60)}
	fakeServers(t, map[string]*fakeServer{"udp://192.0.2.53": srv, "udp://192.0.2.54": srv})
	file := filepath.Join(t.TempDir(), "cache.json")
	s := New(file, "")
	s.Configure([]string{"udp://192.0.2.53"}, probe.Dialer{})
	s.SetNetwork("AS1")
	ask(t, s, "example.com", 1)
	s.SetNetwork("AS2")
	ask(t, s, "example.com", 2)
	if n := srv.asked.Load(); n != 2 {
		t.Fatalf("asked %d times, want once per network", n)
	}
	s.save(true)

	s = New(file, "")
	s.Configure([]string{"udp://192.0.2.53"}, probe.Dialer{})
	s.SetNetwork("AS1")
	ask(t, s, "example.com", 3)
	if n := srv.asked.Load(); n != 2 {
		t.Fatalf("the file's answer not given: asked %d times", n)
	}

	s.Configure([]string{"udp://192.0.2.54"}, probe.Dialer{})
	ask(t, s, "example.com", 4)
	if n := srv.asked.Load(); n != 3 {
		t.Fatalf("an answer of another server given: asked %d times", n)
	}
}

// What the cache keeps, and for how long.
func TestKeepable(t *testing.T) {
	q := query("example.com", 1)
	if ttl, ok := keepable(answer(q, net.ParseIP("192.0.2.1"), 42)); !ok || ttl != 42 {
		t.Errorf("an answer: %d %v", ttl, ok)
	}
	nx := append([]byte(nil), q...)
	nx[2], nx[3] = 0x81, 0x83
	binary.BigEndian.PutUint16(nx[8:], 1)
	rdata := []byte{0, 0}                            // MNAME and RNAME: the root
	rdata = binary.BigEndian.AppendUint32(rdata, 1)  // SERIAL
	rdata = append(rdata, make([]byte, 12)...)       // REFRESH, RETRY, EXPIRE
	rdata = binary.BigEndian.AppendUint32(rdata, 30) // MINIMUM
	nx = append(nx, 0xc0, 0x0c, 0, typeSOA, 0, 1, 0, 0, 0x0e, 0x10, 0, byte(len(rdata)))
	nx = append(nx, rdata...)
	if ttl, ok := keepable(nx); !ok || ttl != 30 {
		t.Errorf("NXDOMAIN with a SOA: %d %v, want 30 from its MINIMUM", ttl, ok)
	}
	fail := answer(q, net.ParseIP("192.0.2.1"), 60)
	fail[3] = 0x82
	if _, ok := keepable(fail); ok {
		t.Error("a SERVFAIL kept")
	}
	tc := answer(q, net.ParseIP("192.0.2.1"), 60)
	tc[2] |= 0x02
	if _, ok := keepable(tc); ok {
		t.Error("a truncated answer kept")
	}
}

// The listeners answer over UDP and TCP, and say where in Serving.
func TestServe(t *testing.T) {
	old := listenAddr
	listenAddr = "127.0.0.1:0"
	defer func() { listenAddr = old }()
	srv := &fakeServer{answer: gives("192.0.2.1", 60)}
	fakeServers(t, map[string]*fakeServer{"udp://192.0.2.53": srv})
	s := newCache(t, "udp://192.0.2.53")
	if err := s.Serve(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	addr := Serving()
	if addr == "" {
		t.Fatal("not serving")
	}

	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write(query("example.com", 7))
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil || firstIP(buf[:n]) != "192.0.2.1" || binary.BigEndian.Uint16(buf) != 7 {
		t.Fatalf("UDP: %x %v", buf[:n], err)
	}

	tc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(2 * time.Second))
	for id := uint16(8); id < 10; id++ {
		q := query("example.com", id)
		tc.Write(append([]byte{0, byte(len(q))}, q...))
		var l [2]byte
		if _, err := io.ReadFull(tc, l[:]); err != nil {
			t.Fatal(err)
		}
		m := make([]byte, int(l[0])<<8|int(l[1]))
		if _, err := io.ReadFull(tc, m); err != nil || firstIP(m) != "192.0.2.1" || binary.BigEndian.Uint16(m) != id {
			t.Fatalf("TCP: %x %v", m, err)
		}
	}

	resp, err := probe.LocalResolver().Exchange(probe.Dialer{}, query("example.com", 11))
	if err != nil || firstIP(resp) != "192.0.2.1" {
		t.Fatalf("in-process: %x %v", resp, err)
	}
	s.Close()
	if Serving() != "" {
		t.Error("still serving after Close")
	}
	if _, err := probe.LocalResolver().Exchange(probe.Dialer{}, query("example.com", 12)); err == nil {
		t.Error("the in-process cache answered after Close")
	}
}

// A server that blocks a name answers it with a loopback address --
// Rostelecom's answer for Meta's names. That is no answer while another
// server has one: the other's is given and kept, the fastest server asked
// first all the same.
func TestSinkholePassedOver(t *testing.T) {
	isp := &fakeServer{delay: time.Millisecond, answer: gives("127.0.0.1", 60)}
	own := &fakeServer{delay: 20 * time.Millisecond, answer: gives("192.0.2.7", 60)}
	fakeServers(t, map[string]*fakeServer{"udp://192.0.2.53": isp, "tls://192.0.2.54": own})
	s := newCache(t, "udp://192.0.2.53", "tls://192.0.2.54")

	// the first fetch races both: the ISP's answer comes first
	if ip := firstIP(ask(t, s, "www.instagram.com", 1)); ip != "192.0.2.7" {
		t.Fatalf("got %s, want the other server's", ip)
	}
	time.Sleep(50 * time.Millisecond)
	// measured faster, the ISP's is asked alone first -- and passed over
	if ip := firstIP(ask(t, s, "gateway.instagram.com", 2)); ip != "192.0.2.7" {
		t.Fatalf("got %s, want the other server's", ip)
	}
	if n := own.asked.Load(); n != 2 {
		t.Errorf("the other server was asked %d times, want 2", n)
	}
	// and the real answer kept: asked again, no server is
	asked := isp.asked.Load() + own.asked.Load()
	if ip := firstIP(ask(t, s, "www.instagram.com", 3)); ip != "192.0.2.7" {
		t.Fatalf("kept %s", ip)
	}
	if n := isp.asked.Load() + own.asked.Load(); n != asked {
		t.Errorf("a kept answer asked of a server again")
	}
	// a name the ISP answers right is still taken from it alone
	isp.answer = gives("192.0.2.1", 60)
	if ip := firstIP(ask(t, s, "static.cdninstagram.com", 4)); ip != "192.0.2.1" {
		t.Fatalf("got %s", ip)
	}
}

// Every server answers loopback: the name lives there. It is given, and not
// kept -- it is asked again, and a server that has it right by then wins.
func TestSinkholeEveryServer(t *testing.T) {
	a := &fakeServer{delay: time.Millisecond, answer: gives("127.0.0.1", 60)}
	b := &fakeServer{delay: 2 * time.Millisecond, answer: gives("127.0.0.1", 60)}
	fakeServers(t, map[string]*fakeServer{"udp://192.0.2.53": a, "udp://192.0.2.54": b})
	s := newCache(t, "udp://192.0.2.53", "udp://192.0.2.54")
	if ip := firstIP(ask(t, s, "localhost.example", 1)); ip != "127.0.0.1" {
		t.Fatalf("got %q", ip)
	}
	if n := len(s.nets["AS1"]); n != 0 {
		t.Fatalf("%d answers kept", n)
	}
	b.answer = gives("192.0.2.9", 60)
	if ip := firstIP(ask(t, s, "localhost.example", 2)); ip != "192.0.2.9" {
		t.Fatalf("got %q after a server had it right", ip)
	}
}

// A sinkhole kept before they were told apart does not come back from the
// file.
func TestSinkholeNotLoaded(t *testing.T) {
	file := filepath.Join(t.TempDir(), "cache.json")
	s := New(file, "")
	s.Configure([]string{"udp://192.0.2.53"}, probe.Dialer{})
	s.SetNetwork("AS1")
	s.mu.Lock()
	s.keepLocked("AS1", "a", answer(query("www.instagram.com", 1), net.ParseIP("127.0.0.1"), 60), 60)
	s.keepLocked("AS1", "b", answer(query("example.com", 2), net.ParseIP("192.0.2.1"), 60), 60)
	s.mu.Unlock()
	s.save(true)
	got := New(file, "")
	if n := len(got.nets["AS1"]); n != 1 {
		t.Fatalf("%d answers loaded, want the real one alone", n)
	}
}

func TestSinkhole(t *testing.T) {
	q := query("a.example", 1)
	aaaa := func(ip string) []byte {
		m := append([]byte(nil), q...)
		m[2], m[3] = 0x81, 0x80
		binary.BigEndian.PutUint16(m[6:], 1)
		m = append(m, 0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16)
		return append(m, net.ParseIP(ip).To16()...)
	}
	nx := answer(q, net.ParseIP("192.0.2.1"), 60)[:len(q)]
	nx[2], nx[3] = 0x81, 0x83
	for name, c := range map[string]struct {
		m    []byte
		want bool
	}{
		"127.0.0.1":   {answer(q, net.ParseIP("127.0.0.1"), 60), true},
		"127.1.2.3":   {answer(q, net.ParseIP("127.1.2.3"), 60), true},
		"0.0.0.0":     {answer(q, net.ParseIP("0.0.0.0"), 60), true},
		"::1":         {aaaa("::1"), true},
		"::":          {aaaa("::"), true},
		"a real one":  {answer(q, net.ParseIP("192.0.2.1"), 60), false},
		"a real IPv6": {aaaa("2001:db8::1"), false},
		"no address":  {nx, false},
	} {
		if got := sinkhole(c.m); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}
