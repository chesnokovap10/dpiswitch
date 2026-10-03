package probe

import (
	"net"
	"testing"
	"time"
)

// The DNS cache's queries share one connection to a stream server, and one
// the server closed meanwhile is replaced without the query being lost.
func TestExchangeKeepsStream(t *testing.T) {
	for _, once := range []bool{false, true} {
		srv := tcpDNS(t, once)
		socks := newSocksStub(t, srv)
		_, port, _ := net.SplitHostPort(srv)
		r, err := ParseResolver("tcp://127.0.0.1:" + port)
		if err != nil {
			t.Fatal(err)
		}
		d := Dialer{Addr: socks.ln.Addr().String(), Timeout: 3 * time.Second}
		for i := range 3 {
			q, id := buildQuery("a.example.org", typeA)
			resp, err := r.Exchange(d, q)
			if err != nil {
				t.Fatalf("once=%v, query %d: %v", once, i, err)
			}
			if ips, err := parseAnswer(resp, id, typeA); err != nil || len(ips) != 1 {
				t.Fatalf("once=%v, query %d: %v %v", once, i, ips, err)
			}
		}
		want := int32(1)
		if once {
			want = 3 // each answer the last on its connection
		}
		if n := socks.conns.Load(); n != want {
			t.Errorf("once=%v: %d connections, want %d", once, n, want)
		}
		// the core restarted: every connection through it cut
		socks.drop()
		q, _ := buildQuery("b.example.org", typeA)
		if _, err := r.Exchange(d, q); err != nil {
			t.Errorf("once=%v: the query after the connections were cut: %v", once, err)
		}
	}
}

// Over UDP the association is kept for the next query, and a lost datagram
// is sent again.
func TestExchangeKeepsAssociation(t *testing.T) {
	old := udpResend
	udpResend = 100 * time.Millisecond
	defer func() { udpResend = old }()
	addr, asked := udpSocksStub(t, 1)
	r, err := ParseResolver("udp://192.0.2.53")
	if err != nil {
		t.Fatal(err)
	}
	d := Dialer{Addr: addr, Timeout: 3 * time.Second}
	for i := range 3 {
		q, id := buildQuery("example.com", typeA)
		resp, err := r.Exchange(d, q)
		if err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
		if ips, err := parseAnswer(resp, id, typeA); err != nil || len(ips) != 1 || ips[0] != "192.0.2.7" {
			t.Fatalf("query %d: %v %v", i, ips, err)
		}
	}
	if n := asked.Load(); n != 4 {
		t.Errorf("%d datagrams, want 4: the lost one sent again", n)
	}
	v, _ := datagramPools.Load(r.poolKey(d))
	if p := v.(*pool[*udpConn]); len(p.idle) != 1 {
		t.Errorf("%d associations kept, want 1", len(p.idle))
	}
}
