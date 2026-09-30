package supervisor

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"
)

// The programs' side of IPv6: the check in checkIPv6 goes from the core
// through the tunnels, and a tunnel carrying IPv6 said nothing of whether
// Windows lets a program's IPv6 reach the TUN adapter at all. A third-party
// network filter (ViPNet's, with callouts on every IPv6 packet) took each one
// before the adapter did, and every program's IPv6 connection hung in
// SynSent while the check found IPv6 working.
//
// The core answers every DNS query that reaches the TUN adapter itself
// (dns-hijack any:53), whatever the rules and the tunnels, and at once: a
// name gets a stand-in address. So a query from the service to an address
// the adapter's routes take, on port 53, answered, reached the adapter.
// IPv4 first, until it is answered: that the adapter is up, and the core
// answering. Then IPv6: silent where IPv4 was answered, it does not get
// there.

// the destinations: documentation ranges, routed into the adapter like
// any other; the core answers for them on port 53
const (
	tunProbe4 = "192.0.2.53:53"
	tunProbe6 = "[2001:db8::53]:53"
)

// dnsAnswered: whether a DNS query sent to addr is answered in time; a var
// for tests, which have no adapter
var dnsAnswered = func(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	var id [2]byte
	rand.Read(id[:])
	q := dnsQuery(binary.BigEndian.Uint16(id[:]), "ipv6-check.dpiswitch.invalid")
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(q); err != nil {
		return false
	}
	b := make([]byte, 512)
	for {
		n, err := conn.Read(b)
		if err != nil {
			return false
		}
		// a reply to this query: the ID, and the response bit
		if n >= 12 && b[0] == id[0] && b[1] == id[1] && b[2]&0x80 != 0 {
			return true
		}
	}
}

// dnsQuery: a query for name's A record
func dnsQuery(id uint16, name string) []byte {
	q := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(q[0:], id)
	q[2] = 0x01 // recursion desired
	q[5] = 1    // one question
	for start := 0; start <= len(name); {
		end := start
		for end < len(name) && name[end] != '.' {
			end++
		}
		q = append(q, byte(end-start))
		q = append(q, name[start:end]...)
		start = end + 1
	}
	return append(q, 0, 0, 1, 0, 1) // root, type A, class IN
}

// tunIPv6 finds whether the programs' IPv6 reaches the TUN adapter: known
// false only when IPv4 is answered and IPv6 is not, so a network down or a
// core not up yet is no verdict.
func tunIPv6(ctx context.Context) (ok, known bool) {
	up := false
	for i := 0; i < 20 && !up; i++ {
		if up = dnsAnswered(tunProbe4, 2*time.Second); !up && !sleepCtx(ctx, 3*time.Second) {
			return false, false
		}
	}
	if !up {
		return false, false
	}
	for i := 0; i < 3; i++ {
		if dnsAnswered(tunProbe6, 2*time.Second) {
			return true, true
		}
		if !sleepCtx(ctx, time.Second) {
			return false, false
		}
	}
	return false, true
}
