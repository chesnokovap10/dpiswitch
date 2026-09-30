package supervisor

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"

	"dpiswitch/internal/ctl"
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

// startIPv6State: what a core starts with of the last checks -- the
// adapter's answers, not the tunnels'. The adapter keeps its IPv6 address
// with IPv6 found blocked, so the check still probes it and is no one-way
// door; and a blocked answer reset at every start made every start rebuild
// the config and re-read it, which rebuilt every outbound: awg2 down for a
// minute, and YouTube direct meanwhile, wherever a filter (ViPNet) takes
// IPv6 for good.
func startIPv6State(last ctl.TunnelIPv6) ctl.TunnelIPv6 {
	keep := ctl.TunnelIPv6{}
	for _, k := range []string{ctl.TunKey, ctl.Tun4Key} {
		if v, ok := last[k]; ok {
			keep[k] = v
		}
	}
	return keep
}

// keepAdapterIPv6 carries the last answer about the adapter's IPv6 into
// found, when this check could not ask it
func keepAdapterIPv6(old, found ctl.TunnelIPv6) {
	if v, seen := old[ctl.TunKey]; seen {
		if _, asked := found[ctl.TunKey]; !asked {
			found[ctl.TunKey] = v
		}
	}
}

// tunnelsToCheck: the tunnels whose IPv6 the check asks after. IPv6 not
// reaching the adapter, the tunnels run on IPv4 alone (see awgconf): an
// outbound on ip-version ipv4 refuses an IPv6 target, so a check through it
// fails whatever the tunnel carries, and wrote awg2 down. None is asked
// then -- their answers are reset at every start, so there is none to keep.
func tunnelsToCheck(found ctl.TunnelIPv6, names []string) []string {
	if found.SystemBlocked() {
		return nil
	}
	return names
}

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

// tunProbeWait: the pause between IPv4 queries; the tests shorten it
var tunProbeWait = 3 * time.Second

// tunIPv4 finds whether the programs' IPv4 reaches the TUN adapter: known
// false only when the core answers its API all along and no query through
// the adapter is answered -- a core not up is no verdict.
func tunIPv4(ctx context.Context, coreUp func() bool) (ok, known bool) {
	for i := 0; i < 20; i++ {
		if dnsAnswered(tunProbe4, 2*time.Second) {
			return true, true
		}
		if !sleepCtx(ctx, tunProbeWait) {
			return false, false
		}
	}
	return false, coreUp()
}

// tunIPv6 finds whether the programs' IPv6 reaches the TUN adapter, IPv4
// having been answered: known false when IPv6 is not.
func tunIPv6(ctx context.Context) (ok, known bool) {
	for i := 0; i < 3; i++ {
		if dnsAnswered(tunProbe6, 2*time.Second) {
			return true, true
		}
		if !sleepCtx(ctx, tunProbeWait/3) {
			return false, false
		}
	}
	return false, true
}
