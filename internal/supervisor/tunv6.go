package supervisor

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"time"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
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
// adapter's answers, and a tunnel found without IPv6 within tunnelV6Hold.
// The adapter keeps its IPv6 address with IPv6 found blocked, so the check
// still probes it and is no one-way door; and a blocked answer reset at
// every start made every start rebuild the config under the running core:
// awg2 down for a minute, and YouTube direct meanwhile, wherever a filter
// (ViPNet) takes IPv6 for good. A tunnel's answer is kept the same way, for
// a while: see tunnelV6Hold.
func startIPv6State(last ctl.TunnelIPv6, held v6Held, now time.Time) ctl.TunnelIPv6 {
	keep := ctl.TunnelIPv6{}
	for k, v := range last {
		switch {
		case k == ctl.TunKey || k == ctl.Tun4Key:
			keep[k] = v
		case !v && held.holds(k, now):
			keep[k] = false
		}
	}
	return keep
}

// tunnelV6Hold: how long a tunnel found without IPv6 keeps that answer
// across core starts. The answer puts ip-version: ipv4 on its outbound, and
// an outbound on ipv4 refuses an IPv6 target: no check through it can see
// IPv6 come back, so the answer must be dropped for one to be made. Dropped
// at every start, as it used to be, the tunnel was found without IPv6 again
// at every start, and the config changed under the running core each time --
// re-read in place, the core kept the old WireGuard outbound beside the new
// one, two sessions with one key, and the tunnel kept dropping for minutes.
// The config is now applied by a core restart, and held for a day the answer
// costs one at most a day: a start past the hold builds the config with IPv6
// again, and the check finding it still dead restarts the core once.
var tunnelV6Hold = 24 * time.Hour

// v6Held: when each tunnel was last found without IPv6, by its proxy name.
// The service writes it beside the answers (paths.TunnelIPv6Held).
type v6Held map[string]time.Time

func loadV6Held(path string) v6Held {
	h := v6Held{}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &h)
	}
	if h == nil {
		h = v6Held{}
	}
	return h
}

func (h v6Held) save(path string) error {
	b, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	return paths.ReplaceFile(path, append(b, '\n'))
}

// holds: whether name's answer is within the hold. A time ahead of the clock
// -- the clock set back -- holds nothing.
func (h v6Held) holds(name string, now time.Time) bool {
	at, ok := h[name]
	return ok && !at.After(now) && now.Sub(at) < tunnelV6Hold
}

// keepTunnelIPv6 carries the tunnels' answers the start kept (see
// startIPv6State) into found: their outbounds run on IPv4 alone, and a check
// through one would find it without IPv6 whatever it carries
func keepTunnelIPv6(old, found ctl.TunnelIPv6) {
	for k, v := range old {
		if k != ctl.TunKey && k != ctl.Tun4Key && !v {
			found[k] = false
		}
	}
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
// then; nor is a tunnel whose answer the start kept, on IPv4 alone for the
// same reason (see tunnelV6Hold).
func tunnelsToCheck(found ctl.TunnelIPv6, names []string) []string {
	if found.SystemBlocked() {
		return nil
	}
	var out []string
	for _, n := range names {
		if _, kept := found[n]; !kept {
			out = append(out, n)
		}
	}
	return out
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
