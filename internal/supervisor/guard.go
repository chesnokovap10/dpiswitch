package supervisor

import (
	"context"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"

	"dpiswitch/internal/core"
	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/udpguard"
)

// The UDP guard (see udpguard) is the setting's, and the core's run is what it
// lives by: filters that block UDP out of the physical adapters are right
// only while the TUN adapter takes the programs' traffic in their place. With
// the core down, or its adapter gone, the same filters would cut every
// program's UDP off with nothing to carry it. So the guard is in place from
// the moment the adapter is up and takes the traffic, and is taken out at
// once when the core is stopped for a restart, ends on its own, the adapter
// goes, or the setting is switched off.
//
// One holdGuard runs for each core, from its start to its stop.

const (
	// guardPeriod: how often the setting and the adapter are looked at, and
	// the guard in place is looked at itself
	guardPeriodDefault = 2 * time.Second
	// guardRetryDefault: the pause before the next try after a refusal --
	// the engine's service may be stopped for good, and the log not to fill
	guardRetryDefault = 10 * time.Second
)

var (
	guardPeriod = guardPeriodDefault
	guardRetry  = guardRetryDefault
)

// udpGuard: what holdGuard asks of the filters: udpguard.Guard, or the tests'
type udpGuard interface {
	Ensure(core string) (udpguard.Change, error)
	Lift() bool
	Rules() int
	Dropped(local, remote netip.AddrPort, since time.Time) bool
}

// tunState: what the adapter looks like
type tunState struct {
	known bool // the adapters and the routes could be read
	// up: the adapter is up and a default route goes through it
	up bool
	// blocked: Windows keeps the programs' traffic from it, as the check at
	// the core's start found (see ctl.TunnelIPv6.TrafficBlocked)
	blocked bool
}

// guardEnv: what holdGuard looks at and writes besides the filters
type guardEnv struct {
	on   func() bool           // the setting
	tun  func() tunState       // the adapter
	core func() string         // the core's path
	say  func(udpguard.Status) // the state, for the UI: given when it changes
	// probe: whether a test packet out of every uplink adapter was seen
	// dropped by the guard just put in; false is no word against it
	probe func(ctx context.Context, g udpGuard) bool
}

func realGuardEnv() guardEnv {
	return guardEnv{
		on:    func() bool { return ctl.LoadSettings(paths.Settings()).UDPGuard },
		tun:   readTun,
		core:  core.Path,
		say:   saveGuardStatus,
		probe: readGuardHolds,
	}
}

// saveGuardStatus writes the file the UI shows the guard's state from
func saveGuardStatus(st udpguard.Status) {
	if err := st.Save(paths.UDPGuard()); err != nil {
		log.Printf("UDP guard: status not saved: %v", err)
	}
}

// readTun reads the adapter's state; one that cannot be read is not known,
// and the guard is left as it is
func readTun() tunState {
	ads, err := adapters()
	if err != nil {
		return tunState{}
	}
	routes, err := defaultRoutes4()
	if err != nil {
		return tunState{}
	}
	return tunState{
		known:   true,
		up:      tunUp(ads, routes),
		blocked: ctl.LoadTunnelIPv6(paths.TunnelIPv6()).TrafficBlocked(),
	}
}

// tunUp: whether the core's adapter is up with a default route through it --
// a core that runs with no adapter (it could not make it, or it was removed
// under it) carries nothing, and the programs' traffic goes by the physical
// one
func tunUp(ads []adapter, routes map[uint32]bool) bool {
	for _, a := range ads {
		if a.up && a.ours() && routes[a.index] {
			return true
		}
	}
	return false
}

// leakDst: where the test packet goes -- the documentation range, which no
// network routes and nothing answers; 9 is discard
var leakDst = netip.MustParseAddrPort("192.0.2.1:9")

// sendFrom sends one byte out of the adapter that has the address given, as a
// program that binds its socket to it does, and says the address and port the
// packet had -- by which the engine's record of dropped packets has it
var sendFrom = func(src net.IP) (netip.AddrPort, error) {
	c, err := net.DialUDP("udp4", &net.UDPAddr{IP: src}, net.UDPAddrFromAddrPort(leakDst))
	if err != nil {
		return netip.AddrPort{}, err
	}
	defer c.Close()
	local := c.LocalAddr().(*net.UDPAddr).AddrPort()
	_, err = c.Write([]byte{0})
	return local, err
}

// holdsWait: how long the engine's record is waited on for a packet's drop
const holdsWait = 2 * time.Second

// readGuardHolds asks guardHolds of the adapters there are
func readGuardHolds(ctx context.Context, g udpGuard) bool {
	ads, err := adapters()
	if err != nil {
		return false
	}
	routes, err := defaultRoutes4()
	if err != nil {
		return false
	}
	return guardHolds(ctx, ads, routes, g, sendFrom, holdsWait)
}

// guardHolds tries the guard the way what it is against does: a datagram out
// of each adapter that leads out, from the address it has. A block gives the
// sender no error -- the send goes through as if the packet were on its way --
// so the proof is the engine's record: the packet seen dropped. True when every
// adapter tried had its packet seen dropped, and at least one was tried. A
// packet not seen dropped is no proof of a leak -- the engine may not have
// recorded it -- and says nothing either way; an adapter whose send failed
// is not counted. It ends with the context, which is the core's: a stop of the
// core does not wait for the record.
func guardHolds(ctx context.Context, ads []adapter, routes map[uint32]bool, g udpGuard, send func(src net.IP) (netip.AddrPort, error), wait time.Duration) bool {
	tried, seen := 0, 0
	for _, a := range ads {
		if !a.up || a.ours() || !routes[a.index] || !a.usable() {
			continue
		}
		for _, ip := range a.v4 {
			if ip = ip.To4(); ip == nil || ip.IsLoopback() || ip[0] == 169 && ip[1] == 254 || tunRange.Contains(ip) {
				continue
			}
			since := time.Now().Add(-time.Second)
			local, err := send(ip)
			if err != nil {
				continue
			}
			tried++
			for deadline := time.Now().Add(wait); ; {
				if g.Dropped(local, leakDst, since) {
					seen++
					break
				}
				if time.Now().After(deadline) || !sleepCtx(ctx, 50*time.Millisecond) {
					break
				}
			}
		}
	}
	return ctx.Err() == nil && tried > 0 && seen == tried
}

// holdGuard keeps the guard as the setting and the adapter ask, until the
// context -- the core's run, or the part of it before it is stopped -- ends,
// and takes it out then.
func holdGuard(ctx context.Context, g udpGuard, env guardEnv) {
	var (
		cur    udpguard.Status
		retry  time.Time // no new try before this, after a refusal
		logged string    // the refusal last logged: one text is said once
		// whether the test packet was seen dropped when the guard last went in
		checked bool
	)
	say := func(st udpguard.Status) {
		if !st.Same(cur) {
			cur = st
			env.say(st)
		}
	}
	lift := func(why string) {
		if g.Lift() {
			log.Printf("UDP guard lifted: %s", why)
		}
	}
	defer func() {
		lift("the core stopped")
		if env.on() {
			say(udpguard.Status{State: udpguard.StateWait, Why: udpguard.WhyCore})
		} else {
			say(udpguard.Status{State: udpguard.StateOff})
		}
	}()
	step := func() {
		if !env.on() {
			lift("switched off in the settings")
			say(udpguard.Status{State: udpguard.StateOff})
			return
		}
		tun := env.tun()
		switch {
		case !tun.known:
			return // nothing read: nothing changes
		case !tun.up:
			lift("the DPI Switch adapter is gone")
			say(udpguard.Status{State: udpguard.StateWait, Why: udpguard.WhyAdapter})
			return
		case tun.blocked:
			lift("Windows keeps the programs' traffic from the DPI Switch adapter")
			say(udpguard.Status{State: udpguard.StateWait, Why: udpguard.WhyTraffic})
			return
		case time.Now().Before(retry):
			return // refused lately: the state shown stays until the next try
		}
		ch, err := g.Ensure(env.core())
		if err != nil {
			retry = time.Now().Add(guardRetry)
			if text := err.Error(); text != logged {
				logged = text
				log.Printf("UDP guard not put in place: %v -- trying again every %s", err, guardRetry)
			}
			say(udpguard.Status{State: udpguard.StateFail, Why: udpguard.Why(err), Err: errText(err)})
			return
		}
		logged = ""
		switch ch {
		case udpguard.Put:
			log.Printf("UDP guard in place: %d filters; UDP leaves the physical adapters only from the core, "+
				"and to the local network", g.Rules())
		case udpguard.Replaced:
			log.Printf("UDP guard put in place again: the filtering engine had dropped it (%d filters)", g.Rules())
		}
		// tried once, when it goes in: not at every look
		if ch != udpguard.Kept && env.probe != nil {
			if checked = env.probe(ctx, g); checked {
				log.Println("UDP guard checked: the engine dropped a test packet sent out of the adapter by its own address")
			} else {
				log.Println("UDP guard not checked: a test packet out of the adapter was not seen dropped " +
					"(none could be tried, or the engine did not record it)")
			}
		}
		say(udpguard.Status{State: udpguard.StateOn, Rules: g.Rules(), Checked: checked})
	}
	for {
		step()
		if !sleepCtx(ctx, guardPeriod) {
			return
		}
	}
}

// errText: an error of Windows' as the page puts it in brackets -- they end in
// a full stop, and the page's sentence has its own
func errText(err error) string {
	return strings.TrimRight(strings.TrimSpace(err.Error()), ".")
}

// startGuard runs holdGuard for the core that has just started, under its
// context; stopGuard ends it
func (s *Supervisor) startGuard(ctx context.Context) {
	gctx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	s.mu.Lock()
	s.guardStop, s.guardDone = stop, done
	s.mu.Unlock()
	go func() {
		defer close(done)
		holdGuard(gctx, s.guard, realGuardEnv())
	}()
}

// stopGuard takes the guard out and waits for it to be out. Asked for a stop
// of the core, it comes before the TUN adapter is taken down: filters kept
// through that would cut every program's UDP off for the seconds it takes.
// Safe to ask again, and with none running.
func (s *Supervisor) stopGuard() {
	s.mu.Lock()
	stop, done := s.guardStop, s.guardDone
	s.mu.Unlock()
	if stop == nil {
		return
	}
	stop()
	<-done
}

// resetGuardStatus: what the UI is told at the service's start, in place of
// what a service before this one left in the file
func resetGuardStatus() {
	if ctl.LoadSettings(paths.Settings()).UDPGuard {
		saveGuardStatus(udpguard.Status{State: udpguard.StateWait, Why: udpguard.WhyCore})
		return
	}
	saveGuardStatus(udpguard.Status{State: udpguard.StateOff})
}
