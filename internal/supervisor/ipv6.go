package supervisor

import (
	"context"
	"log"
	"time"

	"dpiswitch/internal/awgconf"
	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
)

// One-shot IPv6 check, run once per tunnel bring-up.
//
// The liveness check in keepHealthy goes to cp.cloudflare.com, whose name
// resolves to an A record under ip-version: ipv4-prefer -- so it passes
// entirely over IPv4, and a tunnel whose IPv6 is dead looks perfectly
// healthy while every IPv6-only host behind it hangs until its timeout.
// Nothing in the log says why. This is the check that says it.
//
// A tunnel found without IPv6 is written with ip-version: ipv4 -- that one
// tunnel, not both -- and the core is restarted to take it. It used to
// re-read the config in place: the core then kept the old WireGuard
// outbound beside the new one, two sessions with one key that the server
// kept taking from each other, and the tunnel dropped for minutes; the
// core's API no longer takes a config from outside its own file either.
// The answer is held across starts (see tunnelV6Hold), so the restart comes
// once, not after every start.
const (
	// A literal address: no DNS in the way, so this measures IPv6 transport
	// and nothing else.
	v6Literal = "http://[2606:4700:4700::1111]/generate_204"
	// Control target, AAAA only. If the literal is silent and this one
	// answers, IPv6 works and the first address is simply unreachable.
	v6Named = "https://ipv6.google.com/generate_204"
)

// checkIPv6 waits for the tunnels to come up, tests IPv6 through each and
// rewrites the config for the ones that cannot carry it. Runs after every core
// start, against a config that was just rebuilt with IPv6 on for every tunnel
// but one found without it within the hold -- an outbound pinned to
// ip-version: ipv4 rejects IPv6 targets, so a check through that one would
// only ever confirm the answer; it is asked again once the hold is over.
func (s *Supervisor) checkIPv6(ctx context.Context) {
	secret := ctl.SecretFromConfig(paths.Config())
	hc := newHealthChecker("127.0.0.1:9090", secret)
	// what the core started with (see startIPv6State): the adapter's
	// answers, and the tunnels found without IPv6 within the hold
	old := ctl.LoadTunnelIPv6(paths.TunnelIPv6())
	held := loadV6Held(paths.TunnelIPv6Held())
	found := ctl.TunnelIPv6{}
	keepTunnelIPv6(old, found)

	// the programs' side first, IPv6 on or off: Windows may keep the
	// programs' traffic from the adapter altogether (see tunv6.go)
	v4, v4known := tunIPv4(ctx, func() bool { return apiReady(apiAddr, secret) })
	if v4known {
		found[ctl.Tun4Key] = v4
		switch {
		case v4 && old.TrafficBlocked():
			log.Println("traffic reaches the DPI Switch adapter again")
		case !v4:
			log.Println("Windows does not let traffic into the DPI Switch adapter: something takes it first -- " +
				"a third-party network filter (a VPN client, an antivirus). While it does, nothing works through " +
				"DPI Switch: stop the service, or let the filter pass the adapter")
		}
	}
	if !ctl.LoadSettings(paths.Settings()).IPv6 {
		// no IPv6 on the adapter now, so nothing to probe: the last answer is
		// kept for the start with IPv6 back on -- lost, that start built the
		// config with IPv6, found it blocked, and re-read every outbound
		keepAdapterIPv6(old, found)
		s.commitTun(ctx, old, found)
		return // IPv6 is off altogether: both tunnels are already ipv4
	}

	// the second tunnel as the config has it: a .conf loaded and left out
	// of the config was waited for a minute, and the first tunnel's answer
	// with it
	names := awgconf.Tunnels()

	// then IPv6, the adapter being reached: Windows may keep IPv6 from it
	// whatever the tunnels carry
	if !v4 {
		// nothing reaches it: IPv6 is no question of its own
		if v, seen := old[ctl.TunKey]; seen {
			found[ctl.TunKey] = v
		}
	} else if ok, known := tunIPv6(ctx); known {
		found[ctl.TunKey] = ok
		switch {
		case ok && old.SystemBlocked():
			log.Println("IPv6 reaches the DPI Switch adapter again")
		case !ok && !old.SystemBlocked():
			log.Println("IPv6 does not reach the DPI Switch adapter: something in Windows takes it first -- " +
				"a third-party network filter (a VPN client, an antivirus). The core runs without IPv6 until its next start")
		}
	} else if v, seen := old[ctl.TunKey]; seen {
		found[ctl.TunKey] = v
	}
	for _, name := range tunnelsToCheck(found, names) {
		if !s.waitTunnel(ctx, hc, name) {
			// the tunnel never came up: no answer about its IPv6 either, so
			// keep what we knew rather than inventing a verdict
			if v, seen := old[name]; seen {
				found[name] = v
			}
			continue
		}
		ok, detail := hc.check(name, v6Literal, 8000)
		if !ok {
			ok, detail = hc.check(name, v6Named, 8000)
		}
		found[name] = ok
		if ok {
			delete(held, name)
		} else {
			held[name] = time.Now()
		}
		switch {
		case ok && old.Dead(name):
			log.Printf("%s: IPv6 works again (%s)", name, detail)
		case !ok && !old.Dead(name):
			log.Printf("%s: IPv6 does not get through the tunnel (%s) -- "+
				"resolving IPv4 only for it, IPv6-only sites will not open through this tunnel", name, detail)
		}
	}
	if found.Same(old) {
		return
	}
	s.commitV6(ctx, func() {
		if err := found.Save(paths.TunnelIPv6()); err != nil {
			log.Printf("IPv6 state not saved: %v", err)
			return
		}
		// not held, the answer would be dropped at the restart and found
		// again, and the core restarted after every start
		if err := held.only(names).save(paths.TunnelIPv6Held()); err != nil {
			log.Printf("IPv6 state not saved, the core keeps its config until its next start: %v", err)
			return
		}
		changed, err := awgconf.Regenerate()
		if err != nil {
			log.Printf("config not rebuilt after the IPv6 check: %v", err)
			return
		}
		if !changed {
			return
		}
		// under v6mu: the core restarted is the one this check measured
		// (ctx is alive), and the next start builds its config after this
		log.Println("restarting the core: the IPv6 check changed its config")
		s.restartCore()
	})
}

// only: the entries of the tunnels the config has, the rest dropped
func (h v6Held) only(names []string) v6Held {
	out := v6Held{}
	for _, n := range names {
		if at, ok := h[n]; ok {
			out[n] = at
		}
	}
	return out
}

// commitTun writes the adapter's answer alone -- IPv6 being off, nothing in
// the config depends on it
func (s *Supervisor) commitTun(ctx context.Context, old, found ctl.TunnelIPv6) {
	if found.Same(old) {
		return
	}
	s.commitV6(ctx, func() {
		if err := found.Save(paths.TunnelIPv6()); err != nil {
			log.Printf("IPv6 state not saved: %v", err)
		}
	})
}

// commitV6 writes what a check found -- the state file, the config, the
// core's restart -- only while the core it measured still runs: ctx ends
// with it. Under v6mu, which the next core's start holds while it resets
// IPv6 for everyone, the check either finishes before that start or sees
// its core gone and writes nothing.
func (s *Supervisor) commitV6(ctx context.Context, commit func()) bool {
	s.v6mu.Lock()
	defer s.v6mu.Unlock()
	if ctx.Err() != nil {
		log.Println("IPv6 check outlived its core: the new core's own check will answer")
		return false
	}
	commit()
	return true
}

// waitTunnel: an IPv6 answer means nothing until the tunnel itself is up --
// during the handshake everything is silent and every verdict would be false.
func (s *Supervisor) waitTunnel(ctx context.Context, hc *healthChecker, name string) bool {
	for i := 0; i < 12; i++ {
		if ok, _ := hc.check(name, ctl.HealthURL, 5000); ok {
			return true
		}
		if !sleepCtx(ctx, 5*time.Second) {
			return false
		}
	}
	return false
}
