package supervisor

import (
	"context"
	"log"
	"time"

	"dpiswitch/internal/ctl"
)

// A core just started checks its proxy groups at once, while each AmneziaWG
// handshake is still under way: the check fails, the group marks the tunnel
// dead, and until its next check 30 seconds later what goes through the second
// tunnel went direct (YouTube with it) and the UI said "awg2 not responding".
// The tunnel itself answered some seconds after the start.
//
// So each tunnel is asked right after the start, once a second, until it
// answers: a check through the core's API against HealthURL is kept for that
// URL, the groups read their members' state by it, and the tunnel is back in
// its groups as soon as the handshake is done -- not at the next scheduled
// check.
const warmTimeout = 3000 // ms, one check

// how long and how often; vars for tests
var (
	warmFor   = time.Minute
	warmEvery = time.Second
)

// warmCheck: one check of a tunnel; a var for tests
var warmCheck = func(hc *healthChecker, name string) (bool, string) {
	return hc.check(name, ctl.HealthURL, warmTimeout)
}

// warmTunnels checks every tunnel until each answers, for a minute at most; it
// ends with its core (ctx).
func warmTunnels(ctx context.Context, hc *healthChecker, names []string) {
	start := time.Now()
	left := append([]string(nil), names...)
	for len(left) > 0 && time.Since(start) < warmFor {
		var still []string
		for _, name := range left {
			if ok, detail := warmCheck(hc, name); ok {
				log.Printf("tunnel %s up %.0f s after the core started (%s)",
					name, time.Since(start).Seconds(), detail)
				continue
			}
			still = append(still, name)
		}
		left = still
		if len(left) > 0 && !sleepCtx(ctx, warmEvery) {
			return
		}
	}
	for _, name := range left {
		log.Printf("tunnel %s not up within %v of the core's start: its groups' own checks take over", name, warmFor)
	}
}
