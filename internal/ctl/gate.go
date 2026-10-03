package ctl

import (
	"log"
	"strings"
	"time"
)

// gate holds probing back while the network is not itself. A probe then
// measures the moment, not the path: after a wake from sleep the first cycle
// ran before the network was up -- the direct resolver did not answer, a
// direct name failed to resolve -- and at 00:37 on 24.09, while the tunnel's
// own checks were failing, four clean names were measured SLOWER in a minute.
type gate struct {
	interval time.Duration
	last     time.Time // the previous tick, by the wall clock
	paused   bool
}

// allow: whether this tick's cycle may probe. now is the wall clock
// (time.Now().Round(0)): the monotonic one need not run while the machine
// sleeps. health is the tunnel as the core's own checks last found it.
func (g *gate) allow(now time.Time, health func() (bool, string, error)) bool {
	gap := now.Sub(g.last)
	first := g.last.IsZero()
	g.last = now
	// ticks come every interval; a gap well past it is a sleep, or a pause
	// with no network. The network comes back a little after the machine.
	// Three minutes at least: a cycle of blocked names takes half a minute,
	// and the next tick waits for it.
	if !first && gap > max(3*g.interval, 3*time.Minute) {
		log.Printf("resumed after %s: probes wait a cycle for the network to settle",
			gap.Round(time.Second))
		return false
	}
	ok, note, err := health()
	switch {
	case err != nil:
		ok, note = false, "the tunnel does not answer (core API not responding: "+err.Error()+")"
	case !ok && note != "" && !strings.HasPrefix(note, "no first tunnel"):
		note = "the tunnel does not answer (" + note + ")"
	case !ok && note == "":
		note = "the tunnel does not answer"
	}
	if !ok {
		if !g.paused {
			log.Printf("probes paused: %s", note)
			g.paused = true
		}
		return false
	}
	if g.paused {
		if strings.HasPrefix(note, "no first tunnel") {
			log.Printf("probes resumed: %s", note)
		} else {
			log.Printf("probes resumed: the tunnel answers (%s)", note)
		}
		g.paused = false
	}
	return true
}
