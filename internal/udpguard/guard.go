// Package udpguard keeps UDP from leaving around the tunnel.
//
// While the core runs and its TUN adapter takes the programs' traffic, a
// program may still send UDP out of the physical adapter by binding its
// socket to that adapter's address: the routes are not asked then (see
// policy.go). That is how a browser's WebRTC shows a site the real address,
// and how a messenger's or a game's own UDP goes around the tunnel. The guard
// blocks it: every UDP packet out of a cable, Wi-Fi or mobile adapter but the
// core's own and the local network's.
//
// The filters are put into the Windows Filtering Platform itself, the layer
// Windows Firewall and the third-party ones are built on, not into Windows
// Firewall's rules: those do nothing with that firewall off or another one
// in charge, and the platform's filters hold either way. All they need is the
// Base Filtering Engine service, which runs whenever any firewall does. The
// session is dynamic -- the filters go with it: lifted, or with the service
// should it die, and never outlive it.
package udpguard

import (
	"errors"
	"net/netip"
	"sync"
	"time"
)

// engine: the filters in place, and the session that holds them
type engine interface {
	// alive: whether the filters are still there -- the filtering engine
	// drops every dynamic one when the Base Filtering Engine service restarts
	alive() bool
	// close takes them all out at once
	close()
	// dropped: whether the engine reports a UDP packet from local to remote
	// dropped since the time given. A block gives the sender no error -- the
	// send goes through as if the packet were on its way -- so this is the
	// only way to tell a packet blocked from one sent.
	dropped(local, remote netip.AddrPort, since time.Time) bool
}

// EngineError: the filtering engine could not be opened -- its service is
// stopped or refuses us -- as against a filter of ours it did not take
type EngineError struct{ Err error }

func (e *EngineError) Error() string { return e.Err.Error() }
func (e *EngineError) Unwrap() error { return e.Err }

// Why: the Status.Why of a failed Ensure
func Why(err error) string {
	var ee *EngineError
	if errors.As(err, &ee) {
		return WhyEngine
	}
	return WhyOther
}

// Change: what Ensure did
type Change int

const (
	Kept     Change = iota // it was in place
	Put                    // put in
	Replaced               // it had gone from the engine, or the core was another one: put in again
)

// Guard: the filters, or none. Not for use from several goroutines at once
// as a whole, but each call is safe against the others.
type Guard struct {
	// open puts a plan into the engine; the tests' own in place of Windows'
	open func(plan) (engine, error)

	mu   sync.Mutex
	eng  engine
	core string
	n    int
}

func New() *Guard { return &Guard{open: openWFP} }

// Ensure has the guard in place for the core at the path given. One in place
// is looked at, and put in again if the engine lost it -- its service
// restarted -- or the core is another.
func (g *Guard) Ensure(core string) (Change, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	ch := Put
	if g.eng != nil {
		if g.core == core && g.eng.alive() {
			return Kept, nil
		}
		g.eng.close()
		g.eng, g.n, ch = nil, 0, Replaced
	}
	p, err := buildPlan(core)
	if err != nil {
		return ch, err
	}
	eng, err := g.open(p)
	if err != nil {
		return ch, err
	}
	g.eng, g.core, g.n = eng, core, len(p.rules)
	return ch, nil
}

// Lift takes the guard out, and says whether there was one
func (g *Guard) Lift() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.eng == nil {
		return false
	}
	g.eng.close()
	g.eng, g.n = nil, 0
	return true
}

// Dropped: whether the engine reports the UDP packet from local to remote
// dropped since the time given -- the evidence the guard holds, as against
// only being in the engine. False with no guard in place.
func (g *Guard) Dropped(local, remote netip.AddrPort, since time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.eng != nil && g.eng.dropped(local, remote, since)
}

// Rules: how many filters are in place
func (g *Guard) Rules() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.n
}
