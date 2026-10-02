package webui

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
)

// The tunnels' state as the tray, the header and the overview show it, in
// step with the traffic. The core checks each tunnel every 30 seconds, and
// what the last check found was shown: a tunnel gone dead stayed green for
// up to half a minute, and the tray looked every ten seconds on top of it.
//
// The live loop sees every connection every second (see liveHub.update).
// Bytes coming in through a tunnel the last check found dead, or dials
// through it failing while nothing comes in, say the check is out of date:
// the core is asked to check that tunnel now. Its answer goes into the
// history every reader reads -- the state is the core's checks still, only
// never older than the traffic. A tunnel nothing goes through has nothing
// to say, and keeps the last check's word.

type tunnelState struct {
	Alive bool
	Note  string
	at    time.Time // when it was read; zero: never
}

type tunnelPulse struct {
	mu      sync.Mutex
	recv    map[string]time.Time // bytes last came in through the tunnel
	fail    map[string]time.Time // a dial through it last failed
	asked   map[string]time.Time // a check was last asked for
	state   map[string]tunnelState
	looking bool // a look under way: the next tick does not start another
	changed chan struct{}

	health func(proxy string) (bool, string) // the core's last check
	check  func(proxy string)                // the core checks now
}

var pulseTunnels = []string{"awg", "awg2"}

// how fresh traffic must be to speak for the tunnel, how often one tunnel
// may be checked out of turn, and how long such a check waits
var (
	pulseRecent  = 2 * time.Second
	pulseAgain   = 3 * time.Second
	pulseTimeout = 2 * time.Second
)

func newTunnelPulse(health func(string) (bool, string), check func(string)) *tunnelPulse {
	return &tunnelPulse{recv: map[string]time.Time{}, fail: map[string]time.Time{},
		asked: map[string]time.Time{}, state: map[string]tunnelState{},
		changed: make(chan struct{}, 1), health: health, check: check}
}

// pulse: the process's own, on the core the service runs
var pulse = newTunnelPulse(
	func(p string) (bool, string) {
		return ctl.TunnelHealth(apiAddr, ctl.SecretFromConfig(paths.Config()), p)
	},
	func(p string) {
		ctl.CheckTunnel(apiAddr, ctl.SecretFromConfig(paths.Config()), p, pulseTimeout)
	})

// saw takes one tick's traffic -- the tunnels bytes came in through, and
// those a dial failed through -- and looks at the tunnels again.
func (p *tunnelPulse) saw(now time.Time, recv, fail map[string]bool) {
	p.mu.Lock()
	for t := range recv {
		p.recv[t] = now
	}
	for t := range fail {
		p.fail[t] = now
	}
	if p.looking {
		p.mu.Unlock()
		return
	}
	p.looking = true
	p.mu.Unlock()
	go func() {
		p.look(now)
		p.mu.Lock()
		p.looking = false
		p.mu.Unlock()
	}()
}

// look reads each tunnel's last check, and has the core check it again
// when the traffic says otherwise
func (p *tunnelPulse) look(now time.Time) {
	for _, t := range pulseTunnels {
		alive, note := p.health(t)
		p.mu.Lock()
		recv := now.Sub(p.recv[t]) < pulseRecent
		fail := now.Sub(p.fail[t]) < pulseRecent
		ask := (alive && fail && !recv || !alive && recv) && now.Sub(p.asked[t]) >= pulseAgain
		if ask {
			p.asked[t] = now
		}
		p.mu.Unlock()
		if ask {
			p.check(t)
			alive, note = p.health(t)
		}
		p.set(t, alive, note)
	}
}

func (p *tunnelPulse) set(t string, alive bool, note string) {
	p.mu.Lock()
	was := p.state[t]
	p.state[t] = tunnelState{alive, note, time.Now()}
	p.mu.Unlock()
	if was.at.IsZero() || was.Alive != alive || was.Note != note {
		select {
		case p.changed <- struct{}{}:
		default:
		}
	}
}

// get: a tunnel's state, if read lately -- the loop stopped, it is not
func (p *tunnelPulse) get(t string) (tunnelState, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.state[t]
	return s, !s.at.IsZero() && time.Since(s.at) < 3*time.Second
}

// Tunnel: a tunnel's state as the UI shows it, for the tray; ok false when
// the UI has not read it lately -- then the tray asks the core itself
func Tunnel(name string) (alive bool, note string, ok bool) {
	s, ok := pulse.get(name)
	return s.Alive, s.Note, ok
}

// TunnelChanged: told when a tunnel's state changes, for the tray to
// redraw its icon at once
func TunnelChanged() <-chan struct{} { return pulse.changed }

// handleTunnels: the tunnels' state for the header's chips and the
// overview's, every second (see ui.js)
func (s *Server) handleTunnels(w http.ResponseWriter, r *http.Request) {
	l := lang(r)
	out := map[string]any{}
	for _, t := range pulseTunnels {
		st, ok := pulse.get(t)
		if !ok {
			continue
		}
		// the header's chip says the note alone when alive; the overview's
		// pill says so, the note after it -- as the templates draw them
		note := TunnelNote(l, st.Note)
		text, pill := tr(l, "not responding"), tr(l, "not responding")
		if st.Alive {
			text, pill = note, tr(l, "responding")+" · "+note
		}
		out[t] = map[string]any{"alive": st.Alive, "text": text, "pill": pill, "note": note}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(out)
}
