package udpguard

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/tailscale/wf"
)

// wfpEngine: a dynamic session of the Windows Filtering Platform with our
// provider, sublayer and filters in it
type wfpEngine struct {
	s *wf.Session
}

// openWFP opens the session and puts the plan in. A plan that is only partly
// in is taken out again: a block with no permit before it is not to be left.
func openWFP(p plan) (engine, error) {
	s, err := wf.New(&wf.Options{
		Name:        "DPI Switch UDP guard",
		Description: "UDP that would leave around the tunnel",
		// the filters end with the session: a service that dies leaves none
		Dynamic: true,
	})
	if err != nil {
		return nil, &EngineError{err}
	}
	e := &wfpEngine{s: s}
	if err := e.put(p); err != nil {
		s.Close()
		return nil, err
	}
	return e, nil
}

func (e *wfpEngine) put(p plan) error {
	if err := e.s.AddProvider(&p.provider); err != nil {
		return fmt.Errorf("provider: %w", err)
	}
	if err := e.s.AddSublayer(&p.sublayer); err != nil {
		return fmt.Errorf("sublayer: %w", err)
	}
	for _, r := range p.rules {
		if err := e.s.AddRule(r); err != nil {
			return fmt.Errorf("%s: %w", r.Name, err)
		}
	}
	return nil
}

// alive asks for the sublayer by its provider: a few bytes of an answer,
// where a look at the filters would list every one of the system's. The
// session itself answers nothing once the engine has restarted.
func (e *wfpEngine) alive() bool {
	sl, err := e.s.Sublayers(providerKey)
	return err == nil && len(sl) > 0
}

func (e *wfpEngine) close() { e.s.Close() }

// dropped reads the engine's net events: a packet a filter drops is recorded
// with its addresses, ports and the program that sent it, within moments.
func (e *wfpEngine) dropped(local, remote netip.AddrPort, since time.Time) bool {
	return sessionSawDrop(e.s, local, remote, since)
}

// sessionSawDrop: the engine's record is the engine's, not the session's --
// any session sees the packets dropped for any other's filters
func sessionSawDrop(s *wf.Session, local, remote netip.AddrPort, since time.Time) bool {
	evs, err := s.DropEvents()
	if err != nil {
		return false
	}
	local, remote = unzoned(local), unzoned(remote)
	for _, ev := range evs {
		if ev.IPProtocol == uint8(wf.IPProtoUDP) && ev.LocalAddr == local && ev.RemoteAddr == remote && !ev.Timestamp.Before(since) {
			return true
		}
	}
	return false
}

// unzoned: an address as the engine records it, with no scope
func unzoned(a netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(a.Addr().WithZone(""), a.Port())
}
