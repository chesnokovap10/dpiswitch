package ctl

import (
	"log"
	"slices"
	"time"

	"dpiswitch/internal/probe"
)

// A CDN host of a family going direct goes the family's way before it has
// a verdict of its own. One whose node the direct path does not reach hung
// the player for as long as its check took: three timeouts, 25 s, on a
// googlevideo node on 23.10 -- and through the tunnel it would get no
// further (the media URL is signed for the home address, see inherit.go).
// So beside the full check a quick pass is made on it, all three ways at
// once (probe.QuickDead); neither direct way through while the tunnel is,
// it is refused at once, as its verdict would have it, and its connections
// hanging on it are closed. The full check's verdict then decides: the mark
// goes when it is filed, or after quickTerm.

var (
	// quickWait: how long each way of the quick pass may take. A node that
	// answers does in a fraction of a second; one that is slow beyond it
	// is refused until its check says otherwise, and the player takes
	// another host meanwhile.
	quickWait = 3 * time.Second
	// quickTerm: how long a quick refusal holds with no verdict filed
	quickTerm = 2 * time.Minute
	// quickDead: probe.QuickDead, a var for the tests
	quickDead = probe.QuickDead
)

// quickRefuse marks dom refused by a quick pass, until until
func (s *state) quickRefuse(id, dom string, until time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.quick == nil {
		s.quick = map[string]map[string]time.Time{}
	}
	if s.quick[id] == nil {
		s.quick[id] = map[string]time.Time{}
	}
	s.quick[id][dom] = until
}

// unquick: dom's verdict is filed, and it decides
func (s *state) unquick(id, dom string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.quick[id], dom)
}

// quickRefusedLocked: the names refused by a quick pass now, with no live
// verdict of their own; mu held
func (s *state) quickRefusedLocked(id string, now time.Time) []string {
	var out []string
	for dom, until := range s.quick[id] {
		if !now.Before(until) {
			delete(s.quick[id], dom)
			continue
		}
		if e, ok := s.Networks[id][dom]; ok && now.Before(e.ExpiresAt) {
			continue
		}
		out = append(out, dom)
	}
	return out
}

// quickWanted: whether dom gets a quick pass -- a CDN host of a family
// going direct now, with no live verdict, checked on TCP 443
func quickWanted(cfg Config, st *state, netID, dom string, eps []endpoint) bool {
	if !inheritOn(cfg) || cfg.cdns == nil || cfg.FamilyDirectPath == "" {
		return false
	}
	if _, addr := probe.AddrKey(dom); addr {
		return false
	}
	if !slices.ContainsFunc(eps, func(e endpoint) bool { return !e.udp && e.port == 443 }) {
		return false
	}
	if e, ok := st.get(netID, dom); ok && time.Now().Before(e.ExpiresAt) {
		return false
	}
	return directFamilyCDN(cfg, dom)
}

// directFamilyCDN: dom is a CDN host of a family the list sends direct
func directFamilyCDN(cfg Config, dom string) bool {
	direct := map[string]bool{}
	for _, r := range listRules(cfg.FamilyDirectPath) {
		direct[r] = true
	}
	for _, f := range cfg.cdns.families() {
		if cdn, _ := f.cdnOf(dom); cdn && direct["+."+f.CDN] {
			return true
		}
	}
	return false
}

// quickCheck: the quick pass on dom, and the refusal it calls for
func quickCheck(cfg Config, a *api, st *state, netID, dom string, direct, split, tunnel probe.Dialer) {
	t0 := time.Now()
	ip, dead := quickDead(direct, split, tunnel, dom, quickWait)
	if !dead {
		return
	}
	st.quickRefuse(netID, dom, time.Now().Add(quickTerm))
	log.Printf("  %s refused at once: node %s answers neither direct nor with the ClientHello cut, the tunnel does (%s); its check decides",
		dom, ip, time.Since(t0).Round(100*time.Millisecond))
	syncList(cfg, a, st, netID, false)
	if n := closeHost(a, dom); n > 0 {
		log.Printf("  closed %d connections to %s going direct", n, dom)
	}
}

// closeHost closes the connections to dom going direct or with the cut --
// hanging on a node that does not answer, they held the player until they
// timed out
func closeHost(a *api, dom string) int {
	conns, err := a.connections()
	if err != nil {
		return 0
	}
	n := 0
	for _, c := range conns {
		if c.ID == "" || c.domain() != dom || c.fromProbe() || len(c.Chains) == 0 {
			continue
		}
		if c.Chains[0] != "DIRECT" && c.Chains[0] != SplitOutbound {
			continue
		}
		if err := a.closeConnection(c.ID); err == nil {
			n++
		}
	}
	return n
}
