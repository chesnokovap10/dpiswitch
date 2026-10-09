package ctl

import (
	"slices"
	"sort"
	"testing"
)

// A network changed: what the detector's lists routed is closed, to be
// routed again by the new network's lists; the user's lists, the local
// network and the prober's own stay.
func TestCloseOnNetworkChange(t *testing.T) {
	s := newScenario(t)
	conn := func(id, rule, payload string) connection {
		c := famConn(id, id+".example.com", "awg1")
		c.Rule, c.RulePayload = rule, payload
		return c
	}
	probe := conn("probe", "Match", "")
	probe.Metadata.InboundName = "probe-tunnel"
	s.mu.Lock()
	s.conns = []connection{
		conn("match", "Match", ""),
		conn("verified", "RuleSet", s.cfg.Provider),
		conn("hold", "RuleSet", HoldProvider),
		conn("family", "RuleSet", FamilyTunnelProvider),
		conn("inherit-ip", "AND", "((DomainRegex,.+) && (RuleSet,inherit-ip))"),
		conn("user", "RuleSet", "force-tunnel"),
		conn("userdirect", "RuleSet", "force-direct"),
		conn("lan", "IPCIDR", "192.168.0.0/16"),
		probe,
	}
	s.mu.Unlock()
	if n := closeOnNetworkChange(s.cfg, s.api); n != 5 {
		t.Errorf("closed %d", n)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sort.Strings(s.closed)
	if want := []string{"family", "hold", "inherit-ip", "match", "verified"}; !slices.Equal(s.closed, want) {
		t.Fatalf("closed %v, want %v", s.closed, want)
	}
}
