package ctl

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"dpiswitch/internal/probe"
)

// splitScenario: a scenario with the ClientHello cut switched on and its
// probe scripted -- by name, what the cut path shows.
func splitScenario(t *testing.T, cut map[string]probe.Verdict) (*scenario, *[]string) {
	s := newScenario(t)
	s.cfg.Split = true
	s.cfg.SplitProvider = SplitProvider
	s.cfg.SplitListPath = filepath.Join(filepath.Dir(s.cfg.ListPath), "direct-split-verified.txt")
	var tried []string
	old := checkSplit
	checkSplit = func(_, _ probe.Dialer, plain probe.Report, _ int, _ probe.Verdict) probe.Report {
		s.mu.Lock()
		tried = append(tried, plain.Domain)
		s.mu.Unlock()
		r := probe.Report{Domain: plain.Domain, Port: plain.Port, Proto: "tcp", TestedIP: plain.TestedIP,
			Verdict: cut[plain.Domain], Direct: pathOK, Tunnel: pathOK, Note: "ClientHello cut"}
		if r.Verdict != probe.CleanSplit {
			r.Direct, r.Reason = tlsCut, "tls: EOF"
		}
		return r
	}
	t.Cleanup(func() { checkSplit = old })
	return s, &tried
}

// Blocked by its name, clean with the hello cut: the name goes to the cut's
// list, not the plain direct one, for the term of a CLEAN. Its QUIC, blocked
// as well, does not keep it in the tunnel: the core refuses QUIC to it.
func TestCycleSplitGoesDirect(t *testing.T) {
	s, tried := splitScenario(t, map[string]probe.Verdict{"ig.example.org": probe.CleanSplit})
	s.see(tunnelled("ig.example.org", 443), quic("ig.example.org"))
	s.script("ig.example.org tcp/443", blockedTLS("192.0.2.10"))
	s.script("ig.example.org quic/443", probe.Report{Verdict: probe.BlockedQUIC, TestedIP: "192.0.2.10",
		Direct: tcpFails, Tunnel: pathOK})
	s.cycle()
	e := s.entry("ig.example.org")
	if e == nil || e.Verdict != probe.CleanSplit {
		t.Fatalf("verdict %v", e)
	}
	if d := time.Until(e.ExpiresAt); d < s.cfg.TTL-time.Minute {
		t.Errorf("term %s, want the direct term %s", d, s.cfg.TTL)
	}
	if !slices.Equal(*tried, []string{"ig.example.org"}) {
		t.Errorf("cut tried for %v", *tried)
	}
	if got := listRules(s.cfg.SplitListPath); !slices.Equal(got, []string{"ig.example.org"}) {
		t.Fatalf("cut list %v", got)
	}
	if got := listRules(s.cfg.ListPath); len(got) != 0 {
		t.Fatalf("plain direct list %v", got)
	}
	if s.reloads[SplitProvider] == 0 {
		t.Fatal("the core was not told to reload the cut's list")
	}
}

// The cut switched off: a name blocked by its hello is not tried with it,
// and stays in the tunnel.
func TestCycleSplitOff(t *testing.T) {
	s, tried := splitScenario(t, map[string]probe.Verdict{"ig.example.org": probe.CleanSplit})
	s.cfg.Split = false
	s.see(tunnelled("ig.example.org", 443))
	s.script("ig.example.org tcp/443", blockedTLS("192.0.2.10"))
	s.cycle()
	if e := s.entry("ig.example.org"); e.Verdict != probe.BlockedTLS {
		t.Fatalf("verdict %s", e.Verdict)
	}
	if len(*tried) != 0 {
		t.Errorf("cut tried for %v", *tried)
	}
	if got := listRules(s.cfg.SplitListPath); len(got) != 0 {
		t.Fatalf("cut list %v", got)
	}
}

// The cut does not get through either: the block the plain path found
// stands, with what the cut showed beside it. Other verdicts are not tried
// with the cut: it hides the name, and nothing else.
func TestCycleSplitFails(t *testing.T) {
	s, tried := splitScenario(t, map[string]probe.Verdict{"wa.example.org": probe.BlockedTLS})
	s.see(tunnelled("wa.example.org", 443), tunnelled("tcp.example.org", 443))
	s.script("wa.example.org tcp/443", blockedTLS("192.0.2.11"))
	s.script("tcp.example.org tcp/443", probe.Report{Verdict: probe.BlockedTCP, TestedIP: "192.0.2.12",
		Direct: tcpFails, Tunnel: pathOK})
	s.cycle()
	if e := s.entry("wa.example.org"); e.Verdict != probe.BlockedTLS {
		t.Fatalf("verdict %s", e.Verdict)
	}
	if !slices.Equal(*tried, []string{"wa.example.org"}) {
		t.Errorf("cut tried for %v", *tried)
	}
	if got := listRules(s.cfg.SplitListPath); len(got) != 0 {
		t.Fatalf("cut list %v", got)
	}
}

// Switched off, the cut's list empties at once, and its names, checked
// again without it, come out blocked with no revert counted: they lost
// nothing they were checked for.
func TestSplitSwitchedOff(t *testing.T) {
	s, _ := splitScenario(t, map[string]probe.Verdict{"ig.example.org": probe.CleanSplit})
	s.see(tunnelled("ig.example.org", 443))
	s.script("ig.example.org tcp/443", blockedTLS("192.0.2.10"))
	s.cycle()
	s.cfg.Split = false
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.SplitListPath); len(got) != 0 {
		t.Fatalf("cut list after switching off %v", got)
	}
	e := s.entry("ig.example.org")
	e.ExpiresAt = time.Now().Add(-time.Minute)
	s.see(tunnelled("ig.example.org", 443))
	s.cycle()
	e = s.entry("ig.example.org")
	if e.Verdict != probe.BlockedTLS || e.Reverts != 0 {
		t.Fatalf("verdict %s, reverts %d", e.Verdict, e.Reverts)
	}
}

// Names going direct with the cut make no family: the domain is blocked by
// name, and a family would send new subdomains direct without the cut.
func TestSplitNoFamily(t *testing.T) {
	s, _ := splitScenario(t, map[string]probe.Verdict{
		"a.cut.example": probe.CleanSplit, "b.cut.example": probe.CleanSplit, "c.cut.example": probe.CleanSplit})
	for _, h := range []string{"a.cut.example", "b.cut.example", "c.cut.example"} {
		s.see(tunnelled(h, 443))
		s.script(h+" tcp/443", blockedTLS("192.0.2.20"))
	}
	s.see(tunnelled("a.cut.example", 443), tunnelled("b.cut.example", 443), tunnelled("c.cut.example", 443))
	s.cycle()
	if got := listRules(s.cfg.ListPath); len(got) != 0 {
		t.Fatalf("plain direct list %v", got)
	}
	if got := listRules(s.cfg.SplitListPath); len(got) != 3 {
		t.Fatalf("cut list %v", got)
	}
}

// The cut's connections are direct ones: one open with nothing come back
// is a suspect, re-checked before its term.
func TestSplitSuspect(t *testing.T) {
	s, _ := splitScenario(t, map[string]probe.Verdict{"ig.example.org": probe.CleanSplit})
	s.see(tunnelled("ig.example.org", 443))
	s.script("ig.example.org tcp/443", blockedTLS("192.0.2.10"))
	s.cycle()
	c := via("ig.example.org", 443, "tcp", SplitOutbound, "RuleSet", SplitProvider)
	c.Download = 0
	got := suspectDirect(s.cfg, s.st, "n", []connection{c})
	if !slices.Equal(got, []string{"ig.example.org"}) {
		t.Fatalf("suspects %v", got)
	}
	if !strings.Contains(strings.Join(listRules(s.cfg.SplitListPath), ","), "ig.example.org") {
		t.Fatal("not in the cut's list")
	}
}
