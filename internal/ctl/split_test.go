package ctl

import (
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
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

// setMode: the scenario's controller in a mode, auto-switch off as the
// watcher leaves it for observe only and tunnel only
func (s *scenario) setMode(m string) {
	if s.cfg.mode == nil {
		s.cfg.mode = &atomic.Value{}
		s.cfg.autoOff = &atomic.Bool{}
	}
	s.cfg.mode.Store(m)
	s.cfg.Apply = m == ModeOn
	s.cfg.autoOff.Store(m != ModeOn)
}

// Observe only sends everything direct, the cut's names with the cut: its
// list is written there, and the plain direct list is not. Tunnel only
// sends nothing direct: its list goes empty.
func TestSplitObserveAndTunnel(t *testing.T) {
	s, _ := splitScenario(t, map[string]probe.Verdict{"ig.example.org": probe.CleanSplit})
	s.setMode(ModeObserve)
	s.see(tunnelled("ig.example.org", 443), tunnelled("c.example.org", 443))
	s.script("ig.example.org tcp/443", blockedTLS("192.0.2.10"))
	s.script("c.example.org tcp/443", clean("192.0.2.11"))
	s.cycle()
	if got := listRules(s.cfg.SplitListPath); !slices.Equal(got, []string{"ig.example.org"}) {
		t.Fatalf("observe only: cut list %v", got)
	}
	// everything goes the cut's way there: what the cut does not need goes
	// plain by the direct list, above the cut's catch-all
	if got := listRules(s.cfg.ListPath); !slices.Equal(got, []string{"c.example.org"}) {
		t.Fatalf("observe only: plain direct list %v", got)
	}
	// with the cut off, observe only sends all plain: no list at all
	s.cfg.Split = false
	disableAuto(s.cfg, s.api, s.st, false)
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.ListPath); len(got) != 0 {
		t.Fatalf("observe only, cut off: plain direct list %v", got)
	}
	s.cfg.Split = true
	s.cfg.autoOff.Store(false)

	s.setMode(ModeTunnel)
	disableAuto(s.cfg, s.api, s.st, true)
	s.cycle()
	if got := listRules(s.cfg.SplitListPath); len(got) != 0 {
		t.Fatalf("tunnel only: cut list %v", got)
	}

	// back to observe only: the list comes back from memory
	s.setMode(ModeObserve)
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.SplitListPath); !slices.Equal(got, []string{"ig.example.org"}) {
		t.Fatalf("observe only again: cut list %v", got)
	}
}

// With no first tunnel the cut is checked alone: a name taken by the last
// rule and gone direct is a candidate, its 443 probed direct against the
// cut. A verdict made so is marked, sends nothing direct plain, and is the
// first checked once there is a tunnel.
func TestSplitAlone(t *testing.T) {
	s, _ := splitScenario(t, nil)
	s.cfg.alone = true
	var tried []string
	old := checkAlone
	checkAlone = func(_, _ probe.Dialer, dom string, _ int, _ probe.Verdict) probe.Report {
		s.mu.Lock()
		tried = append(tried, dom)
		s.mu.Unlock()
		v := map[string]probe.Verdict{"ig.example.org": probe.CleanSplit, "c.example.org": probe.Clean}[dom]
		return probe.Report{Domain: dom, Port: 443, Proto: "tcp", TestedIP: "192.0.2.10", Verdict: v,
			Direct: pathOK, Tunnel: pathOK}
	}
	t.Cleanup(func() { checkAlone = old })
	direct := func(h string, port int) connection { return via(h, port, "tcp", "DIRECT", "Match", "") }
	s.see(direct("ig.example.org", 443), direct("c.example.org", 443), direct("c.example.org", 5228))
	s.cycle()
	slices.Sort(tried)
	if !slices.Equal(tried, []string{"c.example.org", "ig.example.org"}) {
		t.Fatalf("checked alone %v", tried)
	}
	if len(s.probed) != 0 {
		t.Errorf("probed against a tunnel with none: %v", s.probed)
	}
	if e := s.entry("ig.example.org"); e.Verdict != probe.CleanSplit || !e.Alone {
		t.Fatalf("ig: %s, alone %v", e.Verdict, e.Alone)
	}
	if got := listRules(s.cfg.SplitListPath); !slices.Equal(got, []string{"ig.example.org"}) {
		t.Fatalf("cut list %v", got)
	}
	if got := listRules(s.cfg.ListPath); len(got) != 0 {
		t.Fatalf("a CLEAN with nothing to compare went to the direct list: %v", got)
	}
	if e := s.entry("c.example.org"); slices.Contains(e.Endpoints, "tcp/5228") {
		t.Errorf("a port the cut has nothing to do with was checked: %v", e.Endpoints)
	}

	// a tunnel loaded: both are checked again against it at once
	s.cfg.alone = false
	s.script("ig.example.org tcp/443", blockedTLS("192.0.2.10"))
	s.script("c.example.org tcp/443", clean("192.0.2.11"))
	s.see()
	s.cycle()
	if !s.wasProbed("ig.example.org tcp/443") || !s.wasProbed("c.example.org tcp/443") {
		t.Fatalf("not checked again with a tunnel: %v", s.probed)
	}
	if e := s.entry("c.example.org"); e.Verdict != probe.Clean || e.Alone {
		t.Fatalf("c: %s, alone %v", e.Verdict, e.Alone)
	}
}
