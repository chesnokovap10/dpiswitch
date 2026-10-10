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

// The cut does not get through either: BLOCKED_DPI, with what the cut
// showed beside it, routed and re-checked like the block the plain path
// found. Other verdicts are not tried with the cut: it hides the name, and
// nothing else.
func TestCycleSplitFails(t *testing.T) {
	s, tried := splitScenario(t, map[string]probe.Verdict{"wa.example.org": probe.BlockedTLS})
	s.see(tunnelled("wa.example.org", 443), tunnelled("tcp.example.org", 443))
	s.script("wa.example.org tcp/443", blockedTLS("192.0.2.11"))
	s.script("tcp.example.org tcp/443", probe.Report{Verdict: probe.BlockedTCP, TestedIP: "192.0.2.12",
		Direct: tcpFails, Tunnel: pathOK})
	s.cycle()
	e := s.entry("wa.example.org")
	if e.Verdict != probe.BlockedDPI {
		t.Fatalf("verdict %s", e.Verdict)
	}
	if !e.ExpiresAt.Before(time.Now().Add(s.cfg.FailTTL + time.Minute)) {
		t.Errorf("re-checked at %s: not on a block's schedule", e.ExpiresAt)
	}
	if got := s.entry("tcp.example.org").Verdict; got != probe.BlockedTCP {
		t.Errorf("tcp.example.org: %s", got)
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

// A cycle begun with the cut on writes its list by the cut as switched now:
// on 09.10 one ending a second after the switch put 28 names back on the
// cut's way, and music.youtube.com opened there and stayed.
func TestSplitSwitchedOffDuringCycle(t *testing.T) {
	s, _ := splitScenario(t, map[string]probe.Verdict{"ig.example.org": probe.CleanSplit})
	s.cfg.cut = new(atomic.Value)
	s.see(tunnelled("ig.example.org", 443))
	s.script("ig.example.org tcp/443", blockedTLS("192.0.2.10"))
	s.cycle()
	if got := listRules(s.cfg.SplitListPath); len(got) != 1 {
		t.Fatalf("cut on: list %v", got)
	}
	// switched off; the cycle's copy still says on
	s.cfg.setCut(cutState{false, false})
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.SplitListPath); len(got) != 0 {
		t.Fatalf("the cycle's copy wrote the cut's list after it was switched off: %v", got)
	}
}

// The decoy's flag follows the switch as it is now: off, the rules refusing
// QUIC on the cut's lent ways -- a family going direct, inheritance -- fit
// UDP; on, nothing.
func TestQUICDecoyOffFlag(t *testing.T) {
	s, _ := splitScenario(t, map[string]probe.Verdict{"ig.example.org": probe.CleanSplit})
	s.cfg.QUICOffPath = filepath.Join(filepath.Dir(s.cfg.ListPath), "quic-decoy-off.txt")
	s.cfg.cut = new(atomic.Value)
	s.cfg.setCut(cutState{true, true})
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.QUICOffPath); len(got) != 0 {
		t.Fatalf("decoy on: flag %v", got)
	}
	s.cfg.setCut(cutState{true, false})
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.QUICOffPath); !slices.Equal(got, []string{"NETWORK,UDP"}) {
		t.Fatalf("decoy off: flag %v", got)
	}
	if s.reloads[QUICOffProvider] == 0 {
		t.Error("the flag's provider not reloaded")
	}
	s.cfg.setCut(cutState{true, true})
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.QUICOffPath); len(got) != 0 {
		t.Fatalf("decoy on again: flag %v", got)
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

// quicScenario: the cut and the QUIC decoy switched on, the decoy's probe
// scripted -- by name, what QUIC through it shows.
func quicScenario(t *testing.T, cut, decoy map[string]probe.Verdict) (*scenario, *[]string) {
	s, _ := splitScenario(t, cut)
	s.cfg.QUICFake = true
	s.cfg.NoQUICProvider = NoQUICProvider
	s.cfg.NoQUICListPath = filepath.Join(filepath.Dir(s.cfg.ListPath), "direct-split-noquic.txt")
	var tried []string
	old := checkSplitQUIC
	checkSplitQUIC = func(_, _ probe.Dialer, plain probe.Report, _ int, _ probe.Verdict) probe.Report {
		s.mu.Lock()
		tried = append(tried, plain.Domain)
		s.mu.Unlock()
		r := probe.Report{Domain: plain.Domain, Port: plain.Port, Proto: "quic", TestedIP: plain.TestedIP,
			Verdict: decoy[plain.Domain], Direct: pathOK, Tunnel: pathOK, Note: "QUIC decoy"}
		if r.Verdict != probe.CleanSplit {
			r.Direct, r.Reason = tcpFails, "timeout"
		}
		return r
	}
	t.Cleanup(func() { checkSplitQUIC = old })
	return s, &tried
}

func blockedQUIC(ip string) probe.Report {
	return probe.Report{Verdict: probe.BlockedQUIC, TestedIP: ip, Direct: tcpFails, Tunnel: pathOK}
}

// With the decoy on, a name going direct with the cut has its blocked QUIC
// tried through the decoy: getting through, its QUIC goes the same way;
// not, it is refused -- the name stays direct with the cut over TCP.
func TestCycleQUICDecoy(t *testing.T) {
	s, tried := quicScenario(t,
		map[string]probe.Verdict{"yt.example.org": probe.CleanSplit, "mu.example.org": probe.CleanSplit},
		map[string]probe.Verdict{"yt.example.org": probe.CleanSplit, "mu.example.org": probe.BlockedQUIC})
	for _, d := range []string{"yt.example.org", "mu.example.org"} {
		s.see(tunnelled(d, 443), quic(d))
		s.script(d+" tcp/443", blockedTLS("192.0.2.20"))
		s.script(d+" quic/443", blockedQUIC("192.0.2.20"))
	}
	s.cycle()
	slices.Sort(*tried)
	if !slices.Equal(*tried, []string{"mu.example.org", "yt.example.org"}) {
		t.Errorf("decoy tried for %v", *tried)
	}
	for d, noQUIC := range map[string]bool{"yt.example.org": false, "mu.example.org": true} {
		e := s.entry(d)
		if e == nil || e.Verdict != probe.CleanSplit || e.NoQUIC != noQUIC {
			t.Errorf("%s: %+v, want CLEAN_SPLIT with no QUIC %v", d, e, noQUIC)
		}
	}
	if got := listRules(s.cfg.SplitListPath); !slices.Equal(got, []string{"mu.example.org", "yt.example.org"}) {
		t.Errorf("cut list %v", got)
	}
	if got := listRules(s.cfg.NoQUICListPath); !slices.Equal(got, []string{"mu.example.org"}) {
		t.Errorf("QUIC refused for %v", got)
	}
}

// A name clean over TCP whose QUIC alone is blocked: through the decoy it
// gets through, and the name goes direct through the cut's outbound
// instead of to the tunnel. Not getting through, it stays BLOCKED_QUIC.
func TestCycleQUICDecoyAlone(t *testing.T) {
	s, _ := quicScenario(t, nil,
		map[string]probe.Verdict{"q.example.org": probe.CleanSplit, "b.example.org": probe.BlockedQUIC})
	for _, d := range []string{"q.example.org", "b.example.org"} {
		s.see(tunnelled(d, 443), quic(d))
		s.script(d+" tcp/443", probe.Report{Verdict: probe.Clean, TestedIP: "192.0.2.21", Direct: pathOK, Tunnel: pathOK})
		s.script(d+" quic/443", blockedQUIC("192.0.2.21"))
	}
	s.cycle()
	if e := s.entry("q.example.org"); e == nil || e.Verdict != probe.CleanSplit || e.NoQUIC {
		t.Errorf("q.example.org: %+v", e)
	}
	if e := s.entry("b.example.org"); e == nil || e.Verdict != probe.BlockedQUIC {
		t.Errorf("b.example.org: %+v", e)
	}
}

// The decoy switched off: QUIC is not tried through it, and QUIC to every
// name of the cut's is refused -- direct-split carries the decoy always,
// only that list keeps their QUIC from it.
func TestCycleQUICDecoyOff(t *testing.T) {
	s, tried := quicScenario(t, map[string]probe.Verdict{"yt.example.org": probe.CleanSplit},
		map[string]probe.Verdict{"yt.example.org": probe.CleanSplit})
	s.cfg.QUICFake = false
	s.see(tunnelled("yt.example.org", 443), quic("yt.example.org"))
	s.script("yt.example.org tcp/443", blockedTLS("192.0.2.22"))
	s.script("yt.example.org quic/443", blockedQUIC("192.0.2.22"))
	s.cycle()
	if len(*tried) != 0 {
		t.Errorf("decoy tried for %v", *tried)
	}
	if e := s.entry("yt.example.org"); e == nil || e.Verdict != probe.CleanSplit {
		t.Fatalf("verdict %+v", e)
	}
	if got := listRules(s.cfg.NoQUICListPath); !slices.Equal(got, []string{"yt.example.org"}) {
		t.Errorf("QUIC refused list %v", got)
	}
}

// The mirror of the case above: QUIC gets through with the decoy, TCP is
// blocked even with the cut (rr14---sn-n8v7kn7d.googlevideo.com, 08.10). The
// browser speaks QUIC to it: the name goes direct with the cut, its TCP on
// 443 refused -- not BLOCKED_DPI, held in the tunnel by its TCP. That TCP's
// fall is the refused one, not a dead direct path. Without the decoy it has
// no way direct and leaves the cut's list.
func TestCycleQUICOnly(t *testing.T) {
	s, _ := quicScenario(t,
		map[string]probe.Verdict{"rr14.example.org": probe.BlockedTLS, "dead.example.org": probe.BlockedTLS},
		map[string]probe.Verdict{"rr14.example.org": probe.CleanSplit, "dead.example.org": probe.BlockedQUIC})
	s.cfg.NoTCPProvider = NoTCPProvider
	s.cfg.NoTCPListPath = filepath.Join(filepath.Dir(s.cfg.ListPath), "direct-split-notcp.txt")
	for _, d := range []string{"rr14.example.org", "dead.example.org"} {
		s.see(tunnelled(d, 443), quic(d))
		s.script(d+" tcp/443", blockedTLS("192.0.2.30"))
		s.script(d+" quic/443", blockedQUIC("192.0.2.30"))
	}
	s.cycle()
	e := s.entry("rr14.example.org")
	if e == nil || e.Verdict != probe.CleanSplit || !e.NoTCP || e.NoQUIC {
		t.Fatalf("QUIC only: %+v", e)
	}
	if d := s.entry("dead.example.org"); d == nil || d.Verdict != probe.BlockedDPI || d.NoTCP {
		t.Fatalf("neither way: %+v", d)
	}
	if got := listRules(s.cfg.SplitListPath); !slices.Equal(got, []string{"rr14.example.org"}) {
		t.Fatalf("cut list %v", got)
	}
	if got := listRules(s.cfg.NoTCPListPath); !slices.Equal(got, []string{"rr14.example.org"}) {
		t.Fatalf("TCP refused for %v", got)
	}
	if got := listRules(s.cfg.NoQUICListPath); len(got) != 0 {
		t.Fatalf("QUIC refused for %v", got)
	}

	s.cfg.QUICFake = false
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := concat(listRules(s.cfg.SplitListPath), listRules(s.cfg.NoTCPListPath)); len(got) != 0 {
		t.Fatalf("the decoy off, still direct: %v", got)
	}
}
