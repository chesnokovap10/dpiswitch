package ctl

import (
	"sync"
	"testing"

	"dpiswitch/internal/probe"
)

// v6Scenario: a scenario with IPv6 on in the settings; the verdict of each
// name's IPv6 node as given, none for a name not listed. It says which
// names had theirs checked.
func v6Scenario(t *testing.T, has bool, v6 map[string]probe.Verdict) (*scenario, func() []string) {
	s := newScenario(t)
	s.cfg.IPv6 = true
	var mu sync.Mutex
	var asked []string
	oldCheck, oldHas := checkProtoV6, directHasV6
	t.Cleanup(func() { checkProtoV6, directHasV6 = oldCheck, oldHas })
	directHasV6 = func() bool { return has }
	checkProtoV6 = func(_, _ probe.Dialer, dom string, port, _ int, udp bool, _ probe.Verdict) (probe.Report, bool) {
		mu.Lock()
		asked = append(asked, dom)
		mu.Unlock()
		v, ok := v6[dom]
		if !ok {
			return probe.Report{}, false
		}
		r := probe.Report{Domain: dom, Port: port, Proto: "tcp", TestedIP: "2001:db8::1", Verdict: v,
			Direct: pathOK, Tunnel: pathOK, Note: "IPv6 node"}
		if v != probe.Clean {
			r.Reason = "RST (reset) on the ClientHello"
		}
		return r, true
	}
	return s, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), asked...)
	}
}

// With IPv6 on and the direct path having it, a name's IPv6 node is checked
// beside its IPv4 one, and the worse of the two is the name's verdict: the
// core dials either. One clean on IPv4 and cut on IPv6 went direct, and broke
// whenever the IPv6 node answered first.
func TestCycleChecksIPv6Node(t *testing.T) {
	s, asked := v6Scenario(t, true, map[string]probe.Verdict{
		"both.example.org":  probe.Clean,
		"cut6.example.org":  probe.BlockedTLS,
		"slow6.example.org": probe.Slower,
	})
	for i, d := range []string{"both.example.org", "cut6.example.org", "slow6.example.org", "only4.example.org"} {
		s.see(tunnelled(d, 443))
		s.script(d+" tcp/443", clean("192.0.2."+string(rune('1'+i))))
	}
	s.cycle()
	if len(asked()) != 4 {
		t.Fatalf("IPv6 nodes asked after: %v, want all four names", asked())
	}
	for d, want := range map[string]probe.Verdict{
		"both.example.org":  probe.Clean,
		"only4.example.org": probe.Clean,      // no IPv6 node: IPv4's alone
		"slow6.example.org": probe.Clean,      // slower there is no block
		"cut6.example.org":  probe.BlockedTLS, // the IPv6 node's
	} {
		if e := s.entry(d); e == nil || e.Verdict != want {
			t.Errorf("%s: %+v, want %s", d, e, want)
		}
	}
	if e := s.entry("cut6.example.org"); e != nil && e.TestedIP != "2001:db8::1" {
		t.Errorf("the node kept for the name cut on IPv6 is %s", e.TestedIP)
	}
}

// No IPv6 on the direct path, or IPv6 off in the settings: no IPv6 node is
// checked -- the core's dial of one fails at once there, and IPv4 is taken.
func TestCycleNoIPv6NoCheck(t *testing.T) {
	s, asked := v6Scenario(t, false, map[string]probe.Verdict{"a.example.org": probe.BlockedTLS})
	s.see(tunnelled("a.example.org", 443))
	s.script("a.example.org tcp/443", clean("192.0.2.1"))
	s.cycle()
	if len(asked()) != 0 {
		t.Errorf("the direct path without IPv6: IPv6 nodes asked after %v", asked())
	}
	if e := s.entry("a.example.org"); e == nil || e.Verdict != probe.Clean {
		t.Errorf("a.example.org: %+v, want CLEAN", e)
	}

	s, asked = v6Scenario(t, true, map[string]probe.Verdict{"b.example.org": probe.BlockedTLS})
	s.cfg.IPv6 = false
	s.see(tunnelled("b.example.org", 443))
	s.script("b.example.org tcp/443", clean("192.0.2.2"))
	s.cycle()
	if len(asked()) != 0 {
		t.Errorf("IPv6 off in the settings: IPv6 nodes asked after %v", asked())
	}
}

// A name called clean before its IPv6 node was looked at -- by a version that
// did not, or while the direct path had no IPv6 -- is checked again at once,
// not when its week runs out; and once looked at, left until then.
func TestCycleRechecksCleanMadeWithoutIPv6(t *testing.T) {
	s, asked := v6Scenario(t, false, map[string]probe.Verdict{"old.example.org": probe.BlockedTLS})
	s.see(tunnelled("old.example.org", 443))
	s.script("old.example.org tcp/443", clean("192.0.2.1"))
	s.cycle()
	if e := s.entry("old.example.org"); e == nil || e.Verdict != probe.Clean || e.V6 {
		t.Fatalf("made with no IPv6 on the direct path: %+v, want CLEAN and V6 unset", e)
	}
	s.see()
	s.cycle()
	if s.wasProbed("old.example.org tcp/443") {
		t.Fatal("no IPv6 on the direct path still, and the name was checked again")
	}

	directHasV6 = func() bool { return true }
	s.cycle()
	if !s.wasProbed("old.example.org tcp/443") || len(asked()) != 1 {
		t.Fatalf("the direct path has IPv6 now: probed %v, IPv6 nodes asked after %v", s.probed, asked())
	}
	if e := s.entry("old.example.org"); e == nil || e.Verdict != probe.BlockedTLS || !e.V6 {
		t.Fatalf("after the check with IPv6: %+v, want BLOCKED_TLS and V6 set", e)
	}

	// a clean one is looked at once, and then waits for its term
	s.script("ok.example.org tcp/443", clean("192.0.2.2"))
	s.see(tunnelled("ok.example.org", 443))
	s.cycle()
	if e := s.entry("ok.example.org"); e == nil || e.Verdict != probe.Clean || !e.V6 {
		t.Fatalf("ok.example.org: %+v, want CLEAN and V6 set", e)
	}
	s.see()
	s.cycle()
	if s.wasProbed("ok.example.org tcp/443") {
		t.Error("a name whose IPv6 node was looked at is checked again before its term")
	}
}

// The names waiting for their IPv6 node come after the new ones: a cycle
// with no room left takes none of them.
func TestCycleNewNamesBeforeIPv6Rechecks(t *testing.T) {
	s, _ := v6Scenario(t, false, nil)
	s.cfg.PerCycle = 2
	for i, d := range []string{"a.example.org", "b.example.org"} {
		s.see(tunnelled(d, 443))
		s.script(d+" tcp/443", clean("192.0.2."+string(rune('1'+i))))
		s.cycle()
	}
	directHasV6 = func() bool { return true }
	s.script("new1.example.org tcp/443", clean("192.0.2.8"))
	s.script("new2.example.org tcp/443", clean("192.0.2.9"))
	s.see(tunnelled("new1.example.org", 443), tunnelled("new2.example.org", 443))
	s.cycle()
	if !s.wasProbed("new1.example.org tcp/443") || !s.wasProbed("new2.example.org tcp/443") || s.wasProbed("a.example.org tcp/443") {
		t.Fatalf("probed %v, want the two new names alone", s.probed)
	}
	s.see()
	s.cycle()
	if !s.wasProbed("a.example.org tcp/443") || !s.wasProbed("b.example.org tcp/443") {
		t.Errorf("the next cycle probed %v, want the two waiting for their IPv6 node", s.probed)
	}
}
