package ctl

import (
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dpiswitch/internal/probe"
)

// inheritScenario: a scenario with the cut on and the inheritance lists in
// place, its network book in memory
func inheritScenario(t *testing.T) *scenario {
	s, _ := splitScenario(t, nil)
	dir := filepath.Dir(s.cfg.ListPath)
	s.cfg.InheritPath = filepath.Join(dir, "inherit.txt")
	s.cfg.InheritIPPath = filepath.Join(dir, "inherit-ip.txt")
	s.cfg.HoldPath = filepath.Join(dir, "hold.txt")
	s.cfg.RefusePath = filepath.Join(dir, "refuse.txt")
	s.cfg.book = loadASNBook(filepath.Join(dir, "asn-book.json"))
	return s
}

func (s *scenario) put(dom string, v probe.Verdict, ip string) {
	s.st.put("n", dom, &entry{Verdict: v, TestedIP: ip, ExpiresAt: time.Now().Add(time.Hour)})
}

// The case of 07.10: the player's page went direct with the cut, every new
// media host into the tunnel, and the service refused the tunnel's address.
// googlevideo.com is clearly direct here -- three of its four hosts -- so a
// host with no verdict goes the cut's way; the blocked one is held out.
func TestInheritByDomain(t *testing.T) {
	s := inheritScenario(t)
	s.put("rr1---a.googlevideo.com", probe.CleanSplit, "")
	s.put("rr2---b.googlevideo.com", probe.CleanSplit, "")
	s.put("rr7---c.googlevideo.com", probe.BlockedDPI, "")
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.InheritPath); len(got) != 0 {
		t.Fatalf("two direct of three lend nothing yet: %v", got)
	}
	s.put("rr3---d.googlevideo.com", probe.CleanSplit, "")
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.InheritPath); !slices.Equal(got, []string{"+.googlevideo.com"}) {
		t.Fatalf("inherit list %v", got)
	}
	if got := listRules(s.cfg.HoldPath); !slices.Equal(got, []string{"rr7---c.googlevideo.com"}) {
		t.Fatalf("held %v", got)
	}
	if s.reloads[InheritProvider] == 0 || s.reloads[HoldProvider] == 0 {
		t.Errorf("not reloaded: %v", s.reloads)
	}
	// one more blocked: three of five is less than three of four
	s.put("rr8---e.googlevideo.com", probe.BlockedDPI, "")
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.InheritPath); len(got) != 0 {
		t.Fatalf("three direct of five is not clearly direct: %v", got)
	}
}

// A domain that is a plain family already goes direct above all of this;
// INCONCLUSIVE says nothing unless the direct path failed; a CLEAN past
// its term counts neither way and is held out like a block.
func TestInheritCounts(t *testing.T) {
	s := inheritScenario(t)
	for _, d := range []string{"a.ex.com", "b.ex.com", "c.ex.com"} {
		s.put(d, probe.Clean, "")
	}
	for _, d := range []string{"a.cut.org", "b.cut.org", "c.cut.org"} {
		s.put(d, probe.CleanSplit, "")
	}
	s.put("d.cut.org", probe.Inconcl, "")
	s.st.put("n", "e.cut.org", &entry{Verdict: probe.Inconcl, DirectDown: true, ExpiresAt: time.Now().Add(time.Hour)})
	s.st.put("n", "old.cut.org", &entry{Verdict: probe.CleanSplit, ExpiresAt: time.Now().Add(-time.Minute)})
	// the tunnel did not answer, the direct side did: nothing against the
	// direct way, so it is not held
	s.st.put("n", "f.cut.org", &entry{Verdict: probe.Inconcl, ExpiresAt: time.Now().Add(time.Hour),
		Reason: "tunnel path unavailable: silent drop (no reply) on the ClientHello (carries the name/SNI)"})
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.InheritPath); !slices.Equal(got, []string{"+.cut.org"}) {
		t.Fatalf("inherit list %v: ex.com is a family already", got)
	}
	if got := listRules(s.cfg.HoldPath); !slices.Equal(got, []string{"d.cut.org", "e.cut.org", "old.cut.org"}) {
		t.Fatalf("held %v", got)
	}
}

// googlevideo.com and youtube.com share no domain, but one network owns
// both: a name of either, with no verdict, takes the way of that network's
// names -- by the address ranges it announces, looked up at RIPE.
func TestInheritByNetwork(t *testing.T) {
	s := inheritScenario(t)
	var mu sync.Mutex
	var asked []string
	oldInfo, oldPfx := ripeNetInfo, ripePrefixes
	t.Cleanup(func() { ripeNetInfo, ripePrefixes = oldInfo, oldPfx })
	ripeNetInfo = func(_ *http.Client, ip string) (string, string, error) {
		mu.Lock()
		asked = append(asked, ip)
		mu.Unlock()
		switch ip {
		case "74.125.1.1", "74.125.1.2":
			return "AS15169", "74.125.0.0/16", nil
		case "172.253.1.1":
			return "AS15169", "172.253.0.0/16", nil
		}
		return "", "", errors.New("unknown")
	}
	ripePrefixes = func(_ *http.Client, asn string) ([]string, error) {
		return []string{"74.125.0.0/16", "172.253.0.0/16", "2a00:1450::/32"}, nil
	}
	s.put("music.youtube.com", probe.CleanSplit, "172.253.1.1")
	s.put("rr1---a.googlevideo.com", probe.CleanSplit, "74.125.1.1")
	s.put("rr7---c.googlevideo.com", probe.BlockedDPI, "74.125.1.1")

	// the nodes' networks, then the ranges of the one that lends its way;
	// a node turning up later in a prefix known by then is not asked about
	for i := 0; i < 3; i++ {
		if i == 1 {
			s.put("fonts.gstatic.com", probe.Clean, "74.125.1.2")
		}
		s.cfg.book.round(s.cfg.DirectAddr, s.st.unownedNodes("n", s.cfg.book), func() {})
		for s.cfg.book.busy.Load() {
			time.Sleep(time.Millisecond)
		}
		syncList(s.cfg, s.api, s.st, "n", false)
	}
	if slices.Contains(asked, "74.125.1.2") {
		t.Errorf("a node in a known prefix looked up again: %v", asked)
	}
	if got := listRules(s.cfg.InheritIPPath); !slices.Equal(got, []string{"172.253.0.0/16", "2a00:1450::/32", "74.125.0.0/16"}) {
		t.Fatalf("inherit-ip %v", got)
	}
	// and the book is kept for the next start
	b := loadASNBook(s.cfg.book.path)
	if b.asnOf("74.125.9.9") != "AS15169" {
		t.Fatalf("book not saved: %+v", b)
	}
	if r, ok := b.ranges("AS15169"); !ok || len(r) != 3 {
		t.Fatalf("ranges not saved: %v %v", r, ok)
	}
}

// Inheritance is On's: observe only and tunnel only empty the lists, and
// so does the cut or families switched off.
func TestInheritOnOnly(t *testing.T) {
	s := inheritScenario(t)
	for _, d := range []string{"a.cut.org", "b.cut.org", "c.cut.org"} {
		s.put(d, probe.CleanSplit, "")
	}
	s.put("x.cut.org", probe.BlockedDPI, "")
	syncList(s.cfg, s.api, s.st, "n", false)
	if len(listRules(s.cfg.InheritPath)) == 0 {
		t.Fatal("nothing lent in On")
	}
	for _, off := range []func(*Config){
		func(c *Config) { c.Split = false },
		func(c *Config) { c.Families = false },
		func(c *Config) { c.alone = true },
	} {
		cfg := s.cfg
		off(&cfg)
		syncList(cfg, s.api, s.st, "n", false)
		if got := concat(listRules(cfg.InheritPath), listRules(cfg.HoldPath)); len(got) != 0 {
			t.Fatalf("left %v", got)
		}
		syncList(s.cfg, s.api, s.st, "n", false)
	}
	for _, m := range []string{ModeObserve, ModeTunnel} {
		cfg := s.cfg
		cfg.mode = new(atomic.Value)
		cfg.setMode(m)
		syncList(cfg, s.api, s.st, "n", false)
		if got := concat(listRules(cfg.InheritPath), listRules(cfg.HoldPath)); len(got) != 0 {
			t.Fatalf("%s left %v", m, got)
		}
		syncList(s.cfg, s.api, s.st, "n", false)
	}
}

// A name with no verdict that inheritance sent direct is a candidate like
// a family's -- by domain or by network -- and, open with nothing come in,
// a suspect.
func TestInheritedIsChecked(t *testing.T) {
	s := inheritScenario(t)
	byDom := connection{ID: "1", Rule: "RuleSet", RulePayload: InheritProvider, Chains: []string{SplitOutbound}}
	byDom.Metadata.Host, byDom.Metadata.Network, byDom.Metadata.DestinationPort = "rr9---z.googlevideo.com", "tcp", "443"
	byNet := connection{ID: "2", Rule: "AND", RulePayload: "((DomainRegex,.+) && (RuleSet,inherit-ip))", Chains: []string{SplitOutbound}}
	byNet.Metadata.Host, byNet.Metadata.Network, byNet.Metadata.DestinationPort = "redirector.example.com", "udp", "443"
	if !byDom.inherited() || !byNet.inherited() {
		t.Fatal("not recognised")
	}
	s.see(byDom, byNet)
	_, order := s.w.drain()
	if !slices.Equal(order, []string{"rr9---z.googlevideo.com", "redirector.example.com"}) {
		t.Fatalf("candidates %v", order)
	}
	byDom.Start = time.Now().Add(-time.Minute).Format(time.RFC3339)
	if got := suspectDirect(s.cfg, s.st, "n", []connection{byDom}); !slices.Equal(got, []string{"rr9---z.googlevideo.com"}) {
		t.Fatalf("suspects %v", got)
	}
}
