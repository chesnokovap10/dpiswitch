package ctl

import (
	"slices"
	"testing"
	"time"

	"dpiswitch/internal/probe"
)

// A CDN host of a family going direct, with no verdict, gets a quick pass;
// dead both direct ways it is refused at once, until its verdict is filed
// or the mark runs out -- and a live verdict of its own decides over it.
func TestQuickRefuse(t *testing.T) {
	s := familyScenario(t)
	s.put("music.youtube.com", probe.CleanSplit, "")
	s.shards(30, probe.CleanSplit, 0)
	syncList(s.cfg, s.api, s.st, "n", false)
	if !slices.Contains(listRules(s.cfg.FamilyDirectPath), "+.googlevideo.com") {
		t.Fatal("the family is not direct")
	}
	tcp443 := []endpoint{{port: 443}}
	const dead = "rr50---sn-new.googlevideo.com"
	for dom, want := range map[string]bool{
		dead:                         true,
		"rr1---sn-x.googlevideo.com": false, // has a live verdict
		"music.youtube.com":          false, // a page, not a CDN host
		"x.other.net":                false, // in no family
	} {
		if got := quickWanted(s.cfg, s.st, "n", dom, tcp443); got != want {
			t.Errorf("%s: quick pass %v, want %v", dom, got, want)
		}
	}
	if quickWanted(s.cfg, s.st, "n", dead, []endpoint{{udp: true, port: 443}}) {
		t.Error("a quick pass with no TCP 443 to try")
	}

	old := quickDead
	t.Cleanup(func() { quickDead = old })
	quickDead = func(_, _, _ probe.Dialer, dom string, _ time.Duration) (string, bool) {
		return "192.0.2.9", dom == dead
	}
	quickCheck(s.cfg, s.api, s.st, "n", "rr51---sn-alive.googlevideo.com", probe.Dialer{}, probe.Dialer{}, probe.Dialer{})
	quickCheck(s.cfg, s.api, s.st, "n", dead, probe.Dialer{}, probe.Dialer{}, probe.Dialer{})
	if got := listRules(s.cfg.RefusePath); !slices.Equal(got, []string{dead}) {
		t.Fatalf("refused %v, want the dead host alone", got)
	}
	// its verdict filed: that decides
	s.st.unquick("n", dead)
	s.put(dead, probe.CleanSplit, "")
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.RefusePath); len(got) != 0 {
		t.Fatalf("refused after its verdict: %v", got)
	}
	// a mark run out refuses nothing
	s.st.quickRefuse("n", "rr52---sn-new.googlevideo.com", time.Now().Add(-time.Second))
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.RefusePath); len(got) != 0 {
		t.Fatalf("refused past its term: %v", got)
	}
}
