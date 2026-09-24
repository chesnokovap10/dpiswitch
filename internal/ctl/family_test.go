package ctl

import (
	"testing"
	"time"

	"dpiswitch/internal/probe"
)

func TestFamilies(t *testing.T) {
	st := &state{Networks: map[string]map[string]*entry{}}
	put := func(dom string, v probe.Verdict) {
		st.put("n", dom, &entry{Verdict: v, ExpiresAt: time.Now().Add(time.Hour)})
	}
	has := func(f string) bool {
		for _, x := range st.families("n") {
			if x.Domain == f {
				return true
			}
		}
		return false
	}

	put("a.qms.ru", probe.Clean)
	put("b.qms.ru", probe.Clean)
	if has("qms.ru") {
		t.Fatal("two subdomains are not enough")
	}
	put("c.qms.ru", probe.Clean)
	put("d.qms.ru", probe.Inconcl) // says nothing about blocking
	if !has("qms.ru") {
		t.Fatal("three clean and no bad ones -- that is a family")
	}
	put("e.qms.ru", probe.Slower)
	if has("qms.ru") {
		t.Fatal("a SLOWER sibling -- must not generalise")
	}

	// shared hosting: github.io neighbours are unrelated sites
	for _, d := range []string{"x.github.io", "y.github.io", "z.github.io", "w.github.io"} {
		put(d, probe.Clean)
	}
	if has("github.io") {
		t.Fatal("github.io is a public suffix, it cannot be a family")
	}

	cfg := Config{Families: true}
	put("f.ex.com", probe.Clean)
	put("g.ex.com", probe.Clean)
	put("h.ex.com", probe.Clean)
	rules, _ := directRules(cfg, st, "n")
	for _, r := range rules {
		if r == "f.ex.com" {
			t.Fatal("a host covered by a family is duplicated in the list")
		}
	}
	found := false
	for _, r := range rules {
		found = found || r == "+.ex.com"
	}
	if !found {
		t.Fatalf("no +.ex.com in %v", rules)
	}
	cfg.Families = false
	if rules, _ := directRules(cfg, st, "n"); len(rules) == 0 || rules[0] == "+.ex.com" {
		t.Fatalf("disabled -- hosts only: %v", rules)
	}
}

// A family must not send direct what the verdicts themselves took off the
// list: an expired CLEAN, or a host that failed direct.
func TestFamilyHonoursExpiryAndDirectFailure(t *testing.T) {
	now := time.Now()
	live, gone := now.Add(time.Hour), now.Add(-time.Hour)
	fams := func(m map[string]*entry) []family {
		st := &state{Networks: map[string]map[string]*entry{"n": m}}
		return st.families("n")
	}

	// three CLEAN, one of them past its term: two are not a family
	if f := fams(map[string]*entry{
		"a.ex.com": {Verdict: probe.Clean, ExpiresAt: live},
		"b.ex.com": {Verdict: probe.Clean, ExpiresAt: live},
		"c.ex.com": {Verdict: probe.Clean, ExpiresAt: gone},
	}); len(f) != 0 {
		t.Errorf("an expired CLEAN counted: %v", f)
	}

	three := func(extra *entry) map[string]*entry {
		return map[string]*entry{
			"a.ex.com": {Verdict: probe.Clean, ExpiresAt: live},
			"b.ex.com": {Verdict: probe.Clean, ExpiresAt: live},
			"c.ex.com": {Verdict: probe.Clean, ExpiresAt: live},
			"d.ex.com": extra,
		}
	}
	// the tunnel failing says nothing: the host works direct
	if f := fams(three(&entry{Verdict: probe.Inconcl, ExpiresAt: live})); len(f) != 1 {
		t.Errorf("a tunnel-side INCONCLUSIVE broke the family: %v", f)
	}
	// failing on both paths: not blocking, but no reason to send it direct
	if f := fams(three(&entry{Verdict: probe.Inconcl, ExpiresAt: live, DirectDown: true})); len(f) != 0 {
		t.Errorf("a host failing direct kept the family: %v", f)
	}
}
