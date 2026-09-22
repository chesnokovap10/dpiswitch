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
