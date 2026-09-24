package ctl

import (
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"dpiswitch/internal/probe"
)

// Subdomain families.
//
// Services like speedtest.ru spread traffic over a pool of hosts (*.qms.ru)
// and pick new ones every time. Each new host first goes into the tunnel and
// waits to be checked -- and a speed test is shorter than the check. If a
// domain has accumulated several clean subdomains and no blocked ones, the
// whole domain behaves the same, and it is reasonable to send new hosts
// direct right away.
//
// Safety net: family hosts sent direct without a check are caught by
// suspectDirect (connection open, no data) -- the host is then checked, and
// the first bad verdict removes the whole family.
//
// The "domain" boundary follows the public suffix list including private
// suffixes (github.io, cloudfront.net, appspot.com): otherwise unrelated
// sites on shared hosting would merge into one family.

// minFamily: how many clean subdomains are needed to judge the domain
const minFamily = 3

type family struct {
	Domain string `json:"domain"`
	Clean  int    `json:"clean"`
}

// badForFamily: verdicts showing the domain is NOT uniform.
// SLOWER counts: some hosts are worse direct, so generalising is unsafe.
// INCONCLUSIVE counts only when the host failed direct: it proves no
// blocking, but a family would send that host direct all the same -- past
// the very check that took its CLEAN away.
func badForFamily(e *entry) bool {
	switch e.Verdict {
	case probe.Clean:
		return false
	case probe.Inconcl:
		return e.DirectDown
	}
	return true
}

func familyOf(dom string) string {
	if _, ok := probe.AddrKey(dom); ok {
		return "" // "@91.204.108.4" must not make "108.4" a family
	}
	f, err := publicsuffix.EffectiveTLDPlusOne(dom)
	if err != nil {
		return ""
	}
	return f
}

// families: domains whose subdomains may go direct as a whole
func (s *state) families(id string) []family {
	s.mu.Lock()
	defer s.mu.Unlock()
	clean := map[string]int{}
	bad := map[string]bool{}
	now := time.Now()
	for dom, e := range s.Networks[id] {
		f := familyOf(dom)
		if f == "" {
			continue
		}
		switch {
		case badForFamily(e):
			bad[f] = true
		case e.Verdict == probe.Clean && now.Before(e.ExpiresAt):
			// an expired CLEAN is out of the list itself; counting it kept
			// the family -- and so the host -- direct past its term
			clean[f]++
		}
	}
	var out []family
	for f, n := range clean {
		if n >= minFamily && !bad[f] {
			out = append(out, family{Domain: f, Clean: n})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

// directRules: contents of the direct list -- verified domains and,
// if enabled, families written as "+.domain"
func directRules(cfg Config, st *state, id string) (rules []string, fams []family) {
	rules = st.verified(id)
	if !cfg.Families {
		return rules, nil
	}
	fams = st.families(id)
	covered := map[string]bool{}
	for _, f := range fams {
		covered[f.Domain] = true
		rules = append(rules, "+."+f.Domain)
	}
	// hosts covered by a family are redundant in the list
	out := rules[:0]
	for _, r := range rules {
		if !strings.HasPrefix(r, "+.") && covered[familyOf(r)] {
			continue
		}
		out = append(out, r)
	}
	sort.Strings(out)
	return out, fams
}
