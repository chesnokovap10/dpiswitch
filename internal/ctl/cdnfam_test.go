package ctl

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"dpiswitch/internal/probe"
)

func sans(t *testing.T, file string) []string {
	raw, err := os.ReadFile(filepath.Join("testdata", file))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(raw))
}

// The certificates of 09.10: googlevideo.com's names zones of YouTube's,
// Drive's, Mail's -- "*.c.youtube.com" -- and not those domains themselves:
// they are its clients. The page's, "*.google.com", names youtube.com bare:
// a page's certificate, no client in it, so google.com claims no family.
func TestClientZones(t *testing.T) {
	f := clientZones("googlevideo.com", sans(t, "san-googlevideo.txt"))
	for _, p := range []string{"youtube.com", "drive.google.com", "mail.google.com"} {
		if !slices.Contains(f.Pages, p) {
			t.Errorf("googlevideo.com serves %s: pages %v", p, f.Pages)
		}
	}
	if slices.Contains(f.Pages, "google.com") || slices.Contains(f.Pages, "gvt1.com") {
		t.Errorf("pages %v: google.com is not served whole, gvt1.com is the CDN's own", f.Pages)
	}
	for name, want := range map[string][2]bool{
		"rr5---sn-u15hn5-50.googlevideo.com":   {true, false},
		"rr1---sn-4g5e6nss.c.drive.google.com": {true, false},
		"music.youtube.com":                    {false, true},
		"www.youtube.com":                      {false, true},
		"www.google.com":                       {false, false},
		"i.ytimg.com":                          {false, false},
	} {
		if c, p := f.cdnOf(name); c != want[0] || p != want[1] {
			t.Errorf("%s: cdn %v page %v, want %v", name, c, p, want)
		}
	}
	if g := clientZones("google.com", sans(t, "san-google.txt")); len(g.Pages) != 0 {
		t.Errorf("google.com's certificate is a page's: pages %v", g.Pages)
	}
	if r := f.rules(); slices.Contains(r, "+.gvt1.com") {
		t.Errorf("the CDN's own domains are left out: %v", r)
	}
	// another host of google.com showed a zone of android.com: still a
	// page's domain, googlevideo.com serves its zones
	b := loadCDNBook(filepath.Join(t.TempDir(), "b.json"))
	b.CDNs["googlevideo.com"] = &cdnEntry{cdnFamily: f}
	b.CDNs["google.com"] = &cdnEntry{cdnFamily: cdnFamily{CDN: "google.com", Bases: []string{"partner.android.com"}, Pages: []string{"android.com"}}}
	if got := b.families(); len(got) != 1 || got[0].CDN != "googlevideo.com" {
		t.Errorf("families %v", got)
	}
}

func familyScenario(t *testing.T) *scenario {
	s := inheritScenario(t)
	dir := filepath.Dir(s.cfg.ListPath)
	s.cfg.FamilyDirectPath = filepath.Join(dir, "family-direct.txt")
	s.cfg.FamilyTunnelPath = filepath.Join(dir, "family-tunnel.txt")
	s.cfg.cdns = loadCDNBook(filepath.Join(dir, "cdn-book.json"))
	e := &cdnEntry{At: time.Now()}
	e.cdnFamily = clientZones("googlevideo.com", sans(t, "san-googlevideo.txt"))
	s.cfg.cdns.CDNs["googlevideo.com"] = e
	return s
}

func (s *scenario) shards(n int, v probe.Verdict, from int) {
	for i := range n {
		s.put(fmt.Sprintf("rr%d---sn-x.googlevideo.com", from+i), v, "")
	}
}

// The family takes no list until its CDN is known here -- its names go by
// their own verdicts -- and goes the tunnel's way at Beeline's 10 of 31; direct at 3 in 4 of its CDN names direct -- home's
// 139 of 141 -- its page and CDN together; a blocked page keeps it in the
// tunnel; once direct it keeps so down to 1 in 2.
func TestFamilyWay(t *testing.T) {
	s := familyScenario(t)
	s.put("music.youtube.com", probe.CleanSplit, "")
	s.shards(5, probe.CleanSplit, 0)
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := concat(listRules(s.cfg.FamilyTunnelPath), listRules(s.cfg.FamilyDirectPath)); len(got) != 0 {
		t.Fatalf("five CDN names checked: undecided, no list: %v", got)
	}
	// the page goes its own way: clean with the cut, the cut's
	s.cfg.SplitListPath = filepath.Join(filepath.Dir(s.cfg.ListPath), "direct-split-verified.txt")
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.SplitListPath); !slices.Contains(got, "music.youtube.com") {
		t.Fatalf("undecided: the page by its own CLEAN_SPLIT, cut: %v", got)
	}
	s.shards(5, probe.CleanSplit, 5)
	s.shards(21, probe.BlockedDPI, 100)
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.FamilyTunnelPath); !slices.Contains(got, "+.googlevideo.com") {
		t.Fatalf("10 of 31 direct: the tunnel: %v", got)
	}
	// 60 of 81: under 3 in 4, still the tunnel
	s.shards(50, probe.CleanSplit, 10)
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.FamilyTunnelPath); !slices.Contains(got, "+.googlevideo.com") {
		t.Fatalf("60 of 81: the tunnel: %v", got)
	}
	// the blocked ones checked again, clean with the cut: 81 of 81
	s.shards(21, probe.CleanSplit, 100)
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.FamilyDirectPath); !slices.Contains(got, "+.googlevideo.com") || !slices.Contains(got, "+.c.youtube.com") || !slices.Contains(got, "+.youtube.com") {
		t.Fatalf("81 of 81 direct: the family goes direct: %v", got)
	}
	if got := listRules(s.cfg.FamilyTunnelPath); len(got) != 0 {
		t.Fatalf("tunnel list %v", got)
	}
	if s.reloads[FamilyDirectProvider] == 0 || s.reloads[FamilyTunnelProvider] == 0 {
		t.Errorf("not reloaded: %v", s.reloads)
	}
	// 81 of 141: under 3 in 4, over 1 in 2 -- direct it stays
	s.shards(60, probe.BlockedDPI, 200)
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.FamilyDirectPath); !slices.Contains(got, "+.googlevideo.com") {
		t.Fatalf("81 of 141 keeps a direct family direct: %v", got)
	}
	// 81 of 171: under 1 in 2 -- back to the tunnel
	s.shards(30, probe.BlockedDPI, 300)
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.FamilyTunnelPath); !slices.Contains(got, "+.googlevideo.com") {
		t.Fatalf("81 of 171: the tunnel: %v", got)
	}
	// 101 of 171: over 1 in 2, but from the tunnel 3 in 4 is wanted
	s.shards(20, probe.CleanSplit, 300)
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.FamilyTunnelPath); !slices.Contains(got, "+.googlevideo.com") {
		t.Fatalf("101 of 171, from the tunnel: stays there: %v", got)
	}
}

func TestFamilyBlockedPage(t *testing.T) {
	s := familyScenario(t)
	s.shards(20, probe.CleanSplit, 0)
	s.put("www.youtube.com", probe.CleanSplit, "")
	s.put("music.youtube.com", probe.BlockedDPI, "")
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.FamilyTunnelPath); !slices.Contains(got, "+.googlevideo.com") {
		t.Fatalf("a blocked page takes its CDN with it into the tunnel: %v", got)
	}
	s.put("music.youtube.com", probe.CleanSplit, "")
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.FamilyDirectPath); !slices.Contains(got, "+.googlevideo.com") {
		t.Fatalf("the page clean with the cut: direct: %v", got)
	}
	// blocked by address is the one node probed: the name has others, and
	// the family stays
	s.put("music.youtube.com", probe.BlockedTCP, "")
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.FamilyDirectPath); !slices.Contains(got, "+.googlevideo.com") {
		t.Fatalf("a page blocked by address on a node took its family into the tunnel: %v", got)
	}
	// answered direct with another's certificate, the page goes no more
	// direct than a blocked one
	s.put("music.youtube.com", probe.MITM, "")
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.FamilyDirectPath); slices.Contains(got, "+.googlevideo.com") {
		t.Fatalf("a page with a foreign certificate: its family direct: %v", got)
	}
}

// The cut switched off closes what its outbound carries whatever rule sent
// it there -- a family's and inheritance's too; families switched off, what
// their lists routed.
func TestCloseLentWays(t *testing.T) {
	s := familyScenario(t)
	byRule := func(c connection, provider string) connection {
		c.RulePayload = provider
		return c
	}
	s.mu.Lock()
	s.conns = []connection{
		byRule(famConn("cut", "a.example", SplitOutbound), s.cfg.SplitProvider),
		byRule(famConn("family", "rr1---sn-x.googlevideo.com", SplitOutbound), FamilyDirectProvider),
		byRule(famConn("famtunnel", "rr2---sn-x.googlevideo.com", "awg1", "tunnel-rest"), FamilyTunnelProvider),
		byRule(famConn("plain", "b.example", "DIRECT"), s.cfg.Provider),
	}
	s.mu.Unlock()
	if n := closeOnCut(s.api, ""); n != 2 {
		t.Errorf("the cut off: %d closed", n)
	}
	s.mu.Lock()
	got := slices.Clone(s.closed)
	s.closed = nil
	s.mu.Unlock()
	if !slices.Equal(got, []string{"cut", "family"}) {
		t.Errorf("the cut off: closed %v", got)
	}
	closeFamilies(s.api)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !slices.Equal(s.closed, []string{"family", "famtunnel"}) {
		t.Errorf("families off: closed %v", s.closed)
	}
}

func famConn(id, host string, chains ...string) connection {
	var c connection
	c.ID, c.Chains, c.Rule = id, chains, "RuleSet"
	c.Metadata.Host = host
	return c
}

// The page of 09.10 opened on the cut's way the moment the network changed
// back to Beeline, and stayed there while its new CDN hosts went through the
// tunnel. A family changing its way closes what goes the old one.
func TestFamilyClosesOldWay(t *testing.T) {
	s := familyScenario(t)
	s.put("music.youtube.com", probe.CleanSplit, "")
	s.shards(20, probe.CleanSplit, 0)
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.FamilyDirectPath); !slices.Contains(got, "+.googlevideo.com") {
		t.Fatalf("direct: %v", got)
	}
	s.mu.Lock()
	s.conns = []connection{
		famConn("page", "music.youtube.com", SplitOutbound),
		famConn("cdn", "rr1---sn-x.googlevideo.com", "awg1", "tunnel-rest"),
		famConn("other", "www.google.com", SplitOutbound),
	}
	s.mu.Unlock()
	s.put("music.youtube.com", probe.BlockedDPI, "")
	syncList(s.cfg, s.api, s.st, "n", false)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !slices.Equal(s.closed, []string{"page"}) {
		t.Fatalf("closed %v: the page on the cut's way, nothing else", s.closed)
	}
}

// Refused are the CDN hosts of a family going direct the cut does not get
// through -- through the tunnel the service refuses them, refused the
// player takes another. Nothing else: a family in the tunnel refuses
// nothing, and a site outside any family goes through the tunnel, its
// domain direct or not.
func TestFamilyRefuse(t *testing.T) {
	s := familyScenario(t)
	s.put("music.youtube.com", probe.CleanSplit, "")
	s.shards(30, probe.CleanSplit, 0)
	s.put("rr7---sn-x.googlevideo.com", probe.BlockedDPI, "")
	s.put("rr8---sn-x.googlevideo.com", probe.BlockedTCP, "")
	s.put("rr9---sn-x.googlevideo.com", probe.BlockedTLS, "")
	s.st.put("n", "rr6---old.googlevideo.com", &entry{Verdict: probe.BlockedDPI, ExpiresAt: time.Now().Add(-time.Minute)})
	for i := range 12 {
		s.put(fmt.Sprintf("h%d.other.net", i), probe.CleanSplit, "")
	}
	s.put("x.other.net", probe.BlockedDPI, "")
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.RefusePath); !slices.Equal(got, []string{"rr7---sn-x.googlevideo.com", "rr8---sn-x.googlevideo.com"}) {
		t.Fatalf("refused %v", got)
	}
	if got := listRules(s.cfg.HoldPath); !slices.Contains(got, "x.other.net") {
		t.Fatalf("a site outside the families is held for the tunnel: %v", got)
	}
	// the page blocked: the family to the tunnel, nothing refused
	s.put("music.youtube.com", probe.BlockedDPI, "")
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.RefusePath); len(got) != 0 {
		t.Fatalf("a family in the tunnel refuses nothing: %v", got)
	}
}

// A CDN whose pages nothing here opened is no family: browserleaks.org's
// DNS test hosts, its certificate naming zones of browserleaks.net.
func TestFamilyNeedsAPage(t *testing.T) {
	s := familyScenario(t)
	e := &cdnEntry{At: time.Now()}
	e.cdnFamily = clientZones("browserleaks.org", []string{"browserleaks.org", "*.browserleaks.org", "*.dns4.browserleaks.net", "*.dns6.browserleaks.net"})
	s.cfg.cdns.CDNs["browserleaks.org"] = e
	for i := range 12 {
		s.put(fmt.Sprintf("x%d.dns4.browserleaks.org", i), probe.Clean, "")
	}
	s.shards(12, probe.CleanSplit, 0)
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := concat(listRules(s.cfg.FamilyDirectPath), listRules(s.cfg.FamilyTunnelPath)); len(got) != 0 {
		t.Fatalf("no page opened, no family: %v", got)
	}
	s.put("www.youtube.com", probe.CleanSplit, "")
	syncList(s.cfg, s.api, s.st, "n", false)
	got := listRules(s.cfg.FamilyDirectPath)
	if !slices.Contains(got, "+.googlevideo.com") || slices.Contains(got, "+.browserleaks.org") {
		t.Fatalf("YouTube's page opened: its family alone: %v", got)
	}
}

// A new CDN host of a family going direct is a way lent, like inheritance:
// the watcher takes it for a check, and one that brings nothing is checked
// at once. Left out, a blocked one was never checked nor refused.
func TestFamilyDirectIsLent(t *testing.T) {
	c := famConn("x", "rr1---sn-new.googlevideo.com", SplitOutbound)
	c.RulePayload = FamilyDirectProvider
	if !c.inherited() {
		t.Fatal("a family's direct way is a lent one")
	}
}

// Dropping a family's blocked CDN names from the UI does not take it out
// of the tunnel: unchecked, they have not passed (09.10, Beeline: 38
// dropped, 32 direct of 40 left, the family went direct onto them).
func TestFamilyDroppedNotPassed(t *testing.T) {
	s := familyScenario(t)
	s.put("music.youtube.com", probe.CleanSplit, "")
	s.shards(32, probe.CleanSplit, 0)
	s.shards(30, probe.BlockedDPI, 100)
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.FamilyTunnelPath); !slices.Contains(got, "+.googlevideo.com") {
		t.Fatalf("32 of 62: the tunnel: %v", got)
	}
	var drop []string
	for i := range 30 {
		drop = append(drop, fmt.Sprintf("rr%d---sn-x.googlevideo.com", 100+i))
	}
	s.st.forgetVerdicts("n", drop)
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.FamilyTunnelPath); !slices.Contains(got, "+.googlevideo.com") {
		t.Fatalf("dropped, not checked: still the tunnel: %v", got)
	}
	// checked again, clean with the cut: they passed now
	s.shards(30, probe.CleanSplit, 100)
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.FamilyDirectPath); !slices.Contains(got, "+.googlevideo.com") {
		t.Fatalf("62 of 62 checked direct: direct: %v", got)
	}
}
