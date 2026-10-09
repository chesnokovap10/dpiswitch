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

// The family goes the tunnel's way until its CDN is known here, and on
// Beeline's 10 of 31 too; direct at 3 in 4 of its CDN names direct -- home's
// 139 of 141 -- its page and CDN together; a blocked page keeps it in the
// tunnel; once direct it keeps so down to 1 in 2.
func TestFamilyWay(t *testing.T) {
	s := familyScenario(t)
	s.put("music.youtube.com", probe.CleanSplit, "")
	s.shards(5, probe.CleanSplit, 0)
	syncList(s.cfg, s.api, s.st, "n", false)
	if got := listRules(s.cfg.FamilyTunnelPath); !slices.Contains(got, "+.googlevideo.com") || !slices.Contains(got, "+.youtube.com") {
		t.Fatalf("five CDN names checked: the tunnel's way, page and CDN: %v", got)
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
}
