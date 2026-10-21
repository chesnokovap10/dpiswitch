package webui

import (
	"regexp"
	"strings"
	"testing"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
)

// A help link points at a part of a page, and that part blinks (see
// ui.js): every one of them, in both languages, names a part, and the part
// is on its page. A link to a page alone blinks nothing.
func TestHelpLinks(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	link := regexp.MustCompile(`href="/([a-z0-9]+)#([A-Za-z0-9_-]+)"`)
	anyLink := regexp.MustCompile(`href="(/[^"]*)"`)
	pages := map[string]string{}
	for _, l := range []string{"en", "ru"} {
		body := do(t, h, "GET", "/help", nil, map[string]string{"Cookie": "lang=" + l}).Body.String()
		// the help's own part of the page: the layout's menu links to pages
		if i := strings.Index(body, `class="help"`); i >= 0 {
			for _, m := range anyLink.FindAllStringSubmatch(body[i:], -1) {
				if !strings.Contains(m[1], "#") && !strings.HasPrefix(m[1], "/static/") && !strings.HasPrefix(m[1], "/act/") {
					t.Errorf("%s: a link to %s names no part to blink", l, m[1])
				}
			}
		} else {
			t.Fatalf("%s: the help's part not found", l)
		}
		links := link.FindAllStringSubmatch(body, -1)
		if len(links) < 10 {
			t.Fatalf("%s: only %d links found: the pattern no longer matches the help", l, len(links))
		}
		for _, m := range links {
			page, id := m[1], m[2]
			if _, ok := pages[page]; !ok {
				pages[page] = do(t, h, "GET", "/"+page, nil, nil).Body.String()
			}
			if !strings.Contains(pages[page], `id="`+id+`"`) {
				t.Errorf("%s: /%s#%s: no such part on the page", l, page, id)
			}
		}
	}
}

// A setting's "More" link goes to its part of the help, in both languages,
// and the QUIC decoy has a row of its own beside the ClientHello cut.
func TestSettingsHelpLinks(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	link := regexp.MustCompile(`href="/help#([A-Za-z0-9_-]+)"`)
	for _, l := range []string{"en", "ru"} {
		c := map[string]string{"Cookie": "lang=" + l}
		page := do(t, h, "GET", "/settings", nil, c).Body.String()
		help := do(t, h, "GET", "/help", nil, c).Body.String()
		links := link.FindAllStringSubmatch(page, -1)
		if len(links) < 8 {
			t.Fatalf("%s: only %d links to the help", l, len(links))
		}
		for _, m := range links {
			if !strings.Contains(help, `id="`+m[1]+`"`) {
				t.Errorf("%s: /help#%s: no such part of the help", l, m[1])
			}
		}
		for _, id := range []string{`id="split_hello"`, `id="quic_fake"`} {
			if !strings.Contains(page, id) {
				t.Errorf("%s: no %s row", l, id)
			}
		}
	}
}

// The settings are six groups -- five of the form's and DNS -- each opened on
// its title, all closed as the page comes; the header names the build's
// commit beside the version.
func TestSettingsGroups(t *testing.T) {
	s, _ := testServer(t)
	s.statusFn = func() status {
		return status{Installed: true, PathOK: true, ServiceRun: true, Version: "1.12.0", Commit: "15ff252",
			DataDir: paths.DataDir(), NetworkID: "AS1", Mode: ctl.ModeOn}
	}
	page := do(t, s.Handler(), "GET", "/settings", nil, nil).Body.String()
	groups := regexp.MustCompile(`<details class="grp"[^>]*>`).FindAllString(page, -1)
	if len(groups) != 6 {
		t.Fatalf("%d groups, want 6", len(groups))
	}
	for _, g := range groups {
		if strings.Contains(g, " open") {
			t.Errorf("open as the page comes: %s", g)
		}
	}
	if !strings.Contains(page, "<small>v1.12.0 #15ff252</small>") {
		t.Error("no commit beside the version in the header")
	}
}
