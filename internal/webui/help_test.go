package webui

import (
	"regexp"
	"strings"
	"testing"
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
