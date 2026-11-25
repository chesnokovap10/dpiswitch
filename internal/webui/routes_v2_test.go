package webui

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"dpiswitch/internal/paths"
)

func TestUnifiedRouteListAndNavigation(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	body := do(t, h, http.MethodGet, "/lists", nil, nil).Body.String()
	for _, id := range []string{`id="list-direct"`, `id="list-tunnel"`, `id="list-block"`, `id="presets"`} {
		if strings.Count(body, id) != 1 {
			t.Fatalf("%s count in lists page", id)
		}
	}
	routeBlock := body[strings.Index(body, `<div class="box" id="list-tunnel"`):]
	entry, route, kind := strings.Index(routeBlock, `name="entries"`), strings.Index(routeBlock, `class="entry-routes"`), strings.Index(routeBlock, `class="entry-types"`)
	if entry < 0 || route < entry || kind < route {
		t.Fatalf("columns are not entry | route | type")
	}
	for _, value := range []string{"awg1", "awg2", "awg1-awg2", "awg2-awg1", "awg1-awg2-direct", "awg2-awg1-direct"} {
		if !strings.Contains(body, `value="`+value+`"`) {
			t.Errorf("route %s missing", value)
		}
	}

	w := do(t, h, http.MethodPost, "/act/list", url.Values{
		"kind": {"tunnel"}, "entries": {"one.example\ntwo.example"},
		"routes": {"awg1\nawg2-awg1-direct"}, "op": {"save"},
	}, nil)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), `msg bad`) {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	if got := strings.Join(readEntries(paths.Tunnel1List), ","); got != "one.example" {
		t.Fatalf("awg1 list = %q", got)
	}
	if got := strings.Join(readEntries(paths.Awg2List), ","); got != "two.example" {
		t.Fatalf("reverse direct list = %q", got)
	}

	layout := do(t, h, http.MethodGet, "/overview", nil, nil).Body.String()
	last := -1
	for _, href := range []string{"/overview", "/lists", "/verdicts", "/logs", "/settings", "/help", "/live"} {
		at := strings.Index(layout, `href="`+href+`"`)
		if at <= last {
			t.Fatalf("navigation order at %s", href)
		}
		last = at
	}
	if strings.Contains(layout, `href="/awg2"`) {
		t.Fatal("second-tunnel navigation remains")
	}
}
