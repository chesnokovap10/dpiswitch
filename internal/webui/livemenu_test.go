package webui

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
)

func liveAct(t *testing.T, s *Server, path string, form url.Values, hdr map[string]string) liveAnswer {
	t.Helper()
	w := do(t, s.Handler(), "POST", path, form, hdr)
	if w.Code != 200 {
		t.Fatalf("%s %v: %d %s", path, form, w.Code, w.Body.String())
	}
	var a liveAnswer
	if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil {
		t.Fatalf("%s: %v: %s", path, err, w.Body.String())
	}
	return a
}

// The menu sends a row's line to one list, and takes it out of the others:
// "Always via tunnel" stands above "Always direct", and a line left there
// would keep the site in the tunnel. The same twice is said, a line of no
// kind refused.
func TestLiveAdd(t *testing.T) {
	s, _ := testServer(t)
	add := func(to, entry string) liveAnswer {
		t.Helper()
		return liveAct(t, s, "/act/liveadd", url.Values{"to": {to}, "entry": {entry}}, nil)
	}
	list := func(name string) string { return strings.Join(readEntries(name), ",") }

	if a := add("tunnel", "+.example.com"); !a.OK || a.Msg != "Added to “Always via tunnel”: +.example.com" {
		t.Fatalf("to the tunnel: %+v", a)
	}
	if got := list(paths.TunnelList); got != "+.example.com" {
		t.Fatalf("the tunnel's list: %s", got)
	}
	a := add("direct", "+.example.com")
	if !a.OK || !strings.Contains(a.Msg, "taken out of «Always via tunnel»") {
		t.Fatalf("direct: %+v", a)
	}
	if list(paths.TunnelList) != "" || list(paths.DirectList) != "+.example.com" {
		t.Fatalf("moved: tunnel %q, direct %q", list(paths.TunnelList), list(paths.DirectList))
	}
	if a = add("direct", "+.EXAMPLE.com"); !a.OK || a.Msg != "“Always direct” has +.example.com already" {
		t.Fatalf("again: %+v", a)
	}
	if a = add("block", "Telegram.exe"); !a.OK || list(paths.BlockList) != "Telegram.exe" {
		t.Fatalf("a program forbidden: %+v, %s", a, list(paths.BlockList))
	}
	if a = add("awg2", "1.2.3.4"); !a.OK || list(paths.Awg2List) != "1.2.3.4" {
		t.Fatalf("an address to the second tunnel: %+v", a)
	}
	if a = add("direct", "bad host"); a.OK {
		t.Fatalf("a line of no kind: %+v", a)
	}
	if w := do(t, s.Handler(), "POST", "/act/liveadd", url.Values{"to": {"nope"}, "entry": {"a.example"}}, nil); w.Code != 400 {
		t.Fatalf("an unknown list: %d", w.Code)
	}
	ru := map[string]string{"Cookie": "lang=ru"}
	if a = liveAct(t, s, "/act/liveadd", url.Values{"to": {"awg2"}, "entry": {"1.2.3.4"}}, ru); a.Msg != "1.2.3.4 уже есть в «Второй туннель: свой список»" {
		t.Fatalf("in Russian: %q", a.Msg)
	}
}

// To a preset: the line joins its lines and leaves the user's lists. A line
// its rules take already is said; a preset switched off is said to route
// nothing.
func TestLiveAddPreset(t *testing.T) {
	s, _ := testServer(t)
	add := func(preset, entry string) liveAnswer {
		t.Helper()
		return liveAct(t, s, "/act/liveadd", url.Values{"to": {"preset"}, "preset": {preset}, "entry": {entry}}, nil)
	}
	liveAct(t, s, "/act/liveadd", url.Values{"to": {"direct"}, "entry": {"chat.example"}}, nil)
	a := add("ai", "chat.example")
	if !a.OK || !strings.Contains(a.Msg, "Added to “AI services”: chat.example") ||
		!strings.Contains(a.Msg, "taken out of «Always direct»") || !strings.Contains(a.Msg, "The preset is off") {
		t.Fatalf("to a preset: %+v", a)
	}
	ai, _ := findPreset(presets.Load(), "ai")
	if ai.Lines[len(ai.Lines)-1] != "chat.example" || len(readEntries(paths.DirectList)) != 0 {
		t.Fatalf("the preset's lines end %q, direct %v", ai.Lines[len(ai.Lines)-1], readEntries(paths.DirectList))
	}
	// the shipped list has claude.ai: its whole domain is the same rule
	if a = add("ai", "+.claude.ai"); !a.OK || !strings.Contains(a.Msg, "has +.claude.ai already") {
		t.Fatalf("a line it has: %+v", a)
	}
	do(t, s.Handler(), "POST", "/act/preset", url.Values{"field": {"ai"}, "value": {"1"}}, nil)
	if a = add("ai", "+.more.example"); !a.OK || strings.Contains(a.Msg, "is off") {
		t.Fatalf("to a preset switched on: %+v", a)
	}
	if a = add("nope", "x.example"); a.OK {
		t.Fatalf("a preset not there: %+v", a)
	}
}

// The presets for the menu: in the page's language, the ones switched on
// marked.
func TestLivePresets(t *testing.T) {
	s, _ := testServer(t)
	do(t, s.Handler(), "POST", "/act/preset", url.Values{"field": {"telegram"}, "value": {"1"}}, nil)
	w := do(t, s.Handler(), "GET", "/live/presets", nil, map[string]string{"Cookie": "lang=ru"})
	var got []struct {
		ID, Title string
		On        bool
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("%v: %s", err, w.Body.String())
	}
	if len(got) != 4 || got[2].ID != "ai" || got[2].Title != "ИИ-сервисы" || got[2].On || !got[1].On {
		t.Fatalf("presets: %+v", got)
	}
}

// File location shows the file the core named for the row -- not a path
// the page sends. A row without one, or a file gone, is said.
func TestLiveReveal(t *testing.T) {
	s, _ := testServer(t)
	s.Handler()
	var shown string
	old := liveReveal
	liveReveal = func(p string) error { shown = p; return nil }
	t.Cleanup(func() { liveReveal = old })
	file := filepath.Join(t.TempDir(), "app.exe")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	s.live.open["a"] = &liveRow{ID: "a", Path: file}
	s.live.closed = []*liveRow{{ID: "b", Path: filepath.Join(t.TempDir(), "gone.exe")}, {ID: "c"}}
	reveal := func(id string) liveAnswer {
		return liveAct(t, s, "/act/livereveal", url.Values{"id": {id}}, nil)
	}
	if a := reveal("a"); !a.OK || shown != file {
		t.Fatalf("shown %q: %+v", shown, a)
	}
	shown = ""
	for _, id := range []string{"b", "c", "x"} {
		if a := reveal(id); a.OK || shown != "" {
			t.Errorf("%s: %+v, shown %q", id, a, shown)
		}
	}
}
