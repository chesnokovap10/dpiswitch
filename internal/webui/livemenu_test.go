package webui

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"dpiswitch/internal/ctl"
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

// A line sent to a list goes out of the lists that would route it before
// that one -- by a wider line as well: "+.example.com" in Always via tunnel
// kept api.example.com, sent direct, in the tunnel; "+.example.com" in
// Forbidden kept it refused; 10.0.0.0/8 kept 10.20.30.40. A list after it
// keeps a wider line -- it routes other names, and the line sent routes
// before it -- and loses the narrower ones.
func TestLiveAddOverlap(t *testing.T) {
	s, _ := testServer(t)
	write := func(name string, lines ...string) {
		t.Helper()
		if err := writeEntries(name, lines); err != nil {
			t.Fatal(err)
		}
	}
	list := func(name string) string { return strings.Join(readEntries(name), ",") }
	add := func(to, entry string) liveAnswer {
		t.Helper()
		return liveAct(t, s, "/act/liveadd", url.Values{"to": {to}, "entry": {entry}}, nil)
	}

	write(paths.TunnelList, "+.example.com", "other.example")
	write(paths.BlockList, "+.example.com")
	a := add("direct", "api.example.com")
	if !a.OK || list(paths.TunnelList) != "other.example" || list(paths.BlockList) != "" || list(paths.DirectList) != "api.example.com" {
		t.Fatalf("a wider line before: %+v; tunnel %q, forbidden %q, direct %q", a,
			list(paths.TunnelList), list(paths.BlockList), list(paths.DirectList))
	}
	if !strings.Contains(a.Msg, "«Always via tunnel»: +.example.com") || !strings.Contains(a.Msg, "«Forbidden»: +.example.com") {
		t.Fatalf("what was taken out is not said: %s", a.Msg)
	}

	write(paths.TunnelList, "10.0.0.0/8", "192.168.1.0/24")
	if a = add("direct", "10.20.30.40"); !a.OK || list(paths.TunnelList) != "192.168.1.0/24" {
		t.Fatalf("a network holding the address: %+v, tunnel %q", a, list(paths.TunnelList))
	}

	// a list after: its wider line stays, a narrower one goes
	write(paths.DirectList, "+.example.org", "a.api.example.org")
	write(paths.TunnelList)
	if a = add("tunnel", "+.api.example.org"); !a.OK || list(paths.DirectList) != "+.example.org" {
		t.Fatalf("a list after: %+v, direct %q", a, list(paths.DirectList))
	}

	// programs: the direct ones stand before the tunnel's; by its name a
	// program is every copy, by its path that copy
	write(paths.DirectList, `C:\Apps\chrome.exe`, `D:\Other\game.exe`)
	write(paths.TunnelList)
	if a = add("tunnel", "chrome.exe"); !a.OK || list(paths.DirectList) != `D:\Other\game.exe` {
		t.Fatalf("a copy of the program: %+v, direct %q", a, list(paths.DirectList))
	}
	write(paths.BlockList, "game.exe")
	if a = add("direct", `C:\Games\game.exe`); !a.OK || list(paths.BlockList) != "" {
		t.Fatalf("every copy forbidden: %+v, forbidden %q", a, list(paths.BlockList))
	}
	// a program's other copy routes other connections
	write(paths.BlockList, `E:\x\game.exe`)
	if a = add("direct", `C:\Games\game.exe`); list(paths.BlockList) != `E:\x\game.exe` {
		t.Fatalf("another copy: %+v, forbidden %q", a, list(paths.BlockList))
	}
	// a site's line leaves a program's alone, and the other way round
	write(paths.TunnelList, "chrome.exe", "+.example.net")
	if add("direct", "+.example.net"); list(paths.TunnelList) != "chrome.exe" {
		t.Fatalf("another kind: tunnel %q", list(paths.TunnelList))
	}
}

// A line the list has already is said so, the other lists cleaned all the
// same; and the auto-switch mode that stands above the lists is said: Observe
// only sends all but the forbidden direct, Tunnel only sets Always direct
// aside.
func TestLiveAddSaid(t *testing.T) {
	s, _ := testServer(t)
	add := func(to, entry string) liveAnswer {
		t.Helper()
		return liveAct(t, s, "/act/liveadd", url.Values{"to": {to}, "entry": {entry}}, nil)
	}
	if err := writeEntries(paths.DirectList, []string{"api.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := writeEntries(paths.TunnelList, []string{"+.example.com"}); err != nil {
		t.Fatal(err)
	}
	a := add("direct", "api.example.com")
	if !strings.HasPrefix(a.Msg, "“Always direct” has api.example.com already") ||
		!strings.Contains(a.Msg, "taken out of «Always via tunnel»: +.example.com") || len(readEntries(paths.TunnelList)) != 0 {
		t.Fatalf("there already, the others cleaned: %+v", a)
	}

	mode := func(m string) {
		t.Helper()
		if _, err := ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error { set.SetMode(m); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	mode(ctl.ModeObserve)
	// the always-tunnel list routes in observe only too: nothing to say
	if a = add("tunnel", "t.example"); strings.Contains(a.Msg, "is on") || strings.Contains(a.Msg, "switched off") {
		t.Errorf("observe only, to the tunnel: %s", a.Msg)
	}
	if a = add("block", "b.example"); strings.Contains(a.Msg, "is on") {
		t.Errorf("observe only, forbidden: %s", a.Msg)
	}
	// the second tunnel starts off there, and is said so
	if a = add("awg2", "o.example"); !strings.Contains(a.Msg, "The second tunnel is switched off") {
		t.Errorf("observe only, the second tunnel: %s", a.Msg)
	}
	mode(ctl.ModeTunnel)
	if a = add("direct", "d.example"); !strings.Contains(a.Msg, "Tunnel only is on") {
		t.Errorf("tunnel only, direct: %s", a.Msg)
	}
	if a = add("awg2", "w.example"); strings.Contains(a.Msg, "is on") {
		t.Errorf("tunnel only, the second tunnel: %s", a.Msg)
	}
}

func TestLiveOverlap(t *testing.T) {
	for _, c := range []struct {
		v, line  string
		over, in bool
	}{
		{"api.example.com", "+.example.com", true, false},
		{"api.example.com", "api.example.com", true, true},
		{"api.example.com", "+.api.example.com", true, false},
		{"api.example.com", "*.example.com", true, false},
		{"api.example.com", "example.com", false, false},
		{"example.com", ".example.com", false, false},
		{"example.com", "*.example.com", false, false},
		{"+.example.com", "a.b.example.com", true, true},
		{"+.example.com", "example.com", true, true},
		{"+.example.com", "*.example.com", true, true},
		{"+.example.com", "+.com", true, false},
		{"+.example.com", "badexample.com", false, false},
		{"10.20.30.40", "10.0.0.0/8", true, false},
		{"10.0.0.0/8", "10.20.30.40", true, true},
		{"10.0.0.0/8", "11.0.0.0/8", false, false},
		{"2001:db8::1", "2001:db8::/32", true, false},
		{"chrome.exe", "Chrome.EXE", true, true},
		{"chrome.exe", `C:\a\chrome.exe`, true, true},
		{`C:\a\chrome.exe`, "chrome.exe", true, false},
		{`C:\a\chrome.exe`, `D:\b\chrome.exe`, false, false},
		{"example.com", "93.184.216.34", false, false},
	} {
		if over, in := liveOverlap(c.v)(c.line); over != c.over || in != c.in {
			t.Errorf("%s vs %s: over %v in %v, want %v %v", c.v, c.line, over, in, c.over, c.in)
		}
	}
}

// The presets switched on stand above "Always via tunnel" and a direct site
// or address: the same rule is taken out of them, and one that takes it by a
// wider line is said. A preset switched off, and a program sent direct --
// its rule stands above the presets -- leave the presets as they are.
func TestLiveAddAbovePresets(t *testing.T) {
	s, _ := testServer(t)
	add := func(to, entry string) liveAnswer {
		t.Helper()
		return liveAct(t, s, "/act/liveadd", url.Values{"to": {to}, "entry": {entry}}, nil)
	}
	lines := func(id string) string {
		p, _ := findPreset(presets.Load(), id)
		return strings.Join(p.Lines, ",")
	}
	do(t, s.Handler(), "POST", "/act/preset", url.Values{"field": {"ai"}, "value": {"1"}}, nil)
	youtube := lines("youtube")

	// the whole domain: its names in the preset go too, a.claude.ai and all
	a := add("direct", "+.claude.ai")
	if !a.OK || !strings.Contains(a.Msg, "taken out of «AI services»") {
		t.Fatalf("out of the preset switched on: %+v", a)
	}
	for _, l := range strings.Split(lines("ai"), ",") {
		if l == "claude.ai" || strings.HasSuffix(l, ".claude.ai") {
			t.Errorf("left in the preset: %s", l)
		}
	}
	if !strings.Contains(lines("ai"), "*.livepreview.claude.app") {
		t.Error("a line of another domain taken out")
	}
	// anthropic.com, a line of the preset, takes api.anthropic.com still
	a = add("tunnel", "api.anthropic.com")
	if a.OK || !strings.Contains(a.Msg, "taken out of «AI services»") || !strings.Contains(a.Msg, "«AI services» stands above the lists") {
		t.Fatalf("a wider line: %+v", a)
	}
	if strings.Contains(","+lines("ai")+",", ",api.anthropic.com,") || !strings.Contains(","+lines("ai")+",", ",anthropic.com,") {
		t.Fatalf("the preset's lines: %s", lines("ai"))
	}
	if a = add("direct", "+.youtube.com"); !a.OK || lines("youtube") != youtube {
		t.Fatalf("a preset switched off: %+v", a)
	}
	liveAct(t, s, "/act/liveadd", url.Values{"to": {"preset"}, "preset": {"ai"}, "entry": {"chrome.exe"}}, nil)
	if a = add("direct", "chrome.exe"); !a.OK || !strings.HasSuffix(lines("ai"), ",chrome.exe") {
		t.Fatalf("a program sent direct: %+v, %s", a, lines("ai"))
	}
}

// The lists change together or not at all: one failing to write, the ones
// written before it are put back.
func TestLiveAddAtomic(t *testing.T) {
	s, _ := testServer(t)
	liveAct(t, s, "/act/liveadd", url.Values{"to": {"awg2"}, "entry": {"a.example"}}, nil)
	// the forbidden list is read, and cannot be written: it is read-only.
	// The second tunnel's list comes before it, and is written first.
	block := paths.User(paths.BlockList)
	if err := os.WriteFile(block, []byte("# empty\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(block, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(block, 0o644) })
	if a := liveAct(t, s, "/act/liveadd", url.Values{"to": {"block"}, "entry": {"a.example"}}, nil); a.OK {
		t.Fatalf("saved: %+v", a)
	}
	if got := strings.Join(readEntries(paths.Awg2List), ","); got != "a.example" {
		t.Fatalf("the second tunnel's list, written before the one that failed: %q", got)
	}
}

// Sent at once from several windows, every line lands: each move reads and
// writes the lists under one lock.
func TestLiveAddAtOnce(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			do(t, h, "POST", "/act/liveadd", url.Values{"to": {"tunnel"}, "entry": {fmt.Sprintf("s%d.example", i)}}, nil)
		}()
	}
	wg.Wait()
	if got := readEntries(paths.TunnelList); len(got) != 20 {
		t.Fatalf("%d of 20 lines kept: %v", len(got), got)
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
