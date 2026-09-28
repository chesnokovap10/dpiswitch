package webui

import (
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
)

// A preset is added, edited and deleted in its dialog. A new one is
// switched on; a bad line is refused with the dialog open again on what was
// typed; a shipped one saved as the page showed it keeps the program's
// words; a deleted one is switched off with it.
func TestPresetEdit(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	post := func(path string, form url.Values, hdr map[string]string) string {
		t.Helper()
		w := do(t, h, "POST", path, form, hdr)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		return w.Body.String()
	}

	body := post("/act/presetsave", url.Values{"id": {""}, "title": {"Mine"}, "note": {"games"},
		"lines": {"Game.example\n\n# servers\n203.0.113.0/24\ngame.exe\ngame.example"}}, nil)
	if !strings.Contains(body, "msg ok") {
		t.Fatalf("not added: %s", body)
	}
	all := presets.Load()
	p := all[len(all)-1]
	if p.Title != "Mine" || p.Note != "games" ||
		strings.Join(p.Lines, ",") != "game.example,# servers,203.0.113.0/24,game.exe" {
		t.Fatalf("added %+v", p)
	}
	if !slices.Contains(ctl.LoadSettings(paths.Settings()).Awg2Presets, p.ID) {
		t.Fatal("a new preset is not switched on")
	}
	// its row, its buttons and its dialog
	for _, want := range []string{`name="` + p.ID + `" checked`, `data-open="dlg-preset-` + p.ID + `"`,
		`form="presetdel" name="id" value="` + p.ID + `"`, `id="dlg-preset-` + p.ID + `"`, `id="dlg-preset-new"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("no %s in\n%s", want, body)
		}
	}
	ctl.SyncUserFiles()
	if !ctl.PresetWritten(p, true) {
		t.Fatal("the service did not write the new preset")
	}

	// a bad line saves nothing, and the dialog opens again on what was typed
	body = post("/act/presetsave", url.Values{"id": {p.ID}, "title": {"Mine"}, "lines": {"ok.example\nbad host"}}, nil)
	if !strings.Contains(body, `id="dlg-preset-`+p.ID+`" class="presetdlg" data-show`) ||
		!strings.Contains(body, "bad host</textarea>") || !strings.Contains(body, "msg bad") {
		t.Fatalf("a bad line: %s", body)
	}
	body = post("/act/presetsave", url.Values{"id": {""}, "title": {" "}, "lines": {"x.example"}}, nil)
	if !strings.Contains(body, `id="dlg-preset-new" class="presetdlg" data-show`) {
		t.Fatalf("a preset with no name: %s", body)
	}
	if got := presets.Load(); len(got) != len(all) || strings.Join(got[len(got)-1].Lines, ",") != strings.Join(p.Lines, ",") {
		t.Fatalf("a refused save changed the presets: %+v", got)
	}

	post("/act/presetsave", url.Values{"id": {p.ID}, "title": {"Mine 2"}, "lines": {"other.example"}}, nil)
	got, _ := findPreset(presets.Load(), p.ID)
	if got.Title != "Mine 2" || got.Note != "" || strings.Join(got.Lines, ",") != "other.example" ||
		len(presets.Load()) != len(all) {
		t.Fatalf("edited %+v", got)
	}

	// a shipped one saved as the Russian page showed it keeps its own words:
	// the English page shows it in English still
	ai, _ := presets.Shipped("ai")
	post("/act/presetsave", url.Values{"id": {"ai"}, "title": {tr("ru", ai.Title)}, "note": {tr("ru", ai.Note)},
		"lines": {"claude.ai"}}, map[string]string{"Cookie": "lang=ru"})
	if got, _ := findPreset(presets.Load(), "ai"); got.Title != ai.Title || got.Note != ai.Note ||
		strings.Join(got.Lines, ",") != "claude.ai" {
		t.Fatalf("a shipped preset saved: %+v", got)
	}

	body = post("/act/presetdel", url.Values{"id": {p.ID}}, nil)
	if !strings.Contains(body, "msg ok") || strings.Contains(body, `id="dlg-preset-`+p.ID+`"`) {
		t.Fatalf("not deleted: %s", body)
	}
	if _, ok := findPreset(presets.Load(), p.ID); ok {
		t.Fatal("the deleted preset is still there")
	}
	if b, _ := os.ReadFile(paths.Settings()); strings.Contains(string(b), p.ID) {
		t.Fatalf("the deleted preset is still on: %s", b)
	}
	ctl.SyncUserFiles()
	if !ctl.PresetWritten(p, false) {
		t.Fatal("the deleted preset is still in the core's file")
	}
	// a window that still shows it: deleting or switching it says it is gone
	for _, c := range []struct {
		path string
		form url.Values
	}{
		{"/act/presetdel", url.Values{"id": {p.ID}}},
		{"/act/preset", url.Values{"field": {p.ID}, "value": {"1"}}},
		{"/act/presetsave", url.Values{"id": {p.ID}, "title": {"Mine"}, "lines": {"x.example"}}},
	} {
		if body := post(c.path, c.form, nil); !strings.Contains(body, "msg bad") {
			t.Errorf("%s of a deleted preset: %s", c.path, body)
		}
	}
}

// The button to put the shipped presets back shows only when one is deleted
// or edited. A deleted one comes back switched off, an edited one switched
// on stays on with the shipped lines, and the user's own preset stays.
func TestPresetRestore(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	post := func(path string, form url.Values) string {
		t.Helper()
		w := do(t, h, "POST", path, form, nil)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	page := func() string { return do(t, h, "GET", "/frag/awg2/presets", nil, nil).Body.String() }
	if strings.Contains(page(), "/act/presetrestore") {
		t.Fatal("nothing to restore, yet the button shows")
	}

	post("/act/preset", url.Values{"field": {"youtube"}, "value": {"1"}})
	post("/act/preset", url.Values{"field": {"ai"}, "value": {"1"}})
	post("/act/presetsave", url.Values{"id": {"youtube"}, "title": {"YouTube"}, "lines": {"edited.example"}})
	post("/act/presetdel", url.Values{"id": {"ai"}})
	post("/act/presetsave", url.Values{"id": {""}, "title": {"Mine"}, "lines": {"my.example"}})
	if !strings.Contains(page(), "/act/presetrestore") {
		t.Fatal("a shipped preset edited and one deleted, yet no button")
	}

	body := post("/act/presetrestore", nil)
	if !strings.Contains(body, "msg ok") || strings.Contains(body, "/act/presetrestore") {
		t.Fatalf("not restored: %s", body)
	}
	all := presets.Load()
	yt, _ := findPreset(all, "youtube")
	shipped, _ := presets.Shipped("youtube")
	if !slices.Equal(yt.Lines, shipped.Lines) {
		t.Fatalf("youtube not as shipped: %v", yt.Lines)
	}
	if _, ok := findPreset(all, "ai"); !ok {
		t.Fatal("the deleted preset did not come back")
	}
	if all[len(all)-1].Title != "Mine" {
		t.Fatalf("the user's own preset lost: %+v", all[len(all)-1])
	}
	on := ctl.LoadSettings(paths.Settings()).Awg2Presets
	if !slices.Contains(on, "youtube") || slices.Contains(on, "ai") || !slices.Contains(on, all[len(all)-1].ID) {
		t.Fatalf("switched on after the restore: %v", on)
	}
	ctl.SyncUserFiles()
	if !ctl.PresetWritten(yt, true) {
		t.Fatal("the service did not write youtube as shipped")
	}
}
