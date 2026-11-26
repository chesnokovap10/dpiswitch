package webui

import (
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
)

func TestPresetCategorySelection(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	post := func(field, value string) string {
		t.Helper()
		w := do(t, h, "POST", "/act/preset", url.Values{"field": {field}, "value": {value}}, nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "msg ok") {
			t.Fatalf("%s: %d %s", field, w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	post("youtube", "1")
	post("category:ai", "1")
	on := ctl.LoadSettings(paths.Settings()).Awg2Presets
	for _, p := range presets.Load() {
		want := p.ID == "youtube" || presets.CategoryOf(p) == "ai"
		if slices.Contains(on, p.ID) != want {
			t.Errorf("group selection: %s", p.ID)
		}
	}
	post("claude", "0")
	v := &view{Lang: "ru", Data: awg2Data()}
	groups := v.PresetGroups()
	var titles []string
	for _, g := range groups {
		titles = append(titles, v.T(g.Title))
		if g.ID == "ai" && (!g.Mixed || g.On || g.Selected != len(g.Presets)-1) {
			t.Fatalf("partial category: %+v", g)
		}
		if !slices.IsSortedFunc(g.Presets, func(a, b preset) int {
			return strings.Compare(strings.ToLower(v.T(a.Title)), strings.ToLower(v.T(b.Title)))
		}) {
			t.Fatalf("unsorted services: %s", g.ID)
		}
	}
	if !slices.Equal(titles, []string{"Видеохостинги", "ИИ", "Мессенджеры", "Соцсети", "Прочее"}) {
		t.Fatalf("category order: %v", titles)
	}
	post("category:ai", "0")
	if on = ctl.LoadSettings(paths.Settings()).Awg2Presets; !slices.Equal(on, []string{"youtube"}) {
		t.Fatalf("unrelated selection changed: %v", on)
	}
	body := post("category:messengers", "1")
	if !strings.Contains(body, "Telegram.exe") || !strings.Contains(body, "WhatsApp.exe") {
		t.Fatal("desktop programs not shown")
	}
	ctl.SyncUserFiles()
	for _, p := range presets.Load() {
		if !ctl.PresetWritten(p, p.ID == "youtube" || presets.CategoryOf(p) == "messengers") {
			t.Errorf("core file differs for %s", p.ID)
		}
	}
	w := do(t, h, "POST", "/act/preset", url.Values{"field": {"category:missing"}, "value": {"1"}}, nil)
	if !strings.Contains(w.Body.String(), "msg bad") {
		t.Fatal("unknown category accepted")
	}
}

func TestPresetCategoryOrder(t *testing.T) {
	for lang, want := range map[string][]string{
		"ru": {"video", "ai", "messengers", "social", "other"},
		"en": {"ai", "messengers", "social", "video", "other"},
	} {
		v := &view{Lang: lang}
		var ids []string
		for _, c := range v.PresetCategories() {
			ids = append(ids, c.ID)
		}
		if !slices.Equal(ids, want) {
			t.Errorf("%s: category order %v, want %v", lang, ids, want)
		}
	}
}

func TestCustomPresetCategoryCRUD(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	post := func(path string, form url.Values) string {
		t.Helper()
		w := do(t, h, http.MethodPost, path, form, map[string]string{"Cookie": "lang=ru"})
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		return w.Body.String()
	}

	body := post("/act/presetcategorysave", url.Values{"title": {"Игры"}})
	if !strings.Contains(body, "Категория добавлена") || !strings.Contains(body, "Игры") {
		t.Fatalf("category not added: %s", body)
	}
	catalog := presets.LoadCatalog()
	if len(catalog.Categories) != 1 || catalog.Categories[0].Title != "Игры" {
		t.Fatalf("categories: %+v", catalog.Categories)
	}
	id := catalog.Categories[0].ID
	body = post("/act/presetsave", url.Values{"title": {"Мои игры"}, "category": {id}, "lines": {"game.example"}})
	if !strings.Contains(body, "Пресет добавлен и включён") {
		t.Fatalf("preset not added: %s", body)
	}
	catalog = presets.LoadCatalog()
	mine := catalog.Presets[len(catalog.Presets)-1]
	if mine.Category != id {
		t.Fatalf("preset category %q, want %q", mine.Category, id)
	}

	body = post("/act/presetcategorysave", url.Values{"id": {id}, "title": {"Игровые сервисы"}})
	if !strings.Contains(body, "Категория переименована") || presets.LoadCatalog().Categories[0].Title != "Игровые сервисы" {
		t.Fatalf("category not renamed: %s", body)
	}
	body = post("/act/presetcategorydel", url.Values{"id": {id}})
	if !strings.Contains(body, "пресетов перемещено в «Прочее»: 1") {
		t.Fatalf("category not deleted: %s", body)
	}
	catalog = presets.LoadCatalog()
	if len(catalog.Categories) != 0 {
		t.Fatalf("category remains: %+v", catalog.Categories)
	}
	got, ok := findPreset(catalog.Presets, mine.ID)
	if !ok || got.Category != "other" {
		t.Fatalf("preset lost instead of moved: %+v", got)
	}

	body = post("/act/presetcategorydel", url.Values{"id": {"ai"}})
	if !strings.Contains(body, "msg bad") || !presets.BuiltinCategory("ai") {
		t.Fatalf("built-in category deletion accepted: %s", body)
	}
}

// Optional static fixture for browser checks. testServer isolates the real
// service, API and user settings; the browser gets only rendered HTML/assets.
func TestPresetTreeBrowserFixture(t *testing.T) {
	dir := os.Getenv("DPISWITCH_UI_FIXTURE_DIR")
	if dir == "" {
		t.Skip("browser fixture not requested")
	}
	s, _ := testServer(t)
	secondOn(t)
	if _, err := ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error { set.Awg2Presets = []string{"claude"}; return nil }); err != nil {
		t.Fatal(err)
	}
	w := do(t, s.Handler(), "GET", "/awg2", nil, map[string]string{"Cookie": "lang=ru"})
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if err := os.MkdirAll(filepath.Join(dir, "static"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.html"), w.Body.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	entries, _ := uiFS.ReadDir("static")
	for _, e := range entries {
		b, err := uiFS.ReadFile("static/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, "static", e.Name()), b, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if addr := os.Getenv("DPISWITCH_UI_BROWSER_ADDR"); addr != "" {
		// Serve the real Go handlers with testServer's isolated data/API.
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{}, 1)
		h := s.Handler()
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/__test_done" {
				select {
				case done <- struct{}{}:
				default:
				}
				w.WriteHeader(204)
				return
			}
			// Delay answers to expose an old reply undoing a later press.
			if r.URL.Path == "/act/preset" {
				time.Sleep(150 * time.Millisecond)
			}
			h.ServeHTTP(w, r)
		})}
		defer server.Close()
		go server.Serve(ln)
		select {
		case <-done:
		case <-time.After(3 * time.Minute):
			t.Fatal("browser did not finish")
		}
	}
}
