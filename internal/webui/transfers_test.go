package webui

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
)

func multipartPost(t *testing.T, h http.Handler, target string, values map[string][]string, files map[string]struct {
	name string
	body []byte
}) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	for name, vals := range values {
		for _, value := range vals {
			if err := w.WriteField(name, value); err != nil {
				t.Fatal(err)
			}
		}
	}
	for field, file := range files {
		part, err := w.CreateFormFile(field, file.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(file.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, target, &body)
	r.Host = "127.0.0.1:8080"
	r.Header.Set("Content-Type", w.FormDataContentType())
	r.Header.Set("Referer", "http://127.0.0.1:8080/lists")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestRoutingFileRoundTripIsAtomic(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	if err := writeEntries(paths.DirectList, []string{"direct.example"}); err != nil {
		t.Fatal(err)
	}
	if err := writeEntries(paths.BlockList, []string{"blocked.example"}); err != nil {
		t.Fatal(err)
	}
	if err := writeEntries(paths.Tunnel1List, []string{"enabled_presets", "tunnel.example"}); err != nil {
		t.Fatal(err)
	}
	if err := presets.ReplaceCatalog(presets.Catalog{
		Categories: []presets.Category{{ID: "games", Title: "Games", Custom: true}},
		Presets:    []presets.Preset{{ID: "mine", Title: "Mine", Category: "games", Lines: []string{"preset.example"}}},
	}); err != nil {
		t.Fatal(err)
	}

	exported := do(t, h, http.MethodGet, "/lists/export", nil, nil)
	if exported.Code != http.StatusOK || exported.Header().Get("Content-Disposition") != `attachment; filename="routing.json"` {
		t.Fatalf("export: %d %q", exported.Code, exported.Header().Get("Content-Disposition"))
	}
	var doc routingDocument
	if err := json.Unmarshal(exported.Body.Bytes(), &doc); err != nil || doc.Format != "dpi-switch-routing" || doc.Version != 1 {
		t.Fatalf("routing file: %+v, %v", doc, err)
	}
	if len(doc.Rules) != 4 || len(doc.Categories) != 1 || len(doc.Presets) != 1 {
		t.Fatalf("routing contents: %+v", doc)
	}

	if err := writeEntries(paths.DirectList, []string{"changed.example"}); err != nil {
		t.Fatal(err)
	}
	if err := presets.Replace(nil); err != nil {
		t.Fatal(err)
	}
	rec := multipartPost(t, h, "/act/listsimport", nil, map[string]struct {
		name string
		body []byte
	}{
		"routing": {"routing.json", exported.Body.Bytes()},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	if got := strings.Join(readEntries(paths.DirectList), ","); got != "direct.example" {
		t.Fatalf("direct: %q", got)
	}
	if got := strings.Join(readEntries(paths.BlockList), ","); got != "blocked.example" {
		t.Fatalf("block: %q", got)
	}
	if got := strings.Join(readEntries(paths.Tunnel1List), ","); got != "enabled_presets,tunnel.example" {
		t.Fatalf("tunnel: %q", got)
	}
	if got := presets.LoadCatalog(); len(got.Presets) != 1 || got.Presets[0].ID != "mine" || len(got.Categories) != 1 || got.Categories[0].Title != "Games" {
		t.Fatalf("preset catalog: %+v", got)
	}

	bad := slices.Replace(append([]byte(nil), exported.Body.Bytes()...), 0, 1, '{')
	bad = bytes.Replace(bad, []byte(`"blocked.example"`), []byte(`"bad host"`), 1)
	rec = multipartPost(t, h, "/act/listsimport", nil, map[string]struct {
		name string
		body []byte
	}{
		"routing": {"routing.json", bad},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("refused import: %d %s", rec.Code, rec.Body.String())
	}
	if got := strings.Join(readEntries(paths.DirectList), ","); got != "direct.example" {
		t.Fatalf("partial import remained: %q", got)
	}
}

func TestSettingsArchiveRoundTrip(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	conf1 := "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.8.1.3/32\n[Peer]\nPublicKey = AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nEndpoint = 198.51.100.7:51820\n"
	if err := paths.WriteSecret(paths.SourceConf(), []byte(conf1)); err != nil {
		t.Fatal(err)
	}
	if err := paths.WriteSecret(paths.SourceConf2(), []byte(testConf2)); err != nil {
		t.Fatal(err)
	}
	set := ctl.DefaultSettings()
	set.Attempts, set.SecondTunnel, set.Awg2Presets = 7, true, []string{"mine"}
	if err := presets.Replace([]presets.Preset{{ID: "mine", Title: "Mine", Lines: []string{"preset.example"}}}); err != nil {
		t.Fatal(err)
	}
	if err := ctl.SaveSettings(paths.Settings(), set); err != nil {
		t.Fatal(err)
	}
	if err := writeEntries(paths.DirectList, []string{"saved.example"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Data("ui.key"), []byte("must-not-export"), 0o600); err != nil {
		t.Fatal(err)
	}

	export := do(t, h, http.MethodGet, "/settings/archive", nil, nil)
	if export.Code != http.StatusOK || export.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("archive: %d, cache %q: %s", export.Code, export.Header().Get("Cache-Control"), export.Body.String())
	}
	zr, err := zip.NewReader(bytes.NewReader(export.Body.Bytes()), int64(export.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	if slices.Contains(names, "ui.key") || !slices.Contains(names, "source.conf") || !slices.Contains(names, "source2.conf") || !slices.Contains(names, "manifest.json") || !slices.Contains(names, routingFileName) {
		t.Fatalf("archive files: %v", names)
	}
	for _, old := range []string{"always-direct.txt", "always-via.json", "forbidden.txt", "presets.json"} {
		if slices.Contains(names, old) {
			t.Fatalf("archive still contains legacy %s: %v", old, names)
		}
	}

	set.Attempts = 2
	if err := ctl.SaveSettings(paths.Settings(), set); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(paths.SourceConf2()); err != nil {
		t.Fatal(err)
	}
	if err := writeEntries(paths.DirectList, []string{"changed.example"}); err != nil {
		t.Fatal(err)
	}
	if err := presets.Replace(nil); err != nil {
		t.Fatal(err)
	}
	rec := multipartPost(t, h, "/act/settingsarchive", nil, map[string]struct {
		name string
		body []byte
	}{"archive": {"settings.zip", export.Body.Bytes()}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("load: %d %s", rec.Code, rec.Body.String())
	}
	if got := ctl.LoadSettings(paths.Settings()); got.Attempts != 7 || !got.SecondTunnel || !slices.Equal(got.Awg2Presets, []string{"mine"}) {
		t.Fatalf("settings: %+v", got)
	}
	if got := strings.Join(readEntries(paths.DirectList), ","); got != "saved.example" {
		t.Fatalf("direct: %q", got)
	}
	if b, err := os.ReadFile(paths.SourceConf2()); err != nil || string(b) != testConf2 {
		t.Fatalf("source2: %v, %q", err, b)
	}
	if got := presets.Load(); len(got) != 1 || got[0].ID != "mine" {
		t.Fatalf("presets: %+v", got)
	}
}

func TestSettingsArchiveRejectsBeforeWriting(t *testing.T) {
	s, _ := testServer(t)
	if err := writeEntries(paths.DirectList, []string{"kept.example"}); err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	zw := zip.NewWriter(&body)
	w, _ := zw.Create("manifest.json")
	io.WriteString(w, `{"format":"dpi-switch-settings","version":1}`)
	zw.Close()
	rec := multipartPost(t, s.Handler(), "/act/settingsarchive", nil, map[string]struct {
		name string
		body []byte
	}{"archive": {"bad.zip", body.Bytes()}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("refusal: %d", rec.Code)
	}
	if got := strings.Join(readEntries(paths.DirectList), ","); got != "kept.example" {
		t.Fatalf("refused archive changed data: %q", got)
	}
}
