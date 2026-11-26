package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
)

func apiRequest(t *testing.T, h http.Handler, method, target string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var b bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&b).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, target, &b)
	r.Host = "127.0.0.1:8080"
	r.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAPIV1SettingsAndDiscovery(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	if w := apiRequest(t, h, http.MethodGet, "/api/v1", nil, nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"settings":"/api/v1/settings"`) {
		t.Fatalf("discovery: %d %s", w.Code, w.Body.String())
	}
	w := apiRequest(t, h, http.MethodGet, "/api/v1/settings", nil, nil)
	var got apiSettingsDocument
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Revision == "" || !got.Settings.CompareLatency {
		t.Fatalf("settings: %d %s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodPatch, "/api/v1/settings", map[string]any{
		"revision": got.Revision, "settings": map[string]any{"compare_latency": false},
	}, map[string]string{"If-Match": `"` + got.Revision + `"`})
	if w.Code != 200 || ctl.LoadSettings(paths.Settings()).CompareLatency {
		t.Fatalf("patch: %d %s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodPatch, "/api/v1/settings", map[string]any{
		"settings": map[string]any{"compare_latency": true},
	}, map[string]string{"If-Match": `"` + got.Revision + `"`})
	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale patch: %d %s", w.Code, w.Body.String())
	}
}

func TestAPIV1RoutesAreAtomicAndVersioned(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	w := apiRequest(t, h, http.MethodGet, "/api/v1/routes", nil, nil)
	var got apiRoutesDocument
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Revision == "" {
		t.Fatalf("routes: %d %s", w.Code, w.Body.String())
	}
	w = apiRequest(t, h, http.MethodPut, "/api/v1/routes", apiRoutesDocument{Revision: got.Revision, Rules: []apiRouteRule{
		{Entry: "direct.example", Route: "direct"},
		{Entry: "blocked.example", Route: "block"},
		{Entry: "tunnel.example", Route: "awg2-awg1-direct"},
		{Entry: "enabled_presets", Route: "awg1"},
	}}, map[string]string{"If-Match": got.Revision})
	if w.Code != 200 {
		t.Fatalf("put routes: %d %s", w.Code, w.Body.String())
	}
	if strings.Join(readEntries(paths.DirectList), ",") != "direct.example" || strings.Join(readEntries(paths.BlockList), ",") != "blocked.example" || strings.Join(readEntries(paths.Awg2List), ",") != "tunnel.example" || strings.Join(readEntries(paths.Tunnel1List), ",") != "enabled_presets" {
		t.Fatal("route files do not match the API document")
	}
	w = apiRequest(t, h, http.MethodPut, "/api/v1/routes", apiRoutesDocument{Revision: got.Revision}, nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("stale routes: %d %s", w.Code, w.Body.String())
	}
}

func TestAPIV1SemanticResources(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	for _, path := range []string{"/api/v1/status", "/api/v1/verdicts", "/api/v1/presets"} {
		w := apiRequest(t, h, http.MethodGet, path, nil, nil)
		if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "application/json") {
			t.Errorf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	w := apiRequest(t, h, http.MethodGet, "/api/v1/presets", nil, nil)
	var catalog struct {
		Categories []struct {
			ID      string `json:"id"`
			Builtin bool   `json:"builtin"`
		} `json:"categories"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &catalog); err != nil || len(catalog.Categories) != len(presets.BuiltinCategories()) || !catalog.Categories[0].Builtin {
		t.Fatalf("preset categories API: %s", w.Body.String())
	}
}
