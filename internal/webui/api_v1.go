package webui

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
)

const apiV1MaxBody = 8 << 20

type apiV1Error struct {
	Error string `json:"error"`
}

func apiV1Fail(w http.ResponseWriter, code int, err any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	writeJSON(w, apiV1Error{Error: fmt.Sprint(err)})
}

func apiRevision(v any) string {
	b, _ := json.Marshal(v)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func apiETag(w http.ResponseWriter, revision string) { w.Header().Set("ETag", `"`+revision+`"`) }

func apiMatch(r *http.Request, revision string) bool {
	want := strings.Trim(r.Header.Get("If-Match"), `" `)
	return want == "" || want == revision
}

func apiDecode(w http.ResponseWriter, r *http.Request, dst any) bool {
	d := json.NewDecoder(io.LimitReader(r.Body, apiV1MaxBody))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		apiV1Fail(w, http.StatusBadRequest, err)
		return false
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		apiV1Fail(w, http.StatusBadRequest, "one JSON value is required")
		return false
	}
	return true
}

func (s *Server) handleAPIV1(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1", "/api/v1/":
		if r.Method != http.MethodGet {
			apiV1Fail(w, http.StatusMethodNotAllowed, "GET required")
			return
		}
		writeJSON(w, map[string]any{"version": 1, "resources": map[string]string{
			"status": "/api/v1/status", "settings": "/api/v1/settings", "routes": "/api/v1/routes",
			"verdicts": "/api/v1/verdicts", "presets": "/api/v1/presets",
		}})
	case "/api/v1/status":
		s.apiV1Status(w, r)
	case "/api/v1/settings":
		s.apiV1Settings(w, r)
	case "/api/v1/routes":
		s.apiV1Routes(w, r)
	case "/api/v1/verdicts":
		s.apiV1Verdicts(w, r)
	case "/api/v1/presets":
		s.apiV1Presets(w, r)
	default:
		apiV1Fail(w, http.StatusNotFound, "unknown API resource")
	}
}

func (s *Server) apiV1Status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apiV1Fail(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	st := s.status()
	writeJSON(w, map[string]any{
		"version": st.Version, "commit": st.Commit, "mode": st.Mode, "network_id": st.NetworkID,
		"service":        map[string]any{"installed": st.Installed, "running": st.ServiceRun, "pending": st.Pending, "network_up": st.NetworkUp},
		"verdict_counts": map[string]int{"direct": st.DirectCount, "blocked": st.Blocked, "slower": st.Slower, "unverified": st.Unverified, "families": st.Families},
		"tunnels": map[string]any{
			"awg1": map[string]any{"configured": st.HasConfig, "enabled": st.Awg1On, "alive": st.TunnelAlive, "note": st.TunnelNote, "endpoint": st.Endpoint},
			"awg2": map[string]any{"configured": st.Awg2, "enabled": st.Awg2On, "alive": st.Awg2Alive, "note": st.Awg2Note, "endpoint": st.Endpoint2, "error": st.Awg2Err},
		},
	})
}

type apiSettingsDocument struct {
	Revision string       `json:"revision"`
	Settings ctl.Settings `json:"settings"`
}

type apiSettingsPatch struct {
	Revision string                     `json:"revision,omitempty"`
	Settings map[string]json.RawMessage `json:"settings"`
}

func (s *Server) apiV1Settings(w http.ResponseWriter, r *http.Request) {
	old := loadSettings()
	revision := apiRevision(old)
	if r.Method == http.MethodGet {
		apiETag(w, revision)
		writeJSON(w, apiSettingsDocument{revision, old})
		return
	}
	if r.Method != http.MethodPatch && r.Method != http.MethodPut {
		apiV1Fail(w, http.StatusMethodNotAllowed, "GET, PATCH or PUT required")
		return
	}
	if !apiMatch(r, revision) {
		apiV1Fail(w, http.StatusPreconditionFailed, "settings changed; fetch them again")
		return
	}
	var req apiSettingsPatch
	if !apiDecode(w, r, &req) {
		return
	}
	if req.Revision != "" && req.Revision != revision {
		apiV1Fail(w, http.StatusConflict, "settings changed; fetch them again")
		return
	}
	base := map[string]json.RawMessage{}
	if r.Method == http.MethodPatch {
		b, _ := json.Marshal(old)
		_ = json.Unmarshal(b, &base)
	}
	allowed := map[string]bool{}
	b, _ := json.Marshal(ctl.DefaultSettings())
	var defaults map[string]json.RawMessage
	_ = json.Unmarshal(b, &defaults)
	for k := range defaults {
		allowed[k] = true
	}
	for k, v := range req.Settings {
		if !allowed[k] {
			apiV1Fail(w, http.StatusBadRequest, "unknown setting "+k)
			return
		}
		base[k] = v
	}
	b, _ = json.Marshal(base)
	next, err := ctl.DecodeSettings(b)
	if err != nil {
		apiV1Fail(w, http.StatusBadRequest, err)
		return
	}
	if err := paths.UserReady(); err == nil {
		err = ctl.SaveSettings(paths.Settings(), next)
	}
	if err != nil {
		apiV1Fail(w, http.StatusInternalServerError, err)
		return
	}
	secret := ctl.SecretFromConfig(paths.Config())
	if old.DefaultTunnel != next.DefaultTunnel || old.Awg1On != next.Awg1On || old.Awg2On != next.Awg2On {
		ctl.SyncRoutesNow(apiAddr, secret)
		_, _ = ctl.CloseConns(apiAddr, secret, func(ctl.Conn) bool { return true })
	}
	if !slices.Equal(old.Awg2Presets, next.Awg2Presets) {
		ps := presets.Load()
		_, _ = closePresetImport(appliedImport{oldPresets: ps, newPresets: ps, oldSettings: old, newSettings: next})
	}
	revision = apiRevision(next)
	apiETag(w, revision)
	writeJSON(w, apiSettingsDocument{revision, next})
}

type apiRouteRule struct {
	Entry string `json:"entry"`
	Route string `json:"route"`
}
type apiRoutesDocument struct {
	Revision string         `json:"revision"`
	Rules    []apiRouteRule `json:"rules"`
	Moved    int            `json:"moved_connections,omitempty"`
	Warning  string         `json:"warning,omitempty"`
}

func currentAPIRoutes() []apiRouteRule {
	var out []apiRouteRule
	for _, spec := range ruleSpecs {
		for _, entry := range readEntries(spec.List) {
			out = append(out, apiRouteRule{entry, spec.ID})
		}
	}
	return out
}

func (s *Server) apiV1Routes(w http.ResponseWriter, r *http.Request) {
	current := currentAPIRoutes()
	revision := apiRevision(current)
	if r.Method == http.MethodGet {
		apiETag(w, revision)
		writeJSON(w, apiRoutesDocument{Revision: revision, Rules: current})
		return
	}
	if r.Method != http.MethodPut {
		apiV1Fail(w, http.StatusMethodNotAllowed, "GET or PUT required")
		return
	}
	if !apiMatch(r, revision) {
		apiV1Fail(w, http.StatusPreconditionFailed, "routes changed; fetch them again")
		return
	}
	var req apiRoutesDocument
	if !apiDecode(w, r, &req) {
		return
	}
	if req.Revision != "" && req.Revision != revision {
		apiV1Fail(w, http.StatusConflict, "routes changed; fetch them again")
		return
	}
	valid := map[string]string{}
	for _, spec := range ruleSpecs {
		valid[spec.ID] = spec.List
	}
	byFile, seen := map[string][]string{}, map[string]bool{}
	for i, row := range req.Rules {
		file := valid[row.Route]
		if file == "" {
			apiV1Fail(w, http.StatusBadRequest, fmt.Sprintf("rule %d: unknown route %q", i+1, row.Route))
			return
		}
		doc := ctl.ParseList(row.Entry, ctl.ListPolicy{AllowEnabledPresets: file != ""})
		if len(doc.Issues) != 0 || len(doc.Values()) != 1 {
			apiV1Fail(w, http.StatusBadRequest, fmt.Sprintf("rule %d: exactly one valid entry is required", i+1))
			return
		}
		entry := doc.Values()[0]
		key := strings.ToLower(entry)
		if seen[key] {
			apiV1Fail(w, http.StatusBadRequest, fmt.Sprintf("rule %d: duplicate entry %q", i+1, entry))
			return
		}
		seen[key] = true
		byFile[file] = append(byFile[file], entry)
	}
	moved, err, closeErr := s.saveRouteEntries(byFile)
	if err != nil {
		apiV1Fail(w, http.StatusInternalServerError, err)
		return
	}
	next := currentAPIRoutes()
	out := apiRoutesDocument{Revision: apiRevision(next), Rules: next, Moved: moved}
	if closeErr != nil {
		out.Warning = closeErr.Error()
	}
	apiETag(w, out.Revision)
	writeJSON(w, out)
}

func (s *Server) apiV1Verdicts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apiV1Fail(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	d := verdictsData(r)
	writeJSON(w, map[string]any{"network": d.Cur, "selected_network": d.Net, "category": d.Cat, "counts": d.Counts, "rows": d.Rows})
}

func (s *Server) apiV1Presets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apiV1Fail(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	on := map[string]bool{}
	for _, id := range loadSettings().Awg2Presets {
		on[id] = true
	}
	type item struct {
		presets.Preset
		Enabled bool `json:"enabled"`
	}
	var out []item
	for _, p := range presets.Load() {
		out = append(out, item{p, on[p.ID]})
	}
	writeJSON(w, map[string]any{"presets": out})
}
