package webui

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"slices"
	"strings"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
)

const (
	transferFileMax    = 4 << 20
	transferRequestMax = 36 << 20
)

var transferOrder = []string{"direct", "routes", "block", "presets"}

var transferName = map[string]string{
	"direct":  "always-direct.txt",
	"routes":  "always-via.json",
	"tunnel":  "always-via-tunnels.txt",
	"tunnel1": "always-via-tunnel1.txt",
	"tunnel2": "always-via-tunnel2.txt",
	"block":   "forbidden.txt",
	"awg2":    "second-tunnel-own-list.txt",
	"presets": "presets.json",
}

func transferBody(kind string) ([]byte, error) {
	if kind == "routes" {
		var rows []struct{ Entry, Route string }
		for _, spec := range routeSpecs {
			for _, entry := range readEntries(spec.List) {
				rows = append(rows, struct{ Entry, Route string }{entry, spec.ID})
			}
		}
		return json.MarshalIndent(rows, "", "  ")
	}
	if name := listFile[kind]; name != "" {
		return listBody(readEntries(name)), nil
	}
	if kind == "presets" {
		return presets.EncodeFile(presets.Load())
	}
	return nil, errors.New("unknown transfer item")
}

func selectedKinds(values []string) ([]string, error) {
	want := map[string]bool{}
	for _, kind := range values {
		if transferName[kind] == "" || want[kind] {
			return nil, errors.New("unknown transfer item")
		}
		want[kind] = true
	}
	var out []string
	for _, kind := range transferOrder {
		if want[kind] {
			out = append(out, kind)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("Select at least one item")
	}
	return out, nil
}

// handleListExport keeps the old kind= link working and serves the new
// selection dialog. One item stays its original file; several become a ZIP.
func (s *Server) handleListExport(w http.ResponseWriter, r *http.Request) {
	values := r.URL.Query()["item"]
	if kind := r.URL.Query().Get("kind"); len(values) == 0 && kind != "" {
		values = []string{kind}
	}
	kinds, err := selectedKinds(values)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(kinds) == 1 {
		body, err := transferBody(kinds[0])
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		contentType := "text/plain; charset=utf-8"
		if kinds[0] == "presets" || kinds[0] == "routes" {
			contentType = "application/json"
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", `attachment; filename="`+transferName[kinds[0]]+`"`)
		w.Write(body)
		return
	}
	var body bytes.Buffer
	zw := zip.NewWriter(&body)
	for _, kind := range kinds {
		b, err := transferBody(kind)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		f, err := zw.Create(transferName[kind])
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, err := f.Write(b); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if err := zw.Close(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="dpi-switch-routing.zip"`)
	w.Write(body.Bytes())
}

func readTransferFile(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, transferFileMax+1))
	if err != nil {
		return nil, err
	}
	if len(b) > transferFileMax {
		return nil, errors.New("The file is too large: 4 MB at most")
	}
	return b, nil
}

func zipTransferFiles(b []byte) (map[string][]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, errors.New("The ZIP archive could not be read")
	}
	byName := map[string]string{}
	for kind, name := range transferName {
		byName[strings.ToLower(name)] = kind
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		kind := byName[strings.ToLower(path.Base(f.Name))]
		if kind == "" || f.FileInfo().IsDir() {
			continue
		}
		if _, duplicate := out[kind]; duplicate {
			return nil, fmt.Errorf("%s: duplicate file in ZIP", transferName[kind])
		}
		if f.UncompressedSize64 > transferFileMax {
			return nil, fmt.Errorf("%s: the file is too large", transferName[kind])
		}
		r, err := f.Open()
		if err != nil {
			return nil, err
		}
		out[kind], err = readTransferFile(r)
		r.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", transferName[kind], err)
		}
	}
	return out, nil
}

func transferUpload(r *http.Request, field string) ([]byte, bool, error) {
	f, _, err := r.FormFile(field)
	if errors.Is(err, http.ErrMissingFile) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	b, err := readTransferFile(f)
	return b, true, err
}

type importPlan struct {
	kinds   []string
	lists   map[string][]string
	routes  map[string][]string
	presets []presets.Preset
	hasPS   bool
}

func addTransferToPlan(plan *importPlan, kind string, b []byte, lang string) error {
	if kind == "routes" {
		var rows []struct{ Entry, Route string }
		if err := json.Unmarshal(b, &rows); err != nil {
			return fmt.Errorf("%s: %w", transferName[kind], err)
		}
		valid := map[string]string{}
		for _, spec := range routeSpecs {
			valid[spec.ID] = spec.List
		}
		seen := map[string]bool{}
		for i, row := range rows {
			file := valid[row.Route]
			if file == "" {
				return fmt.Errorf("%s: row %d: unknown route %q", transferName[kind], i+1, row.Route)
			}
			doc := ctl.ParseList(row.Entry, ctl.ListPolicy{AllowAwg2Rule: file == paths.Tunnel2List})
			if len(doc.Issues) != 0 || len(doc.Values()) != 1 {
				return fmt.Errorf("%s: row %d: invalid entry", transferName[kind], i+1)
			}
			entry := doc.Values()[0]
			key := strings.ToLower(entry)
			if seen[key] {
				continue
			}
			seen[key] = true
			plan.routes[file] = append(plan.routes[file], entry)
		}
		return nil
	}
	if kind == "presets" {
		ps, err := presets.DecodeFile(b)
		if err != nil {
			return fmt.Errorf("%s: %w", transferName[kind], err)
		}
		plan.presets, plan.hasPS = ps, true
		return nil
	}
	doc := ctl.ParseList(string(b), ctl.ListPolicy{AllowAwg2Rule: kind == "tunnel2"})
	if len(doc.Issues) > 0 {
		return fmt.Errorf("%s: %s", transferName[kind], listIssues(lang, doc.Issues))
	}
	entries := doc.Values()
	if len(listBody(entries)) > ctl.UserListMax {
		return fmt.Errorf("%s: %w", transferName[kind], errListTooLarge)
	}
	plan.lists[kind] = entries
	return nil
}

func transferPlan(r *http.Request) (importPlan, error) {
	var plan importPlan
	kinds, err := selectedKinds(r.MultipartForm.Value["item"])
	if err != nil {
		return plan, err
	}
	plan.kinds, plan.lists, plan.routes = kinds, map[string][]string{}, map[string][]string{}
	fromZIP := map[string][]byte{}
	if b, ok, err := transferUpload(r, "bundle"); err != nil {
		return plan, err
	} else if ok {
		fromZIP, err = zipTransferFiles(b)
		if err != nil {
			return plan, err
		}
	}
	for _, kind := range kinds {
		b, ok, err := transferUpload(r, "file_"+kind)
		if err != nil {
			return plan, fmt.Errorf("%s: %w", transferName[kind], err)
		}
		if !ok {
			b, ok = fromZIP[kind]
		}
		if !ok {
			return plan, fmt.Errorf("%s: no file selected", transferName[kind])
		}
		if err := addTransferToPlan(&plan, kind, b, lang(r)); err != nil {
			return plan, err
		}
	}
	return plan, nil
}

type fileSnapshot struct {
	path   string
	body   []byte
	exists bool
}

func takeSnapshot(name string) (fileSnapshot, error) {
	s := fileSnapshot{path: name}
	b, err := os.ReadFile(name)
	switch {
	case err == nil:
		s.body, s.exists = b, true
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return s, err
	}
	return s, nil
}

func restoreSnapshots(snapshots []fileSnapshot) error {
	var errs []error
	for i := len(snapshots) - 1; i >= 0; i-- {
		s := snapshots[i]
		if s.exists {
			errs = append(errs, paths.ReplaceFile(s.path, s.body))
		} else {
			errs = append(errs, paths.RemoveRetry(s.path))
		}
	}
	return errors.Join(errs...)
}

type appliedImport struct {
	oldLists                 map[string][]string
	oldRoutes                map[string][]string
	oldPresets, newPresets   []presets.Preset
	oldSettings, newSettings ctl.Settings
}

func (s *Server) applyImport(plan importPlan) (appliedImport, error) {
	result := appliedImport{oldLists: map[string][]string{}, oldRoutes: map[string][]string{}, oldPresets: presets.Load(), oldSettings: loadSettings()}
	result.newPresets, result.newSettings = result.oldPresets, result.oldSettings
	if err := paths.UserReady(); err != nil {
		return result, err
	}
	s.listMu.Lock()
	defer s.listMu.Unlock()
	var snapshots []fileSnapshot
	for _, kind := range plan.kinds {
		if kind == "routes" {
			for _, spec := range routeSpecs {
				result.oldRoutes[spec.List] = readEntries(spec.List)
				snap, err := takeSnapshot(paths.User(spec.List))
				if err != nil {
					return result, err
				}
				snapshots = append(snapshots, snap)
				if err := writeEntries(spec.List, plan.routes[spec.List]); err != nil {
					restoreSnapshots(snapshots)
					return result, err
				}
			}
			continue
		}
		name := listFile[kind]
		if name == "" {
			continue
		}
		result.oldLists[kind] = readEntries(name)
		snap, err := takeSnapshot(paths.User(name))
		if err != nil {
			return result, err
		}
		snapshots = append(snapshots, snap)
		if err := writeEntries(name, plan.lists[kind]); err != nil {
			restoreSnapshots(snapshots)
			return result, err
		}
		if kind == "direct" {
			apps, err := takeSnapshot(paths.User(paths.AppsList))
			if err != nil {
				restoreSnapshots(snapshots)
				return result, err
			}
			snapshots = append(snapshots, apps)
			if err := paths.RemoveRetry(apps.path); err != nil {
				restoreSnapshots(snapshots)
				return result, err
			}
		}
	}
	if !plan.hasPS {
		return result, nil
	}
	if err := presets.Replace(plan.presets); err != nil {
		restoreSnapshots(snapshots)
		return result, err
	}
	result.newPresets = plan.presets
	known := map[string]bool{}
	for _, p := range plan.presets {
		known[p.ID] = true
	}
	keep := slices.DeleteFunc(slices.Clone(result.oldSettings.Awg2Presets), func(id string) bool { return !known[id] })
	if !slices.Equal(keep, result.oldSettings.Awg2Presets) {
		set, err := ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error {
			set.Awg2Presets = keep
			return nil
		})
		if err != nil {
			presets.Replace(result.oldPresets)
			restoreSnapshots(snapshots)
			return result, err
		}
		result.newSettings = set
	}
	return result, nil
}

func presetRulesFor(ps []presets.Preset, enabled []string) []string {
	on := map[string]bool{}
	for _, id := range enabled {
		on[id] = true
	}
	var out []string
	for _, p := range ps {
		if on[p.ID] {
			out = append(out, ctl.PresetRules(p)...)
		}
	}
	return out
}

func closePresetImport(a appliedImport) (int, error) {
	moved := changed(presetRulesFor(a.oldPresets, a.oldSettings.Awg2Presets),
		presetRulesFor(a.newPresets, a.newSettings.Awg2Presets))
	if len(moved) == 0 {
		return 0, nil
	}
	newByID := map[string]presets.Preset{}
	for _, p := range a.newPresets {
		newByID[p.ID] = p
	}
	newOn := map[string]bool{}
	for _, id := range a.newSettings.Awg2Presets {
		newOn[id] = true
	}
	oldOn := map[string]bool{}
	for _, id := range a.oldSettings.Awg2Presets {
		oldOn[id] = true
	}
	return closeMoved([]string{ctl.PresetsProvider, ctl.Awg2RuleProvider}, rulesMatch(moved), func() bool {
		for _, p := range a.newPresets {
			if newOn[p.ID] && !ctl.PresetWritten(p, true) {
				return false
			}
		}
		for _, p := range a.oldPresets {
			if oldOn[p.ID] && !newOn[p.ID] {
				if _, stillThere := newByID[p.ID]; !stillThere && !ctl.PresetWritten(p, false) {
					return false
				}
			}
		}
		return ctl.Awg2RuleSynced()
	})
}

func (s *Server) actTransferImport(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, transferRequestMax)
	if err := r.ParseMultipartForm(transferRequestMax); err != nil {
		s.redirect(w, r, errors.New("The import is too large or could not be read"), "")
		return
	}
	defer r.MultipartForm.RemoveAll()
	plan, err := transferPlan(r)
	if err != nil {
		s.redirect(w, r, err, "")
		return
	}
	applied, err := s.applyImport(plan)
	if err != nil {
		s.redirect(w, r, err, "")
		return
	}
	moved := 0
	var closeErrs []error
	for _, kind := range plan.kinds {
		if kind == "routes" {
			for _, spec := range routeSpecs {
				n, err := closeEntriesChange(spec.List, applied.oldRoutes[spec.List], plan.routes[spec.List])
				moved += n
				closeErrs = append(closeErrs, err)
			}
			continue
		}
		if name := listFile[kind]; name != "" {
			n, err := closeEntriesChange(name, applied.oldLists[kind], plan.lists[kind])
			moved += n
			closeErrs = append(closeErrs, err)
		}
	}
	if plan.hasPS {
		n, err := closePresetImport(applied)
		moved += n
		closeErrs = append(closeErrs, err)
	}
	if err := errors.Join(closeErrs...); err != nil {
		s.redirect(w, r, errors.New("Imported, but the open connections were not moved: they keep their old route until they reconnect"), "")
		return
	}
	if moved > 0 {
		s.redirect(w, r, nil, "Imported %d files; %d open connections moved", len(plan.kinds), moved)
		return
	}
	s.redirect(w, r, nil, "Imported %d files", len(plan.kinds))
}

func (s *Server) actListClassify(w http.ResponseWriter, r *http.Request) {
	b, err := readTransferFile(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	classes := ctl.ClassifyListLines(string(b), ctl.ListPolicy{AllowAwg2Rule: r.URL.Query().Get("kind") == "tunnel2"})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(classes)
}
