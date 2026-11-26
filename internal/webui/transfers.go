package webui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"slices"
	"strings"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
)

const (
	transferFileMax    = 32 << 20
	transferRequestMax = 36 << 20
	routingFileName    = "routing.json"
)

var routingParts = []string{"direct", "routes", "block", "presets"}

type routingDocument struct {
	Format     string             `json:"format"`
	Version    int                `json:"version"`
	Rules      []apiRouteRule     `json:"rules"`
	Categories []presets.Category `json:"categories,omitempty"`
	Presets    []presets.Preset   `json:"presets"`
}

func routingBody() ([]byte, error) {
	catalog := presets.LoadCatalog()
	b, err := json.MarshalIndent(routingDocument{
		Format: "dpi-switch-routing", Version: 1, Rules: currentAPIRoutes(),
		Categories: catalog.Categories, Presets: catalog.Presets,
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(b) > transferFileMax {
		return nil, errors.New("The file is too large: 32 MB at most")
	}
	return append(b, '\n'), nil
}

func (s *Server) handleListExport(w http.ResponseWriter, r *http.Request) {
	body, err := routingBody()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+routingFileName+`"`)
	w.Write(body)
}

func readTransferFile(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, transferFileMax+1))
	if err != nil {
		return nil, err
	}
	if len(b) > transferFileMax {
		return nil, errors.New("The file is too large: 32 MB at most")
	}
	return b, nil
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
	kinds      []string
	lists      map[string][]string
	routes     map[string][]string
	categories []presets.Category
	presets    []presets.Preset
	hasPS      bool
}

func routingPlan(b []byte) (importPlan, error) {
	plan := importPlan{kinds: slices.Clone(routingParts), lists: map[string][]string{}, routes: map[string][]string{}}
	var file routingDocument
	if err := json.Unmarshal(b, &file); err != nil {
		return plan, fmt.Errorf("%s: %w", routingFileName, err)
	}
	if file.Format != "dpi-switch-routing" || file.Version != 1 {
		return plan, errors.New("This is not a supported DPI Switch routing file")
	}
	valid := map[string]string{}
	for _, spec := range ruleSpecs {
		valid[spec.ID] = spec.List
	}
	seen := map[string]bool{}
	for i, row := range file.Rules {
		name := valid[row.Route]
		if name == "" {
			return plan, fmt.Errorf("%s: rule %d: unknown route %q", routingFileName, i+1, row.Route)
		}
		doc := ctl.ParseList(row.Entry, ctl.ListPolicy{AllowEnabledPresets: true})
		if len(doc.Issues) != 0 || len(doc.Values()) != 1 {
			return plan, fmt.Errorf("%s: rule %d: invalid entry", routingFileName, i+1)
		}
		entry := doc.Values()[0]
		key := strings.ToLower(entry)
		if seen[key] {
			return plan, fmt.Errorf("%s: rule %d: duplicate entry %q", routingFileName, i+1, entry)
		}
		seen[key] = true
		switch row.Route {
		case "direct", "block":
			plan.lists[row.Route] = append(plan.lists[row.Route], entry)
		default:
			plan.routes[name] = append(plan.routes[name], entry)
		}
	}
	for _, entries := range append([][]string{plan.lists["direct"], plan.lists["block"]}, mapValues(plan.routes)...) {
		if len(listBody(entries)) > ctl.UserListMax {
			return plan, fmt.Errorf("%s: %w", routingFileName, errListTooLarge)
		}
	}
	catalogBody, err := presets.EncodeCatalogFile(presets.Catalog{Categories: file.Categories, Presets: file.Presets})
	if err != nil {
		return plan, fmt.Errorf("%s: %w", routingFileName, err)
	}
	catalog, err := presets.DecodeCatalogFile(catalogBody)
	if err != nil {
		return plan, fmt.Errorf("%s: %w", routingFileName, err)
	}
	plan.categories, plan.presets, plan.hasPS = catalog.Categories, catalog.Presets, true
	return plan, nil
}

func mapValues(m map[string][]string) [][]string {
	out := make([][]string, 0, len(m))
	for _, entries := range m {
		out = append(out, entries)
	}
	return out
}

func transferPlan(r *http.Request) (importPlan, error) {
	b, ok, err := transferUpload(r, "routing")
	if err != nil {
		return importPlan{}, fmt.Errorf("%s: %w", routingFileName, err)
	}
	if !ok {
		return importPlan{}, errors.New("Choose a DPI Switch routing file")
	}
	return routingPlan(b)
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
	oldLists                     map[string][]string
	oldRoutes                    map[string][]string
	oldCategories, newCategories []presets.Category
	oldPresets, newPresets       []presets.Preset
	oldSettings, newSettings     ctl.Settings
}

func (s *Server) applyImport(plan importPlan) (appliedImport, error) {
	oldCatalog := presets.LoadCatalog()
	result := appliedImport{oldLists: map[string][]string{}, oldRoutes: map[string][]string{}, oldCategories: oldCatalog.Categories, oldPresets: oldCatalog.Presets, oldSettings: loadSettings()}
	result.newCategories, result.newPresets, result.newSettings = result.oldCategories, result.oldPresets, result.oldSettings
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
	if err := presets.ReplaceCatalog(presets.Catalog{Categories: plan.categories, Presets: plan.presets}); err != nil {
		restoreSnapshots(snapshots)
		return result, err
	}
	result.newCategories, result.newPresets = plan.categories, plan.presets
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
			presets.ReplaceCatalog(presets.Catalog{Categories: result.oldCategories, Presets: result.oldPresets})
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
	return closeMoved([]string{ctl.PresetsProvider, ctl.EnabledPresetsProvider}, rulesMatch(moved), func() bool {
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
		return ctl.EnabledPresetsSynced()
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
			n, err := closeRouteEntriesChange(routeSpecs, applied.oldRoutes, plan.routes)
			moved += n
			closeErrs = append(closeErrs, err)
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
		s.redirect(w, r, nil, "Routing data loaded; %d open connections moved", moved)
		return
	}
	s.redirect(w, r, nil, "Routing data loaded")
}

func (s *Server) actListClassify(w http.ResponseWriter, r *http.Request) {
	b, err := readTransferFile(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	kind := r.URL.Query().Get("kind")
	classes := ctl.ClassifyListLines(string(b), ctl.ListPolicy{AllowEnabledPresets: kind == "tunnel" || listFile[kind] != ""})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(classes)
}
