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
	"path"
	"strings"
	"time"

	"dpiswitch/internal/awgconf"
	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
)

const settingsArchiveMax = 48 << 20

type settingsArchiveManifest struct {
	Format  string `json:"format"`
	Version int    `json:"version"`
	Source1 bool   `json:"source1"`
	Source2 bool   `json:"source2"`
}

func zipAdd(zw *zip.Writer, name string, body []byte) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

func readOptional(name string) ([]byte, bool, error) {
	b, err := paths.ReadUserFile(name, transferFileMax)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	return b, err == nil, err
}

func settingsArchiveBody() ([]byte, error) {
	manifest := settingsArchiveManifest{Format: "dpi-switch-settings", Version: 2}
	conf1, has1, err := readOptional(paths.SourceConf())
	if err != nil {
		return nil, err
	}
	conf2, has2, err := readOptional(paths.SourceConf2())
	if err != nil {
		return nil, err
	}
	manifest.Source1, manifest.Source2 = has1, has2
	settings, err := json.MarshalIndent(loadSettings(), "", "  ")
	if err != nil {
		return nil, err
	}
	manifestBody, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	var body bytes.Buffer
	zw := zip.NewWriter(&body)
	if err := zipAdd(zw, "manifest.json", manifestBody); err != nil {
		return nil, err
	}
	if err := zipAdd(zw, "settings.json", settings); err != nil {
		return nil, err
	}
	routing, err := routingBody()
	if err != nil {
		return nil, err
	}
	if err := zipAdd(zw, routingFileName, routing); err != nil {
		return nil, err
	}
	if manifest.Source1 {
		if err := zipAdd(zw, "source.conf", conf1); err != nil {
			return nil, err
		}
	}
	if manifest.Source2 {
		if err := zipAdd(zw, "source2.conf", conf2); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

func (s *Server) handleSettingsArchive(w http.ResponseWriter, r *http.Request) {
	body, err := settingsArchiveBody()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="dpi-switch-settings-`+time.Now().Format("2006-01-02")+`.zip"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Write(body)
}

type settingsArchivePlan struct {
	manifest settingsArchiveManifest
	settings ctl.Settings
	transfer importPlan
	conf1    []byte
	conf2    []byte
}

func settingsArchiveFiles(b []byte) (map[string][]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, errors.New("The ZIP archive could not be read")
	}
	known := map[string]bool{"manifest.json": true, "settings.json": true, "source.conf": true, "source2.conf": true, routingFileName: true}
	out := map[string][]byte{}
	for _, f := range zr.File {
		name := strings.ToLower(path.Base(f.Name))
		if !known[name] || f.FileInfo().IsDir() {
			continue
		}
		if _, duplicate := out[name]; duplicate {
			return nil, fmt.Errorf("%s: duplicate file in ZIP", name)
		}
		if f.UncompressedSize64 > transferFileMax {
			return nil, fmt.Errorf("%s: the file is too large", name)
		}
		r, err := f.Open()
		if err != nil {
			return nil, err
		}
		out[name], err = readTransferFile(r)
		r.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	return out, nil
}

func makeSettingsArchivePlan(b []byte) (settingsArchivePlan, error) {
	var plan settingsArchivePlan
	files, err := settingsArchiveFiles(b)
	if err != nil {
		return plan, err
	}
	if err := json.Unmarshal(files["manifest.json"], &plan.manifest); err != nil || plan.manifest.Format != "dpi-switch-settings" || plan.manifest.Version != 2 {
		return plan, errors.New("This is not a supported DPI Switch settings archive")
	}
	settingsBody, ok := files["settings.json"]
	if !ok {
		return plan, errors.New("settings.json is missing from the archive")
	}
	routing, ok := files[routingFileName]
	if !ok {
		return plan, fmt.Errorf("%s is missing from the archive", routingFileName)
	}
	plan.transfer, err = routingPlan(routing)
	if err != nil {
		return plan, err
	}
	known := map[string]bool{}
	for _, p := range plan.transfer.presets {
		known[p.ID] = true
	}
	plan.settings, err = ctl.DecodeSettingsWithPresets(settingsBody, known)
	if err != nil {
		return plan, fmt.Errorf("settings.json: %w", err)
	}
	var conf1, conf2 *awgconf.Conf
	for _, c := range []struct {
		name   string
		has    bool
		dst    *[]byte
		out    **awgconf.Conf
		second bool
	}{{"source.conf", plan.manifest.Source1, &plan.conf1, &conf1, false}, {"source2.conf", plan.manifest.Source2, &plan.conf2, &conf2, true}} {
		*c.dst, ok = files[c.name]
		if c.has != ok {
			return plan, fmt.Errorf("%s does not match the archive manifest", c.name)
		}
		if ok {
			parsed, err := awgconf.Parse(string(*c.dst))
			if err != nil {
				return plan, fmt.Errorf("%s: %w", c.name, err)
			}
			if c.second {
				err = parsed.Usable()
			} else {
				_, err = parsed.Render()
			}
			if err == nil {
				err = parsed.CheckKeys()
			}
			if err != nil {
				return plan, fmt.Errorf("%s: %w", c.name, err)
			}
			*c.out = parsed
		}
	}
	if conf1 != nil && conf2 != nil && awgconf.SameKey(conf1, conf2) {
		return plan, awgconf.ErrSameKey
	}
	return plan, nil
}

func restoreSettingsArchive(snaps []fileSnapshot, oldCatalog presets.Catalog) error {
	var errs []error
	for i := len(snaps) - 1; i >= 0; i-- {
		snap := snaps[i]
		if !snap.exists {
			errs = append(errs, paths.RemoveRetry(snap.path))
		} else if snap.path == paths.SourceConf() || snap.path == paths.SourceConf2() {
			errs = append(errs, paths.WriteSecret(snap.path, snap.body))
		} else {
			errs = append(errs, paths.ReplaceFile(snap.path, snap.body))
		}
	}
	err := errors.Join(errs...)
	if pErr := presets.ReplaceCatalog(oldCatalog); pErr != nil {
		err = errors.Join(err, pErr)
	}
	return err
}

func (s *Server) applySettingsArchive(plan settingsArchivePlan) (appliedImport, error) {
	oldCatalog := presets.LoadCatalog()
	result := appliedImport{oldLists: map[string][]string{}, oldRoutes: map[string][]string{}, oldCategories: oldCatalog.Categories, oldPresets: oldCatalog.Presets, oldSettings: loadSettings(), newCategories: plan.transfer.categories, newPresets: plan.transfer.presets, newSettings: plan.settings}
	if err := paths.UserReady(); err != nil {
		return result, err
	}
	var snaps []fileSnapshot
	files := []string{paths.Settings(), paths.SourceConf(), paths.SourceConf2(), paths.User(paths.AppsList), paths.UserPresets()}
	for _, kind := range routingParts {
		if kind == "routes" {
			for _, spec := range routeSpecs {
				files = append(files, paths.User(spec.List))
				result.oldRoutes[spec.List] = readEntries(spec.List)
			}
			continue
		}
		if name := listFile[kind]; name != "" {
			files = append(files, paths.User(name))
			result.oldLists[kind] = readEntries(name)
		}
	}
	for _, name := range files {
		snap, err := takeSnapshot(name)
		if err != nil {
			return result, err
		}
		snaps = append(snaps, snap)
	}
	fail := func(err error) (appliedImport, error) {
		if restoreErr := restoreSettingsArchive(snaps, presets.Catalog{Categories: result.oldCategories, Presets: result.oldPresets}); restoreErr != nil {
			err = errors.Join(err, fmt.Errorf("rollback: %w", restoreErr))
		}
		return result, err
	}
	s.listMu.Lock()
	defer s.listMu.Unlock()
	for _, kind := range routingParts {
		if kind == "routes" {
			for _, spec := range routeSpecs {
				if err := writeEntries(spec.List, plan.transfer.routes[spec.List]); err != nil {
					return fail(err)
				}
			}
			continue
		}
		if name := listFile[kind]; name != "" {
			if err := writeEntries(name, plan.transfer.lists[kind]); err != nil {
				return fail(err)
			}
		}
	}
	if err := paths.RemoveRetry(paths.User(paths.AppsList)); err != nil {
		return fail(err)
	}
	if err := presets.ReplaceCatalog(presets.Catalog{Categories: plan.transfer.categories, Presets: plan.transfer.presets}); err != nil {
		return fail(err)
	}
	for _, c := range []struct {
		name string
		has  bool
		body []byte
	}{{paths.SourceConf(), plan.manifest.Source1, plan.conf1}, {paths.SourceConf2(), plan.manifest.Source2, plan.conf2}} {
		var err error
		if c.has {
			err = paths.WriteSecret(c.name, c.body)
		} else {
			err = paths.RemoveRetry(c.name)
		}
		if err != nil {
			return fail(err)
		}
	}
	if err := ctl.SaveSettings(paths.Settings(), plan.settings); err != nil {
		return fail(err)
	}
	return result, nil
}

func (s *Server) actSettingsArchive(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, settingsArchiveMax)
	if err := r.ParseMultipartForm(settingsArchiveMax); err != nil {
		s.redirect(w, r, errors.New("The settings archive is too large or could not be read"), "")
		return
	}
	defer r.MultipartForm.RemoveAll()
	f, _, err := r.FormFile("archive")
	if err != nil {
		s.redirect(w, r, errors.New("Choose a DPI Switch settings ZIP archive"), "")
		return
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, settingsArchiveMax+1))
	if err != nil || len(body) > settingsArchiveMax {
		s.redirect(w, r, errors.New("The settings archive is too large or could not be read"), "")
		return
	}
	plan, err := makeSettingsArchivePlan(body)
	if err != nil {
		s.redirect(w, r, err, "")
		return
	}
	_, err = s.applySettingsArchive(plan)
	if err != nil {
		s.redirect(w, r, err, "")
		return
	}
	if err := restartService(); err != nil {
		s.redirect(w, r, err, "")
		return
	}
	s.redirect(w, r, nil, "Settings loaded")
}
