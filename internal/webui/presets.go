package webui

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
)

// The second tunnel's presets themselves: each is edited in a dialog of its
// own, a new one is made in another, and a deleted one is gone for good.
// The service takes the user's file within a second and writes the rules
// of the ones switched on for the core (see ctl.SyncUserFiles).

var errPresetGone = errors.New("This preset is no longer there: it was deleted in another window")

func findPreset(all []presets.Preset, id string) (presets.Preset, bool) {
	for _, p := range all {
		if p.ID == id {
			return p, true
		}
	}
	return presets.Preset{}, false
}

// presetDraft: a preset's dialog as it was sent, and why it was not saved
type presetDraft struct {
	ID, Title, Note, Text, Err string
}

// presetDlg: what a preset's dialog shows. ID is "" for a new preset.
type presetDlg struct {
	V                     *view
	Key                   string // the dialog's own name: the ID, "new" for a new one
	ID, Title, Note, Text string
	Err                   string
	Show                  bool // opened as it arrives: a save refused
}

// PresetDlg: the dialog of the preset with this ID, or of a new one for "".
// A shipped preset's name and note are shown in the page's language.
func (v *view) PresetDlg(id string) presetDlg {
	d := presetDlg{V: v, Key: "new", ID: id}
	a, _ := v.Data.(awg2)
	if id != "" {
		d.Key = id
		for _, p := range a.Presets {
			if p.ID == id {
				d.Title, d.Note, d.Text = v.T(p.Title), v.T(p.Note), strings.Join(p.Lines, "\n")
			}
		}
	}
	if dr := a.Draft; dr != nil && dr.ID == id {
		d.Title, d.Note, d.Text, d.Err, d.Show = dr.Title, dr.Note, dr.Text, dr.Err, true
	}
	return d
}

// presetLines: a preset's box as it is kept -- a site, an address or a
// program written the one way the lists write it, each once, the comments
// as they are; bad is the first line that is none of the kinds
func presetLines(text string) (out []string, bad string) {
	out = []string{}
	seen := map[string]bool{}
	for _, l := range splitLines(text) {
		if strings.HasPrefix(l, "#") {
			out = append(out, l)
			continue
		}
		_, v, err := ctl.ParseEntry(l)
		if err != nil {
			if bad == "" {
				bad = l
			}
			continue
		}
		if k := strings.ToLower(v); !seen[k] {
			seen[k] = true
			out = append(out, v)
		}
	}
	return out, bad
}

// actPresetSave saves a preset from its dialog, or adds a new one --
// switched on: it is made to be used. What the change moves is closed, as
// a list's save does.
func (s *Server) actPresetSave(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	d := presetDraft{ID: id, Title: strings.TrimSpace(r.FormValue("title")),
		Note: strings.TrimSpace(r.FormValue("note")), Text: r.FormValue("lines")}
	lines, bad := presetLines(d.Text)
	switch {
	case d.Title == "":
		d.Err = tr(lang(r), "Give the preset a name")
	case bad != "":
		d.Err = fmt.Sprintf(tr(lang(r), "%q is neither a site, an address nor a program: nothing saved"), bad)
	}
	if d.Err != "" {
		s.refusePreset(w, r, d)
		return
	}
	p := presets.Preset{ID: id, Title: d.Title, Note: d.Note, Lines: lines}
	// a shipped preset saved with the name it was shown under keeps the
	// program's own: it is then shown in the language of whoever looks
	if b, ok := presets.Shipped(id); ok {
		if p.Title == tr(lang(r), b.Title) {
			p.Title = b.Title
		}
		if p.Note == tr(lang(r), b.Note) {
			p.Note = b.Note
		}
	}
	var was []string // the rules the preset had
	err := paths.UserReady()
	if err == nil {
		err = presets.Update(func(all []presets.Preset) ([]presets.Preset, error) {
			if id == "" {
				p.ID = presets.NewID(all)
				return append(all, p), nil
			}
			for i := range all {
				if all[i].ID == id {
					was = ctl.PresetRules(all[i])
					all[i] = p
					return all, nil
				}
			}
			return nil, errPresetGone
		})
	}
	on := false
	if err == nil {
		_, err = ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error {
			if id == "" {
				set.Awg2Presets = append(set.Awg2Presets, p.ID)
			}
			on = slices.Contains(set.Awg2Presets, p.ID)
			return nil
		})
	}
	// a preset switched off routes nothing: nothing moves
	n := 0
	var cerr error
	if err == nil && on {
		n, cerr = closeMoved([]string{ctl.PresetsProvider}, rulesMatch(changed(was, ctl.PresetRules(p))),
			func() bool { return ctl.PresetWritten(p, true) })
	}
	ok, msg := saved(r, err, n, cerr)
	if ok && n == 0 && id == "" {
		ok, msg = done(r, nil, "Preset added and switched on")
	}
	s.part(w, r, "awg2", "presets", ok, msg)
}

// refusePreset: the presets again, the dialog open on what was sent, with
// why it was not saved -- the list in its place lost what had been typed
func (s *Server) refusePreset(w http.ResponseWriter, r *http.Request, d presetDraft) {
	s.fresh()
	v := &view{Lang: lang(r), Page: "awg2", Path: back(r), St: s.status()}
	a := awg2Data()
	if _, ok := findPreset(presetsOf(a), d.ID); d.ID != "" && !ok {
		v.Msg = &flash{false, tr(lang(r), errPresetGone.Error())}
	} else {
		a.Draft = &d
	}
	v.Data = a
	render(w, v, "presets")
}

func presetsOf(a awg2) []presets.Preset {
	out := make([]presets.Preset, len(a.Presets))
	for i, p := range a.Presets {
		out[i] = p.Preset
	}
	return out
}

// actPresetDel deletes a preset. The connections it took are closed: they
// go the way the other lists send them.
func (s *Server) actPresetDel(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	// asked before the preset goes: the settings forget a preset that is
	// not there
	on := slices.Contains(ctl.LoadSettings(paths.Settings()).Awg2Presets, id)
	var old presets.Preset
	err := paths.UserReady()
	if err == nil {
		err = presets.Update(func(all []presets.Preset) ([]presets.Preset, error) {
			for i := range all {
				if all[i].ID == id {
					old = all[i]
					return slices.Delete(all, i, i+1), nil
				}
			}
			return nil, errPresetGone
		})
	}
	if err == nil && on {
		_, err = ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error {
			set.Awg2Presets = slices.DeleteFunc(set.Awg2Presets, func(x string) bool { return x == id })
			return nil
		})
	}
	n := 0
	var cerr error
	if err == nil && on {
		n, cerr = closeMoved([]string{ctl.PresetsProvider}, rulesMatch(ctl.PresetRules(old)),
			func() bool { return ctl.PresetWritten(old, false) })
	}
	ok, msg := saved(r, err, n, cerr)
	if ok && n == 0 {
		ok, msg = done(r, nil, "Preset deleted")
	}
	s.part(w, r, "awg2", "presets", ok, msg)
}

// actPresetRestore puts the shipped presets back as the program ships them:
// the deleted ones come back switched off, the edited ones lose the edits,
// the user's own stay as they are. What an edited preset switched on routes
// anew is moved.
func (s *Server) actPresetRestore(w http.ResponseWriter, r *http.Request) {
	var was []presets.Preset
	err := paths.UserReady()
	if err == nil {
		was, err = presets.Restore()
	}
	// the deleted ones come back switched off, as the program ships them: a
	// settings file edited by hand may still name one
	var back []string
	for _, p := range presets.Builtin() {
		if _, ok := findPreset(was, p.ID); !ok {
			back = append(back, p.ID)
		}
	}
	var on []string
	if err == nil {
		on = ctl.LoadSettings(paths.Settings()).Awg2Presets
		if slices.ContainsFunc(on, func(id string) bool { return slices.Contains(back, id) }) {
			var set ctl.Settings
			set, err = ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error {
				set.Awg2Presets = slices.DeleteFunc(set.Awg2Presets, func(id string) bool { return slices.Contains(back, id) })
				return nil
			})
			on = set.Awg2Presets
		}
	}
	// an edited preset switched on routes as shipped now
	var moved []string
	var now []presets.Preset
	if err == nil {
		for _, p := range presets.Builtin() {
			old, ok := findPreset(was, p.ID)
			if !ok || !slices.Contains(on, p.ID) {
				continue
			}
			if c := changed(ctl.PresetRules(old), ctl.PresetRules(p)); len(c) > 0 {
				moved = append(moved, c...)
				now = append(now, p)
			}
		}
	}
	n := 0
	var cerr error
	if len(now) > 0 {
		n, cerr = closeMoved([]string{ctl.PresetsProvider}, rulesMatch(moved), func() bool {
			for _, p := range now {
				if !ctl.PresetWritten(p, true) {
					return false
				}
			}
			return true
		})
	}
	ok, msg := saved(r, err, n, cerr)
	if ok && n == 0 {
		ok, msg = done(r, nil, "Built-in presets restored")
	}
	s.part(w, r, "awg2", "presets", ok, msg)
}
