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
var errCategoryGone = errors.New("This category is no longer there: it was deleted in another window")
var errBuiltinCategory = errors.New("Built-in categories cannot be changed or deleted")

type presetGroup struct {
	ID, Title string
	Presets   []preset
	On, Mixed bool
	Custom    bool
	Selected  int
}

// Go supplies the whole tree and its translated order, including user presets.
func (v *view) PresetCategories() []presets.Category {
	out := presets.Categories()
	slices.SortFunc(out, func(a, b presets.Category) int {
		if a.ID == "other" && b.ID != "other" {
			return 1
		}
		if b.ID == "other" && a.ID != "other" {
			return -1
		}
		return strings.Compare(strings.ToLower(v.CategoryTitle(a)), strings.ToLower(v.CategoryTitle(b)))
	})
	return out
}

func (v *view) CategoryTitle(c presets.Category) string {
	if c.Custom {
		return c.Title
	}
	return v.T(c.Title)
}

func (v *view) PresetGroups() []presetGroup {
	a := presetsViewData(v.Data)
	var out []presetGroup
	for _, c := range v.PresetCategories() {
		g := presetGroup{ID: c.ID, Title: v.CategoryTitle(c), Custom: c.Custom}
		for _, p := range a.Presets {
			if presets.CategoryOf(p.Preset) != c.ID {
				continue
			}
			g.Presets = append(g.Presets, p)
			if p.On {
				g.Selected++
			}
		}
		if len(g.Presets) == 0 && !c.Custom {
			continue
		}
		slices.SortFunc(g.Presets, func(a, b preset) int {
			if n := strings.Compare(strings.ToLower(v.T(a.Title)), strings.ToLower(v.T(b.Title))); n != 0 {
				return n
			}
			return strings.Compare(a.ID, b.ID)
		})
		g.On = len(g.Presets) > 0 && g.Selected == len(g.Presets)
		g.Mixed = g.Selected > 0 && !g.On
		out = append(out, g)
	}
	return out
}

type categoryDlg struct {
	V       *view
	Key, ID string
	Title   string
}

func (v *view) CategoryDlg(id string) categoryDlg {
	d := categoryDlg{V: v, Key: "new-category", ID: id}
	if id == "" {
		return d
	}
	d.Key = id
	for _, c := range presets.Categories() {
		if c.Custom && c.ID == id {
			d.Title = c.Title
			break
		}
	}
	return d
}

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
	ID, Title, Note, Text, Err, Category string
}

// presetDlg: what a preset's dialog shows. ID is "" for a new preset.
type presetDlg struct {
	V                     *view
	Key                   string // the dialog's own name: the ID, "new" for a new one
	ID, Title, Note, Text string
	Err                   string
	Show                  bool // opened as it arrives: a save refused
	Category              string
}

// PresetDlg: the dialog of the preset with this ID, or of a new one for "".
// A shipped preset's name and note are shown in the page's language.
func (v *view) PresetDlg(id string) presetDlg {
	d := presetDlg{V: v, Key: "new", ID: id, Category: "other"}
	a := presetsViewData(v.Data)
	if id != "" {
		d.Key = id
		for _, p := range a.Presets {
			if p.ID == id {
				d.Title, d.Note, d.Text = v.T(p.Title), v.T(p.Note), strings.Join(p.Lines, "\n")
				d.Category = presets.CategoryOf(p.Preset)
			}
		}
	}
	if dr := a.Draft; dr != nil && dr.ID == id {
		d.Title, d.Note, d.Text, d.Err, d.Show = dr.Title, dr.Note, dr.Text, dr.Err, true
		d.Category = dr.Category
	}
	return d
}

func presetsViewData(data any) awg2 {
	switch d := data.(type) {
	case awg2:
		return d
	case lists:
		return d.awg2
	default:
		return awg2{}
	}
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
		Note: strings.TrimSpace(r.FormValue("note")), Text: r.FormValue("lines"), Category: r.FormValue("category")}
	if !presets.ValidCategory(d.Category) {
		d.Category = "other"
		if old, ok := findPreset(presets.Load(), id); ok {
			d.Category = presets.CategoryOf(old)
		}
	}
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
	p := presets.Preset{ID: id, Title: d.Title, Note: d.Note, Category: d.Category, Lines: lines}
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
	// A new preset is switched on: two files, written one after the other.
	// Settings not written, the preset goes again -- it stayed, switched
	// off, with the page saying it was not saved. An edit changes no
	// setting, and writes none: one refused failed an edit already saved.
	on := false
	switch {
	case err != nil:
	case id == "":
		_, err = ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error {
			set.Awg2Presets = append(set.Awg2Presets, p.ID)
			return nil
		})
		if err != nil {
			presets.Update(func(all []presets.Preset) ([]presets.Preset, error) {
				return slices.DeleteFunc(all, func(x presets.Preset) bool { return x.ID == p.ID }), nil
			})
		}
		on = err == nil
	default:
		on = slices.Contains(loadSettings().Awg2Presets, p.ID)
	}
	// a preset switched off routes nothing: nothing moves
	n := 0
	var cerr error
	if err == nil && on {
		n, cerr = closeMoved([]string{ctl.PresetsProvider, ctl.EnabledPresetsProvider}, rulesMatch(changed(was, ctl.PresetRules(p))),
			func() bool { return ctl.PresetWritten(p, true) && ctl.EnabledPresetsSynced() })
	}
	ok, msg := saved(r, err, n, cerr)
	if ok && n == 0 && id == "" {
		ok, msg = done(r, nil, "Preset added and switched on")
	}
	s.part(w, r, "lists", "presets", ok, msg)
}

// refusePreset: the presets again, the dialog open on what was sent, with
// why it was not saved -- the list in its place lost what had been typed
func (s *Server) refusePreset(w http.ResponseWriter, r *http.Request, d presetDraft) {
	v := &view{Lang: lang(r), Page: "lists", Path: back(r), St: s.status()}
	a := awg2Data()
	if _, ok := findPreset(presetsOf(a), d.ID); d.ID != "" && !ok {
		v.Msg = &flash{false, tr(lang(r), errPresetGone.Error())}
	} else {
		a.Draft = &d
	}
	pageData := listsData()
	pageData.awg2 = a
	v.Data = pageData
	render(w, v, "presets")
}

func presetsOf(a awg2) []presets.Preset {
	out := make([]presets.Preset, len(a.Presets))
	for i, p := range a.Presets {
		out[i] = p.Preset
	}
	return out
}

func categoryTitleTaken(lang, title, except string) bool {
	for _, c := range presets.Categories() {
		if c.ID == except {
			continue
		}
		shown := c.Title
		if !c.Custom {
			shown = tr(lang, shown)
		}
		if strings.EqualFold(strings.TrimSpace(shown), title) {
			return true
		}
	}
	return false
}

// actPresetCategorySave adds or renames a custom root category.
func (s *Server) actPresetCategorySave(w http.ResponseWriter, r *http.Request) {
	id, title, l := r.FormValue("id"), strings.TrimSpace(r.FormValue("title")), lang(r)
	var err error
	switch {
	case title == "":
		err = errors.New(tr(l, "Give the category a name"))
	case len([]rune(title)) > 80:
		err = errors.New(tr(l, "The category name is too long"))
	case categoryTitleTaken(l, title, id):
		err = errors.New(tr(l, "A category with this name already exists"))
	case presets.BuiltinCategory(id):
		err = errBuiltinCategory
	}
	if err == nil {
		err = paths.UserReady()
	}
	if err == nil {
		err = presets.UpdateCatalog(func(c presets.Catalog) (presets.Catalog, error) {
			if categoryTitleTaken(l, title, id) {
				return c, errors.New(tr(l, "A category with this name already exists"))
			}
			if id == "" {
				c.Categories = append(c.Categories, presets.Category{ID: presets.NewCategoryID(c.Categories), Title: title, Custom: true})
				return c, nil
			}
			for i := range c.Categories {
				if c.Categories[i].ID == id {
					c.Categories[i].Title = title
					return c, nil
				}
			}
			return c, errCategoryGone
		})
	}
	message := "Category renamed"
	if id == "" {
		message = "Category added"
	}
	ok, msg := done(r, err, message)
	s.part(w, r, "lists", "presets", ok, msg)
}

// actPresetCategoryDel deletes a custom root and safely moves its presets to
// Other. Built-in roots stay stable for shipped presets and translations.
func (s *Server) actPresetCategoryDel(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	moved := 0
	var err error
	if presets.BuiltinCategory(id) {
		err = errBuiltinCategory
	} else {
		err = paths.UserReady()
	}
	if err == nil {
		err = presets.UpdateCatalog(func(c presets.Catalog) (presets.Catalog, error) {
			at := slices.IndexFunc(c.Categories, func(x presets.Category) bool { return x.ID == id })
			if at < 0 {
				return c, errCategoryGone
			}
			c.Categories = slices.Delete(c.Categories, at, at+1)
			for i := range c.Presets {
				if c.Presets[i].Category == id {
					c.Presets[i].Category = "other"
					moved++
				}
			}
			return c, nil
		})
	}
	ok, msg := done(r, err, "Category deleted; presets moved to Other: %d", moved)
	s.part(w, r, "lists", "presets", ok, msg)
}

// actPresetDel deletes a preset. The connections it took are closed: they
// go the way the other lists send them.
func (s *Server) actPresetDel(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	// asked before the preset goes: the settings forget a preset that is
	// not there
	on := slices.Contains(loadSettings().Awg2Presets, id)
	var old presets.Preset
	at := -1
	err := paths.UserReady()
	if err == nil {
		err = presets.Update(func(all []presets.Preset) ([]presets.Preset, error) {
			for i := range all {
				if all[i].ID == id {
					old, at = all[i], i
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
		// the settings still naming it, the preset comes back where it was:
		// said not deleted, it was gone
		if err != nil {
			presets.Update(func(all []presets.Preset) ([]presets.Preset, error) {
				return slices.Insert(all, min(at, len(all)), old), nil
			})
		}
	}
	n := 0
	var cerr error
	if err == nil && on {
		n, cerr = closeMoved([]string{ctl.PresetsProvider, ctl.EnabledPresetsProvider}, rulesMatch(ctl.PresetRules(old)),
			func() bool { return ctl.PresetWritten(old, false) && ctl.EnabledPresetsSynced() })
	}
	ok, msg := saved(r, err, n, cerr)
	if ok && n == 0 {
		ok, msg = done(r, nil, "Preset deleted")
	}
	s.part(w, r, "lists", "presets", ok, msg)
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
		on = loadSettings().Awg2Presets
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
		n, cerr = closeMoved([]string{ctl.PresetsProvider, ctl.EnabledPresetsProvider}, rulesMatch(moved), func() bool {
			for _, p := range now {
				if !ctl.PresetWritten(p, true) {
					return false
				}
			}
			return ctl.EnabledPresetsSynced()
		})
	}
	ok, msg := saved(r, err, n, cerr)
	if ok && n == 0 {
		ok, msg = done(r, nil, "Built-in presets restored")
	}
	s.part(w, r, "lists", "presets", ok, msg)
}
