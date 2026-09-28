package webui

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
)

// The live page's menu: a row's site, address or program sent to one of the
// lists or to a preset, and a program's file shown in its folder.

// liveListNames: the lists the menu sends to, as its messages name them
var liveListNames = map[string]string{
	"direct": "Always direct", "tunnel": "Always via tunnel",
	"awg2": "Second tunnel: your own list", "block": "Forbidden",
}

// liveAnswer: what the page's script shows of an action
type liveAnswer struct {
	OK  bool   `json:"ok"`
	Msg string `json:"msg"`
}

// errHad: the line is where it was sent already -- nothing is written
var errHad = errors.New("had")

// actLiveAdd sends one line to a list or a preset. It goes one way only: it
// is taken out of the other lists, which would route it before the one it
// went to or instead of it -- "Always via tunnel" stands above "Always
// direct", "Forbidden" above everything. The connections it moves are
// closed, as a list's save does.
func (s *Server) actLiveAdd(w http.ResponseWriter, r *http.Request) {
	to, id, entry := r.FormValue("to"), r.FormValue("preset"), strings.TrimSpace(r.FormValue("entry"))
	var name string
	switch {
	case to == "preset":
		p, ok := findPreset(presets.Load(), id)
		if !ok {
			writeJSON(w, liveAnswer{false, tr(lang(r), errPresetGone.Error())})
			return
		}
		name = tr(lang(r), p.Title)
	case listFile[to] != "":
		name = tr(lang(r), liveListNames[to])
	default:
		http.Error(w, "unknown list", http.StatusBadRequest)
		return
	}
	_, v, err := ctl.ParseEntry(entry)
	if err != nil {
		writeJSON(w, liveAnswer{false, fmt.Sprintf(tr(lang(r), "%q is neither a site, an address nor a program: nothing saved"), entry)})
		return
	}
	if err := paths.UserReady(); err != nil {
		writeJSON(w, liveAnswer{false, tr(lang(r), err.Error())})
		return
	}
	var n int
	var had, off bool
	var closeErr error
	if to == "preset" {
		n, had, off, err, closeErr = s.toPreset(id, v)
	} else {
		n, had, err, closeErr = s.saveLine(listFile[to], v, true)
	}
	if err != nil {
		writeJSON(w, liveAnswer{false, tr(lang(r), err.Error())})
		return
	}
	// out of the other lists
	var outOf []string
	for kind, list := range listFile {
		if kind == to {
			continue
		}
		k, was, err, cerr := s.saveLine(list, v, false)
		if err != nil {
			writeJSON(w, liveAnswer{false, tr(lang(r), err.Error())})
			return
		}
		if was {
			n += k
			outOf = append(outOf, "«"+tr(lang(r), liveListNames[kind])+"»")
			closeErr = firstErr(closeErr, cerr)
		}
	}
	slices.Sort(outOf)
	var msg string
	switch {
	case had && len(outOf) == 0:
		writeJSON(w, liveAnswer{true, fmt.Sprintf(tr(lang(r), "“%s” has %s already"), name, v)})
		return
	case n > 0:
		msg = fmt.Sprintf(tr(lang(r), "Added to “%s”: %s; open connections moved: %d"), name, v, n)
	default:
		msg = fmt.Sprintf(tr(lang(r), "Added to “%s”: %s"), name, v)
	}
	if len(outOf) > 0 {
		msg += fmt.Sprintf(tr(lang(r), " (taken out of %s)"), strings.Join(outOf, ", "))
	}
	if off {
		msg += tr(lang(r), ". The preset is off: it routes nothing until it is switched on")
	}
	if closeErr != nil {
		writeJSON(w, liveAnswer{false, msg + ". " + tr(lang(r), "Saved, but the open connections were not moved: they keep their old route until they reconnect")})
		return
	}
	writeJSON(w, liveAnswer{true, msg})
}

// firstErr: the first of two errors that is one
func firstErr(a, b error) error {
	if a != nil {
		return a
	}
	return b
}

// saveLine puts v into a user list, or takes it out; had: it was there
// before. A list the change leaves as it was is not written.
func (s *Server) saveLine(list, v string, in bool) (n int, had bool, err, closeErr error) {
	entries := readEntries(list)
	same := func(x string) bool { return strings.EqualFold(x, v) }
	had = slices.ContainsFunc(entries, same)
	if had == in {
		return 0, had, nil, nil
	}
	if in {
		entries, _ = normEntries(append(entries, v))
	} else {
		entries = slices.DeleteFunc(entries, same)
	}
	n, err, closeErr = s.saveEntries(list, entries)
	return n, had, err, closeErr
}

// toPreset adds v to a preset's lines, unless its rules have it already.
// off: the preset is switched off, and routes nothing.
func (s *Server) toPreset(id, v string) (n int, had, off bool, err, closeErr error) {
	add := ctl.PresetRules(presets.Preset{Lines: []string{v}})
	var p presets.Preset
	var was []string
	err = presets.Update(func(all []presets.Preset) ([]presets.Preset, error) {
		for i := range all {
			if all[i].ID != id {
				continue
			}
			was = ctl.PresetRules(all[i])
			if !slices.ContainsFunc(add, func(r string) bool { return !slices.Contains(was, r) }) {
				return nil, errHad
			}
			all[i].Lines = append(all[i].Lines, v)
			p = all[i]
			return all, nil
		}
		return nil, errPresetGone
	})
	on := slices.Contains(ctl.LoadSettings(paths.Settings()).Awg2Presets, id)
	if errors.Is(err, errHad) {
		return 0, true, !on, nil, nil
	}
	if err != nil || !on {
		return 0, false, !on, err, nil
	}
	n, closeErr = closeMoved([]string{ctl.PresetsProvider}, rulesMatch(changed(was, ctl.PresetRules(p))),
		func() bool { return ctl.PresetWritten(p, true) })
	return n, false, false, nil, closeErr
}

// handleLivePresets: the presets for the menu, in the page's language
func (s *Server) handleLivePresets(w http.ResponseWriter, r *http.Request) {
	type item struct {
		ID    string `json:"id"`
		Title string `json:"title"`
		On    bool   `json:"on"`
	}
	on := ctl.LoadSettings(paths.Settings()).Awg2Presets
	out := []item{}
	for _, p := range presets.Load() {
		out = append(out, item{p.ID, tr(lang(r), p.Title), slices.Contains(on, p.ID)})
	}
	writeJSON(w, out)
}

// liveReveal opens the folder a file is in, the file picked out; a var for
// tests, which must not start Explorer
var liveReveal = func(path string) error {
	cmd := exec.Command("explorer.exe")
	// "/select," and the path in quotes, as Explorer reads it: Go would put
	// the whole argument in quotes
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: `explorer.exe /select,"` + path + `"`}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Explorer answers 1 even when it did what it was asked
	go cmd.Wait()
	return nil
}

// actLiveReveal shows the file of the program behind a connection in its
// folder. The path is the one the core gave the row, not the page's.
func (s *Server) actLiveReveal(w http.ResponseWriter, r *http.Request) {
	path := s.live.pathOf(r.FormValue("id"))
	if path == "" {
		writeJSON(w, liveAnswer{false, tr(lang(r), "The core did not say where the program's file is")})
		return
	}
	if fi, err := os.Stat(path); err != nil || fi.IsDir() {
		writeJSON(w, liveAnswer{false, fmt.Sprintf(tr(lang(r), "The file is not there: %s"), path)})
		return
	}
	if err := liveReveal(path); err != nil {
		writeJSON(w, liveAnswer{false, err.Error()})
		return
	}
	writeJSON(w, liveAnswer{true, ""})
}
