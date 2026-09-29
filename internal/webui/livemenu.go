package webui

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
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

// errUnchanged: the presets are as they were -- nothing is written
var errUnchanged = errors.New("unchanged")

// liveMove: what a menu action came to
type liveMove struct {
	had      bool      // the line was where it was sent already
	outOf    []liveOut // the lines taken out of the lists and presets
	still    []string  // presets switched on that take it all the same, above where it went
	off      bool      // it went to a preset switched off, which routes nothing
	moved    int
	closeErr error
}

// liveOut: the lines taken out of a list or a preset, by its name
type liveOut struct {
	name  string
	lines []string
}

// actLiveAdd sends one line to a list or a preset, and out of the places
// that would route it otherwise -- see moveLine. The connections it moves
// are closed, as a list's save does.
func (s *Server) actLiveAdd(w http.ResponseWriter, r *http.Request) {
	l := lang(r)
	to, id, entry := r.FormValue("to"), r.FormValue("preset"), strings.TrimSpace(r.FormValue("entry"))
	var name string
	switch {
	case to == "preset":
		p, ok := findPreset(presets.Load(), id)
		if !ok {
			writeJSON(w, liveAnswer{false, tr(l, errPresetGone.Error())})
			return
		}
		name = tr(l, p.Title)
	case listFile[to] != "":
		name = tr(l, liveListNames[to])
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
		writeJSON(w, liveAnswer{false, tr(l, err.Error())})
		return
	}
	mv, err := s.moveLine(to, id, v)
	if err != nil {
		writeJSON(w, liveAnswer{false, tr(l, err.Error())})
		return
	}
	quote := func(names []string) string {
		q := make([]string, len(names))
		for i, n := range names {
			q[i] = "«" + tr(l, n) + "»"
		}
		slices.Sort(q)
		return strings.Join(q, ", ")
	}
	// where it was taken out of, and what, when it is more than the line
	// itself: a wider line there routed it too
	outs := make([]string, 0, len(mv.outOf))
	for _, o := range mv.outOf {
		out := "«" + tr(l, o.name) + "»"
		if len(o.lines) != 1 || !strings.EqualFold(o.lines[0], v) {
			shown := o.lines[:min(len(o.lines), 5)]
			out += ": " + strings.Join(shown, ", ")
			if n := len(o.lines) - len(shown); n > 0 {
				out += fmt.Sprintf(" +%d", n)
			}
		}
		outs = append(outs, out)
	}
	slices.Sort(outs)
	var msg string
	switch {
	case mv.had:
		msg = fmt.Sprintf(tr(lang(r), "“%s” has %s already"), name, v)
		if mv.moved > 0 {
			msg += fmt.Sprintf(tr(lang(r), "; open connections moved: %d"), mv.moved)
		}
	case mv.moved > 0:
		msg = fmt.Sprintf(tr(lang(r), "Added to “%s”: %s; open connections moved: %d"), name, v, mv.moved)
	default:
		msg = fmt.Sprintf(tr(lang(r), "Added to “%s”: %s"), name, v)
	}
	if len(mv.outOf) > 0 {
		msg += fmt.Sprintf(tr(lang(r), " (taken out of %s)"), strings.Join(outs, "; "))
	}
	if mv.off {
		msg += tr(lang(r), ". The preset is off: it routes nothing until it is switched on")
	}
	// the auto-switch mode stands above the lists: said, not left to find
	switch set := ctl.LoadSettings(paths.Settings()); {
	case (to == "awg2" || to == "preset") && !set.Awg2Active():
		msg += tr(lang(r), ". The second tunnel is switched off in this mode: this routes nothing until it is switched on")
	case set.Mode() == ctl.ModeTunnel && to == "direct":
		msg += tr(lang(r), ". Tunnel only is on: Always direct is set aside until auto-switch is on")
	}
	ok := true
	if len(mv.still) > 0 {
		// a preset takes it by a wider line, which is not the menu's to cut
		msg += fmt.Sprintf(tr(lang(r), ". But %s stands above the lists and takes it all the same while switched on"), quote(mv.still))
		ok = false
	}
	if mv.closeErr != nil {
		msg += ". " + tr(lang(r), "Saved, but the open connections were not moved: they keep their old route until they reconnect")
		ok = false
	}
	writeJSON(w, liveAnswer{ok, msg})
}

// moveLine sends v to the list named to, or to the preset id, and takes it
// out of the places that would route it otherwise. A list whose rules stand
// before the one v went to loses every line routing what v routes -- the
// same, a narrower one, and a wider one: "+.example.com" in "Always via
// tunnel" would keep api.example.com sent direct in the tunnel. A list after
// it loses the same line and the narrower ones only: a wider line there
// routes other names, and v's before it. The presets switched on stand
// before "Always via tunnel" and a direct site or address, and lose the same
// line and the narrower ones; a wider line of theirs is named. The lists and
// the presets are read and written as one: under the lists' lock, inside
// the presets' change, and a file failing to write puts back the ones
// written before it.
func (s *Server) moveLine(to, id, v string) (mv liveMove, err error) {
	kind, _, _ := ctl.ParseEntry(v)
	same := func(x string) bool { return strings.EqualFold(x, v) }
	rule := ctl.PresetRules(presets.Preset{Lines: []string{v}})
	within, overlap := inside(v), liveOverlap(v)
	rank := liveRank(to, kind)
	above := liveRank("preset", kind) < rank
	on := ctl.LoadSettings(paths.Settings()).Awg2Presets
	var (
		lists   = map[string][]string{} // the lists that change, as they will be
		moved   []string                // the lines that route anew
		rules   []string                // the rules of the presets switched on that route anew
		written []presets.Preset        // the presets switched on that change, as they will be
		undo    func()
	)
	s.listMu.Lock()
	err = presets.Update(func(all []presets.Preset) ([]presets.Preset, error) {
		for k, name := range listFile {
			cur := readEntries(name)
			if k == to {
				if slices.ContainsFunc(cur, same) {
					mv.had = true
				} else {
					lists[name], _ = normEntries(append(cur, v))
					moved = append(moved, v)
				}
				continue
			}
			before := liveRank(k, kind) < rank
			var out []string
			rest := slices.DeleteFunc(slices.Clone(cur), func(x string) bool {
				over, in := overlap(x)
				if in || before && over {
					out = append(out, x)
					return true
				}
				return false
			})
			if len(out) > 0 {
				lists[name] = rest
				mv.outOf = append(mv.outOf, liveOut{liveListNames[k], out})
				moved = append(moved, out...)
			}
		}
		found, changedAny := false, false
		for i := range all {
			p := &all[i]
			isOn := slices.Contains(on, p.ID)
			was := ctl.PresetRules(*p)
			switch {
			case to == "preset" && p.ID == id:
				found = true
				mv.off = !isOn
				if !slices.ContainsFunc(rule, func(r string) bool { return !slices.Contains(was, r) }) {
					mv.had = true
					continue
				}
				p.Lines = append(slices.Clone(p.Lines), v)
			case above && isOn:
				var out []string
				lines := slices.DeleteFunc(slices.Clone(p.Lines), func(l string) bool {
					if within(l) {
						out = append(out, l)
						return true
					}
					return false
				})
				cut := len(out) > 0
				if cut {
					p.Lines = lines
					mv.outOf = append(mv.outOf, liveOut{p.Title, out})
				}
				// a wider line of it takes it still
				if rulesMatch(ctl.PresetRules(*p))(liveConnOf(kind, v)) {
					mv.still = append(mv.still, p.Title)
				}
				if !cut {
					continue
				}
			default:
				continue
			}
			changedAny = true
			if isOn {
				rules = append(rules, changed(was, ctl.PresetRules(*p))...)
				written = append(written, *p)
			}
		}
		if to == "preset" && !found {
			return nil, errPresetGone
		}
		// the lists are written here, the presets' lock held: they go with
		// the presets, or not at all
		var err error
		if undo, err = writeLists(lists); err != nil {
			return nil, err
		}
		if !changedAny {
			return nil, errUnchanged
		}
		return all, nil
	})
	switch {
	case errors.Is(err, errUnchanged):
		err = nil
	case err != nil && undo != nil:
		undo() // the presets were not written: the lists go back
	}
	s.listMu.Unlock()
	if err != nil {
		return liveMove{}, err
	}

	var providers []string
	for name := range lists {
		providers = append(providers, ctl.ListProviders(name)...)
	}
	if len(written) > 0 {
		providers = append(providers, ctl.PresetsProvider)
	}
	if len(providers) == 0 {
		return mv, nil
	}
	byLine, byRule := entryMatch(moved), rulesMatch(rules)
	mv.moved, mv.closeErr = closeMoved(providers, func(c ctl.Conn) bool { return byLine(c) || byRule(c) }, func() bool {
		for name := range lists {
			if !ctl.Synced(name) {
				return false
			}
		}
		for _, p := range written {
			if !ctl.PresetWritten(p, true) {
				return false
			}
		}
		return true
	})
	return mv, nil
}

// liveRank: where a list's rules of a kind stand among the core's rules --
// the lower, the sooner they route (see awgconf): Forbidden, the programs
// sent direct, the second tunnel (its presets, then its own list), Always
// via tunnel, the sites and addresses sent direct
func liveRank(list string, kind int) int {
	switch list {
	case "block":
		return 0
	case "direct":
		if kind == ctl.EntryApp {
			return 1
		}
		return 4
	case "preset", "awg2":
		return 2
	case "tunnel":
		return 3
	}
	return 5
}

// liveOverlap: how a list's line stands to the line v, as the lists read
// them -- over: it routes some of what v routes; in: it routes nothing v
// does not. A site: "example.com" is the name alone, "+.example.com" the
// domain and everything under it. An address or a network: the networks
// overlap, or one holds the other. A program: by its name every copy, by its
// path that copy. Lines of other kinds route other connections.
func liveOverlap(v string) func(line string) (over, in bool) {
	kind, val, _ := ctl.ParseEntry(v)
	whole := kind == ctl.EntryName && strings.IndexAny(val, "+.*") == 0
	name := strings.TrimLeft(val, "+.*")
	net := entryPrefix(val)
	return func(line string) (bool, bool) {
		k, x, err := ctl.ParseEntry(line)
		if err != nil || k != kind {
			return false, false
		}
		switch kind {
		case ctl.EntryName:
			y := strings.TrimLeft(x, "+.*")
			wide := strings.IndexAny(x, "+.*") == 0
			in := y == name && (whole || !wide) || whole && strings.HasSuffix(y, "."+name)
			return in || ctl.MatchDomainRule(x, name), in
		case ctl.EntryIP:
			n := entryPrefix(x)
			if !net.IsValid() || !n.IsValid() {
				return false, false
			}
			return net.Overlaps(n), net.Bits() <= n.Bits() && net.Contains(n.Addr())
		}
		if !strings.EqualFold(filepath.Base(x), filepath.Base(val)) {
			return false, false
		}
		path, pathV := strings.ContainsAny(x, `\/`), strings.ContainsAny(val, `\/`)
		in := strings.EqualFold(x, val) || !pathV && path
		return in || !path || !pathV, in
	}
}

// inside: whether a preset's line routes nothing the line v does not route
// -- the same, or narrower: a name under v's whole domain, a network inside
// v's. The menu takes those out of a preset; a wider one is not its to cut.
func inside(v string) func(line string) bool {
	kind, val, _ := ctl.ParseEntry(v)
	whole := kind == ctl.EntryName && strings.IndexAny(val, "+.*") == 0
	name := strings.TrimLeft(val, "+.*")
	net := entryPrefix(val)
	return func(line string) bool {
		k, x, err := ctl.ParseEntry(line)
		if err != nil || k != kind {
			return false
		}
		switch kind {
		case ctl.EntryName:
			y := strings.TrimLeft(x, "+.*")
			return y == name || whole && strings.HasSuffix(y, "."+name)
		case ctl.EntryIP:
			n := entryPrefix(x)
			return net.IsValid() && n.IsValid() && net.Bits() <= n.Bits() && net.Contains(n.Addr())
		}
		return strings.EqualFold(x, val)
	}
}

// entryPrefix: an address or a network of a list, as a network
func entryPrefix(s string) netip.Prefix {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen())
	}
	return netip.Prefix{}
}

// liveConnOf: a connection a line routes, to ask a preset whether it takes it
func liveConnOf(kind int, v string) ctl.Conn {
	switch kind {
	case ctl.EntryName:
		return ctl.Conn{Host: strings.TrimLeft(v, "+.*")}
	case ctl.EntryIP:
		return ctl.Conn{IP: entryPrefix(v).Addr().String()}
	}
	return ctl.Conn{Process: filepath.Base(v), ProcessPath: v}
}

// writeLists writes the user's lists given, each whole, in a fixed order.
// One failing, the ones written before it are put back as they were; the
// undo it returns puts them all back. The direct list takes in the
// programs' list of its own from before, which goes with it.
func writeLists(next map[string][]string) (func(), error) {
	type file struct {
		path string
		data []byte
		had  bool
	}
	var done []file
	undo := func() {
		for i := len(done) - 1; i >= 0; i-- {
			f := done[i]
			if f.had {
				paths.ReplaceFile(f.path, f.data)
			} else {
				os.Remove(f.path)
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(next)) {
		files := []string{paths.User(name)}
		if name == paths.DirectList {
			files = append(files, paths.User(paths.AppsList))
		}
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				undo()
				return nil, err
			}
			done = append(done, file{f, data, err == nil})
		}
		err := writeEntries(name, next[name])
		if err == nil && name == paths.DirectList {
			if rerr := os.Remove(paths.User(paths.AppsList)); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
				err = rerr
			}
		}
		if err != nil {
			undo()
			return nil, err
		}
	}
	return undo, nil
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
