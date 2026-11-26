package webui

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/netprocs"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
)

// The user's lists -- always direct, always via the tunnel, forbidden, via
// the second tunnel -- each hold sites, addresses and programs, one per line
// (see ctl.ParseEntry). Every one is the same block on its page.

// listFile: the user list behind each block, by the block's kind
var listFile = map[string]string{
	"direct": paths.DirectList, "tunnel": paths.TunnelList, "tunnel1": paths.Tunnel1List,
	"tunnel2": paths.Tunnel2List, "block": paths.BlockList, "awg2": paths.Awg2List,
}

// entryList: what a list's block shows
type entryList struct {
	V           *view
	Kind, Title string
	Hint        any // string, or trusted translated markup from view.TH
	Entries     []string
	Online      []netprocs.Proc
}

// readEntriesFile: a user list as the box shows it -- each line written the
// one way, once, sites first, then addresses, then programs. The direct list
// takes in the programs' list of its own from before, until it is saved.
// Read through readEntries, which keeps it in memory.
func readEntriesFile(name string) []string {
	lines := readList(paths.User(name))
	if name == paths.DirectList {
		for _, l := range readList(paths.User(paths.AppsList)) {
			if _, v, ok := strings.Cut(l, ","); ok {
				lines = append(lines, v) // "PROCESS-NAME,x.exe"
			}
		}
	}
	out, _ := normEntriesFor(lines, true)
	return out
}

// normEntries: the lines as they are kept, each once, sorted by kind; bad is
// the first line that is none of the kinds
func normEntries(lines []string) (out []string, issues []ctl.ListIssue) {
	return normEntriesFor(lines, false)
}

func normEntriesFor(lines []string, allowEnabledPresets bool) (out []string, issues []ctl.ListIssue) {
	d := ctl.ParseList(strings.Join(lines, "\n"), ctl.ListPolicy{AllowEnabledPresets: allowEnabledPresets})
	return d.Values(), d.Issues
}

// errListTooLarge: a list the service would not read -- it used to be saved,
// and was never taken
var errListTooLarge = errors.New("The list is too large: 4 MB at most")

// listBody: a user's list as its file holds it
func listBody(entries []string) []byte {
	var b strings.Builder
	b.WriteString("# sites, addresses and programs, one per line -- list maintained by the user\n")
	for _, e := range entries {
		b.WriteString(e + "\n")
	}
	return []byte(b.String())
}

func writeEntries(name string, entries []string) error {
	body := listBody(entries)
	if len(body) > ctl.UserListMax {
		return errListTooLarge
	}
	return paths.ReplaceFile(paths.User(name), body)
}

// entryMatch: the open connections these entries route. An address counts
// only for a connection that carries no name, as the core's rule asks no
// resolving.
func entryMatch(entries []string) func(ctl.Conn) bool {
	var names, apps []string
	var nets []netip.Prefix
	for _, e := range entries {
		kind, v, err := ctl.ParseEntry(e)
		switch {
		case err != nil:
		case kind == ctl.EntryName:
			names = append(names, v)
		case kind == ctl.EntryApp:
			apps = append(apps, v)
		default:
			if p, err := netip.ParsePrefix(v); err == nil {
				nets = append(nets, p)
			} else if a, err := netip.ParseAddr(v); err == nil {
				nets = append(nets, netip.PrefixFrom(a, a.BitLen()))
			}
		}
	}
	return func(c ctl.Conn) bool {
		for _, a := range apps {
			if strings.EqualFold(a, c.Process) || strings.EqualFold(a, c.ProcessPath) {
				return true
			}
		}
		if c.Host == "" {
			a, err := netip.ParseAddr(c.IP)
			for _, p := range nets {
				if err == nil && p.Contains(a.Unmap()) {
					return true
				}
			}
			return false
		}
		for _, n := range names {
			if ctl.MatchDomainRule(n, c.Host) {
				return true
			}
		}
		return false
	}
}

// enabledPresetsSourceMatch matches the currently enabled presets behind the
// virtual enabled_presets row.
func enabledPresetsSourceMatch() func(ctl.Conn) bool {
	set := loadSettings()
	on := map[string]bool{}
	for _, id := range set.Awg2Presets {
		on[id] = true
	}
	var entries []string
	for _, p := range presets.Load() {
		if on[p.ID] {
			entries = append(entries, p.Lines...)
		}
	}
	entries, _ = normEntries(entries)
	return entryMatch(entries)
}

// saveEntries writes the user's copy of a list and closes what the change
// moved. err is the list's own, closeErr the connections'.
func (s *Server) saveEntries(name string, entries []string) (n int, err, closeErr error) {
	if err := paths.UserReady(); err != nil {
		return 0, err, nil
	}
	s.listMu.Lock()
	old := readEntries(name)
	was, rerr := os.ReadFile(paths.User(name))
	had := rerr == nil
	if rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
		s.listMu.Unlock()
		return 0, rerr, nil
	}
	err = writeEntries(name, entries)
	if err == nil && name == paths.DirectList {
		// the programs' list of its own is in the direct list now. One that
		// cannot go would go on routing its programs: the save is undone,
		// and "not saved" is so -- it used to stay, said not saved, with
		// the connections it moved left open.
		if rerr := os.Remove(paths.User(paths.AppsList)); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			err = rerr
			if had {
				paths.ReplaceFile(paths.User(name), was)
			} else {
				os.Remove(paths.User(name))
			}
		}
	}
	s.listMu.Unlock()
	if err != nil {
		return 0, err, nil
	}
	n, closeErr = closeEntriesChange(name, old, entries)
	return n, nil, closeErr
}

// closeEntriesChange moves connections affected by a list already written.
// The bundle importer writes several files first, then uses the same route
// transition logic as an ordinary Save for each changed list.
func closeEntriesChange(name string, old, entries []string) (int, error) {
	moved := changed(old, entries)
	isRule := func(s string) bool { return strings.EqualFold(s, ctl.EnabledPresets) }
	plain := slices.DeleteFunc(slices.Clone(moved), isRule)
	match := entryMatch(plain)
	oldRule, newRule := slices.ContainsFunc(old, isRule), slices.ContainsFunc(entries, isRule)
	providers := ctl.ListProviders(name)
	if oldRule != newRule {
		marker := enabledPresetsSourceMatch()
		byLine := match
		match = func(c ctl.Conn) bool { return byLine(c) || marker(c) }
		providers = append(providers, ctl.EnabledPresetsProvider)
		if serviceRunning() {
			ctl.SyncRoutesNow(apiAddr, ctl.SecretFromConfig(paths.Config()))
		}
	}
	return closeMoved(providers, match,
		func() bool { return ctl.Synced(name) })
}

// routeAllowsOutbound reports whether a connection that already took
// outbound still satisfies route. Expanding awg1 to awg1 -> awg2, for
// example, must not tear down a connection already using awg1.
func routeAllowsOutbound(route, outbound string) bool {
	direct := outbound == "DIRECT" || outbound == ctl.SplitOutbound
	switch route {
	case "direct":
		return direct
	case "awg1":
		return outbound == "awg1"
	case "awg2":
		return outbound == "awg2"
	case "awg1-awg2", "awg2-awg1":
		return outbound == "awg1" || outbound == "awg2"
	case "awg1-awg2-direct", "awg2-awg1-direct":
		return direct || outbound == "awg1" || outbound == "awg2"
	default: // block, or a row removed altogether
		return false
	}
}

func indexedRoutes(specs []routeSpec, files map[string][]string) map[string]string {
	out := map[string]string{}
	for _, spec := range specs {
		for _, entry := range files[spec.List] {
			key := strings.ToLower(entry)
			if _, exists := out[key]; !exists {
				out[key] = spec.ID
			}
		}
	}
	return out
}

// closeRouteEntriesChange reloads an atomic common-editor change and closes
// only connections whose actual outbound is no longer accepted by the new
// route. The old per-file comparison closed every matching connection twice
// when a row merely moved from one route file to another.
func closeRouteEntriesChange(specs []routeSpec, old, cur map[string][]string) (int, error) {
	before, after := indexedRoutes(specs, old), indexedRoutes(specs, cur)
	type transition struct{ entry, route string }
	var transitions []transition
	presetRoute, presetChanged := "", false
	seen := map[string]bool{}
	for entry, oldRoute := range before {
		seen[entry] = true
		newRoute := after[entry]
		if oldRoute == newRoute {
			continue
		}
		if strings.EqualFold(entry, ctl.EnabledPresets) {
			presetRoute, presetChanged = newRoute, true
		} else {
			transitions = append(transitions, transition{entry, newRoute})
		}
	}
	for entry, newRoute := range after {
		if seen[entry] {
			continue
		}
		if strings.EqualFold(entry, ctl.EnabledPresets) {
			presetRoute, presetChanged = newRoute, true
		} else {
			transitions = append(transitions, transition{entry, newRoute})
		}
	}
	// With no override, presets use their strict default order. Both tunnel
	// outbounds remain valid; direct never does.
	if presetChanged && presetRoute == "" {
		presetRoute = "awg1-awg2"
	}

	var providers, changedFiles []string
	for _, spec := range specs {
		if len(changed(old[spec.List], cur[spec.List])) == 0 {
			continue
		}
		changedFiles = append(changedFiles, spec.List)
		providers = append(providers, ctl.ListProviders(spec.List)...)
	}
	if len(changedFiles) == 0 {
		return 0, nil
	}
	if presetChanged {
		providers = append(providers, ctl.EnabledPresetsProvider)
		if serviceRunning() {
			ctl.SyncRoutesNow(apiAddr, ctl.SecretFromConfig(paths.Config()))
		}
	}
	presetMatch := enabledPresetsSourceMatch()
	match := func(c ctl.Conn) bool {
		for _, move := range transitions {
			if entryMatch([]string{move.entry})(c) && !routeAllowsOutbound(move.route, c.Outbound) {
				return true
			}
		}
		return presetChanged && presetMatch(c) && !routeAllowsOutbound(presetRoute, c.Outbound)
	}
	return closeMoved(providers, match, func() bool {
		for _, file := range changedFiles {
			if !ctl.Synced(file) {
				return false
			}
		}
		return true
	})
}

// actList saves one of the lists; "add" puts a program from the online list
// into it and saves at once -- it used to land in the field only, waiting
// for a Save that was easy to miss.
func (s *Server) actList(w http.ResponseWriter, r *http.Request) {
	kind := r.FormValue("kind")
	if kind == "tunnel" {
		s.actRouteList(w, r)
		return
	}
	name := listFile[kind]
	if name == "" {
		http.Error(w, "unknown list", http.StatusBadRequest)
		return
	}
	page := "lists"
	if kind == "awg2" {
		page = "awg2"
	}
	text := r.FormValue("entries")
	if r.FormValue("op") == "add" {
		a := strings.TrimSpace(r.FormValue("add"))
		if a == "" {
			s.refuse(w, r, page, kind, splitLines(text), tr(lang(r), "Pick a program from the list first"))
			return
		}
		if text = strings.TrimRight(text, "\r\n"); text != "" {
			text += "\n"
		}
		text += a
	}
	doc := ctl.ParseList(text, ctl.ListPolicy{AllowEnabledPresets: listFile[kind] != ""})
	entries := doc.Values()
	if len(doc.Issues) != 0 {
		s.refuse(w, r, page, kind, splitLines(text), listIssues(lang(r), doc.Issues))
		return
	}
	// what was pasted stays in the box to be cut down
	if len(listBody(entries)) > ctl.UserListMax {
		s.refuse(w, r, page, kind, splitLines(text), tr(lang(r), errListTooLarge.Error()))
		return
	}
	n, err, cerr := s.saveEntries(name, entries)
	ok, msg := saved(r, err, n, cerr)
	if err == nil {
		msg = listParseReport(lang(r), msg, doc, redundantListEntries(entries), shadowedListEntries(kind, entries))
	}
	s.part(w, r, page, "list-"+kind, ok, msg)
}

// actRouteList saves the common routing-rules editor. The hidden routes field
// has one route ID for every visible line in entries.
func (s *Server) actRouteList(w http.ResponseWriter, r *http.Request) {
	text, routeText := r.FormValue("entries"), r.FormValue("routes")
	if r.FormValue("op") == "add" {
		a := strings.TrimSpace(r.FormValue("add"))
		if a == "" {
			s.refuse(w, r, "lists", "tunnel", splitLines(text), tr(lang(r), "Pick a program from the list first"))
			return
		}
		if text = strings.TrimRight(text, "\r\n"); text != "" {
			text += "\n"
			routeText = strings.TrimRight(routeText, "\r\n") + "\n"
		}
		text += a
		def := loadSettings().DefaultTunnel
		if def == ctl.DefaultTunnel12 {
			routeText += "awg1-awg2"
		} else {
			routeText += "awg2-awg1"
		}
	}
	raw, rawRoutes := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n"), strings.Split(strings.ReplaceAll(routeText, "\r\n", "\n"), "\n")
	byFile := map[string][]string{}
	shown, shownRoutes := []string{}, []string{}
	valid := map[string]string{}
	for _, spec := range ruleSpecs {
		valid[spec.ID] = spec.List
	}
	seen := map[string]bool{}
	for i, line := range raw {
		route := ""
		if i < len(rawRoutes) {
			route = strings.TrimSpace(rawRoutes[i])
		}
		file := valid[route]
		doc := ctl.ParseList(line, ctl.ListPolicy{AllowEnabledPresets: file != ""})
		if len(doc.Issues) != 0 {
			s.refuse(w, r, "lists", "tunnel", raw, listIssues(lang(r), doc.Issues))
			return
		}
		values := doc.Values()
		if len(values) == 0 {
			continue
		}
		if file == "" {
			s.refuse(w, r, "lists", "tunnel", raw, tr(lang(r), "Choose a route for every entry"))
			return
		}
		for _, entry := range values {
			key := strings.ToLower(entry)
			if seen[key] {
				continue
			}
			seen[key] = true
			byFile[file] = append(byFile[file], entry)
			shown, shownRoutes = append(shown, entry), append(shownRoutes, route)
		}
	}
	if len(listBody(shown)) > ctl.UserListMax {
		s.refuse(w, r, "lists", "tunnel", raw, tr(lang(r), errListTooLarge.Error()))
		return
	}
	moved, err, closeErr := s.saveRouteEntries(byFile)
	ok, msg := saved(r, err, moved, closeErr)
	v := &view{Lang: lang(r), Page: "lists", Path: back(r), St: s.status(), Msg: &flash{ok, msg}}
	d := listsData()
	d.TunnelEntries, d.Routes = shown, shownRoutes
	v.Data = d
	render(w, v, "list-tunnel")
}

// saveRouteEntries commits the common editor's backing files as one unit.
// A row moved between files must never disappear or retain two routes when a
// later write fails. Connection moves happen only after every file is durable.
func (s *Server) saveRouteEntries(byFile map[string][]string) (moved int, err, closeErr error) {
	if err := paths.UserReady(); err != nil {
		return 0, err, nil
	}
	s.listMu.Lock()
	old := map[string][]string{}
	var snapshots []fileSnapshot
	for _, spec := range ruleSpecs {
		old[spec.List] = readEntries(spec.List)
		snap, snapErr := takeSnapshot(paths.User(spec.List))
		if snapErr != nil {
			s.listMu.Unlock()
			return 0, snapErr, nil
		}
		snapshots = append(snapshots, snap)
	}
	apps, snapErr := takeSnapshot(paths.User(paths.AppsList))
	if snapErr != nil {
		s.listMu.Unlock()
		return 0, snapErr, nil
	}
	snapshots = append(snapshots, apps)
	rollback := func(cause error) error {
		if restoreErr := restoreSnapshots(snapshots); restoreErr != nil {
			return errors.Join(cause, fmt.Errorf("rollback: %w", restoreErr))
		}
		return cause
	}
	for _, spec := range ruleSpecs {
		if err := writeEntries(spec.List, byFile[spec.List]); err != nil {
			err = rollback(err)
			s.listMu.Unlock()
			return 0, err, nil
		}
	}
	if err := paths.RemoveRetry(paths.User(paths.AppsList)); err != nil {
		err = rollback(err)
		s.listMu.Unlock()
		return 0, err, nil
	}
	s.listMu.Unlock()

	moved, closeErr = closeRouteEntriesChange(ruleSpecs, old, byFile)
	return moved, nil, closeErr
}

type listShadow struct{ entry, list string }

type listRedundant struct{ entry, coveredBy string }

func redundantListEntries(entries []string) []listRedundant {
	var out []listRedundant
	for i, entry := range entries {
		if strings.EqualFold(entry, ctl.EnabledPresets) {
			continue
		}
		for j, wider := range entries {
			if i == j || strings.EqualFold(wider, ctl.EnabledPresets) {
				continue
			}
			_, in := liveOverlap(wider)(entry)
			if !in {
				continue
			}
			_, reverse := liveOverlap(entry)(wider)
			if !reverse || j < i {
				out = append(out, listRedundant{entry: entry, coveredBy: wider})
				break
			}
		}
	}
	return out
}

func shadowedListEntries(kind string, entries []string) []listShadow {
	var out []listShadow
	for _, entry := range entries {
		if strings.EqualFold(entry, ctl.EnabledPresets) {
			continue
		}
		for _, higher := range []string{"block", "tunnel", "tunnel1", "tunnel2", "direct", "awg2"} {
			if liveRank(higher, 0) >= liveRank(kind, 0) {
				continue
			}
			covered := false
			for _, line := range readEntries(listFile[higher]) {
				if _, in := liveOverlap(line)(entry); in {
					covered = true
					break
				}
			}
			if covered {
				out = append(out, listShadow{entry: entry, list: liveListNames[higher]})
				break
			}
		}
	}
	return out
}

func listParseReport(l, saved string, doc ctl.ListDocument, redundant []listRedundant, shadows []listShadow) string {
	var notes []string
	if n := len(doc.Normalized); n > 0 {
		shown := make([]string, 0, min(3, n))
		for _, change := range doc.Normalized[:min(3, n)] {
			shown = append(shown, shortListText(change.Raw)+" → "+shortListText(change.Value))
		}
		more := ""
		if rest := n - len(shown); rest > 0 {
			more = fmt.Sprintf(" +%d", rest)
		}
		notes = append(notes, fmt.Sprintf(tr(l, "normalized: %d (%s)"), n, strings.Join(shown, "; ")+more))
	}
	if n := len(doc.Duplicates); n > 0 {
		notes = append(notes, fmt.Sprintf(tr(l, "duplicates removed: %d"), n))
	}
	if len(redundant) > 0 {
		shown := make([]string, 0, min(3, len(redundant)))
		for _, r := range redundant[:min(3, len(redundant))] {
			shown = append(shown, r.entry+" ← "+r.coveredBy)
		}
		more := ""
		if n := len(redundant) - len(shown); n > 0 {
			more = fmt.Sprintf(" +%d", n)
		}
		notes = append(notes, fmt.Sprintf(tr(l, "redundant inside the list: %d (%s)"), len(redundant), strings.Join(shown, "; ")+more))
	}
	if len(shadows) > 0 {
		shown := make([]string, 0, min(3, len(shadows)))
		for _, s := range shadows[:min(3, len(shadows))] {
			shown = append(shown, s.entry+" — «"+tr(l, s.list)+"»")
		}
		more := ""
		if n := len(shadows) - len(shown); n > 0 {
			more = fmt.Sprintf(" +%d", n)
		}
		notes = append(notes, fmt.Sprintf(tr(l, "shadowed by higher-priority lists: %d (%s)"), len(shadows), strings.Join(shown, "; ")+more))
	}
	if len(notes) == 0 {
		return saved
	}
	return saved + "; " + strings.Join(notes, "; ")
}

func shortListText(s string) string {
	const limit = 48
	r := []rune(s)
	if len(r) <= limit {
		return s
	}
	return string(r[:limit-1]) + "…"
}

func listIssues(l string, issues []ctl.ListIssue) string {
	const maxShown = 5
	shown := issues
	if len(shown) > maxShown {
		shown = shown[:maxShown]
	}
	parts := make([]string, 0, len(shown)+1)
	for _, issue := range shown {
		line := fmt.Sprintf(tr(l, "line %d: %q is neither a site, an address nor a program"), issue.Line, issue.Raw)
		var reason string
		switch {
		case errors.Is(issue.Err, ctl.ErrListEnabledPresetsScope):
			reason = tr(l, "enabled_presets is allowed only in Routing rules")
		case errors.Is(issue.Err, ctl.ErrListRuleFields):
			reason = tr(l, "the rule has the wrong number of fields")
		case errors.Is(issue.Err, ctl.ErrListIPOption):
			reason = tr(l, "the IP rule has an unsupported option")
		case errors.Is(issue.Err, ctl.ErrListHostsAlias):
			reason = tr(l, "a hosts alias is not a domain")
		case errors.Is(issue.Err, ctl.ErrListProgramComma):
			reason = tr(l, "commas in a program name are not supported")
		case errors.Is(issue.Err, ctl.ErrListDomainLabel):
			reason = tr(l, "a domain label is longer than 63 bytes")
		case errors.Is(issue.Err, ctl.ErrListDomainName):
			reason = tr(l, "a domain name is longer than 253 bytes")
		}
		if reason != "" {
			line += ": " + reason
		}
		parts = append(parts, line)
	}
	if rest := len(issues) - len(shown); rest > 0 {
		parts = append(parts, fmt.Sprintf(tr(l, "and %d more errors"), rest))
	}
	return strings.Join(parts, "; ") + ": " + tr(l, "nothing saved")
}

// refuse: the block again with what was sent still in the box -- the saved
// list in its place lost what the user had typed -- and why it was not saved
func (s *Server) refuse(w http.ResponseWriter, r *http.Request, page, kind string, lines []string, msg string) {
	v := &view{Lang: lang(r), Page: page, Path: back(r), St: s.status(), Msg: &flash{false, msg}}
	switch d := s.pageData(r, page, v).(type) {
	case lists:
		switch kind {
		case "direct":
			d.Direct = lines
		case "tunnel":
			d.TunnelEntries = lines
			d.Routes = splitLines(r.FormValue("routes"))
		case "block":
			d.Block = lines
		}
		v.Data = d
	case awg2:
		d.Hosts = lines
		v.Data = d
	}
	render(w, v, "list-"+kind)
}
