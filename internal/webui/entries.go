package webui

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/netprocs"
	"dpiswitch/internal/paths"
)

// The user's lists -- always direct, always via the tunnel, forbidden, via
// the second tunnel -- each hold sites, addresses and programs, one per line
// (see ctl.ParseEntry). Every one is the same block on its page.

// listFile: the user list behind each block, by the block's kind
var listFile = map[string]string{
	"direct": paths.DirectList, "tunnel": paths.TunnelList, "block": paths.BlockList, "awg2": paths.Awg2List,
}

// entryList: what a list's block shows
type entryList struct {
	V                 *view
	Kind, Title, Hint string
	Entries           []string
	Online            []netprocs.Proc
}

// readEntries: a user list as the box shows it -- each line written the one
// way, once, sites first, then addresses, then programs. The direct list
// takes in the programs' list of its own from before, until it is saved.
func readEntries(name string) []string {
	lines := readList(paths.User(name))
	if name == paths.DirectList {
		for _, l := range readList(paths.User(paths.AppsList)) {
			if _, v, ok := strings.Cut(l, ","); ok {
				lines = append(lines, v) // "PROCESS-NAME,x.exe"
			}
		}
	}
	out, _ := normEntries(lines)
	return out
}

// normEntries: the lines as they are kept, each once, sorted by kind; bad is
// the first line that is none of the kinds
func normEntries(lines []string) (out []string, bad string) {
	type entry struct {
		kind int
		v    string
	}
	var es []entry
	seen := map[string]bool{}
	for _, l := range lines {
		kind, v, err := ctl.ParseEntry(l)
		if err != nil {
			if bad == "" {
				bad = strings.TrimSpace(l)
			}
			continue
		}
		if k := strings.ToLower(v); !seen[k] {
			seen[k] = true
			es = append(es, entry{kind, v})
		}
	}
	sort.SliceStable(es, func(i, j int) bool {
		if es[i].kind != es[j].kind {
			return es[i].kind < es[j].kind
		}
		return strings.ToLower(es[i].v) < strings.ToLower(es[j].v)
	})
	out = []string{}
	for _, e := range es {
		out = append(out, e.v)
	}
	return out, bad
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
	n, closeErr = closeMoved(ctl.ListProviders(name), entryMatch(changed(old, entries)),
		func() bool { return ctl.Synced(name) })
	return n, nil, closeErr
}

// actList saves one of the lists; "add" puts a program from the online list
// into it and saves at once -- it used to land in the field only, waiting
// for a Save that was easy to miss.
func (s *Server) actList(w http.ResponseWriter, r *http.Request) {
	kind := r.FormValue("kind")
	name := listFile[kind]
	if name == "" {
		http.Error(w, "unknown list", http.StatusBadRequest)
		return
	}
	page := "lists"
	if kind == "awg2" {
		page = "awg2"
	}
	lines := splitLines(r.FormValue("entries"))
	if r.FormValue("op") == "add" {
		a := strings.TrimSpace(r.FormValue("add"))
		if a == "" {
			s.refuse(w, r, page, kind, lines, tr(lang(r), "Pick a program from the list first"))
			return
		}
		lines = append(lines, a)
	}
	entries, bad := normEntries(lines)
	if bad != "" {
		s.refuse(w, r, page, kind, lines,
			fmt.Sprintf(tr(lang(r), "%q is neither a site, an address nor a program: nothing saved"), bad))
		return
	}
	// what was pasted stays in the box to be cut down
	if len(listBody(entries)) > ctl.UserListMax {
		s.refuse(w, r, page, kind, lines, tr(lang(r), errListTooLarge.Error()))
		return
	}
	n, err, cerr := s.saveEntries(name, entries)
	ok, msg := saved(r, err, n, cerr)
	s.part(w, r, page, "list-"+kind, ok, msg)
}

// refuse: the block again with what was sent still in the box -- the saved
// list in its place lost what the user had typed -- and why it was not saved
func (s *Server) refuse(w http.ResponseWriter, r *http.Request, page, kind string, lines []string, msg string) {
	s.fresh()
	v := &view{Lang: lang(r), Page: page, Path: back(r), St: s.status(), Msg: &flash{false, msg}}
	switch d := s.pageData(r, page, v).(type) {
	case lists:
		switch kind {
		case "direct":
			d.Direct = lines
		case "tunnel":
			d.Tunnel = lines
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
