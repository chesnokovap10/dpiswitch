package webui

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/idna"

	"dpiswitch/internal/awgconf"
	"dpiswitch/internal/ctl"
	"dpiswitch/internal/netprocs"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
	"dpiswitch/internal/probe"
)

// --- overview ---

type overview struct {
	Events []string
	// the first tunnel's DNS: the settings' own, else the .conf's -- the
	// .conf's was shown whatever the settings said
	DNS    string
	DNSSet bool // from the settings
}

var logDate = regexp.MustCompile(`^\d{4}/\d\d/\d\d `)

func overviewData(v *view) overview {
	o := overview{}
	if set := ctl.LoadSettings(paths.Settings()); len(set.TunnelDNS) > 0 {
		o.DNS, o.DNSSet = strings.Join(set.TunnelDNS, ", "), true
	} else if c, err := awgconf.ParseFile(paths.SourceConf()); err == nil {
		o.DNS = strings.Join(c.DNS(), ", ")
	}
	if t, err := tail(paths.ServiceLog(), 16); err == nil && t != "" {
		for _, l := range strings.Split(t, "\n") {
			o.Events = append(o.Events, logDate.ReplaceAllString(l, ""))
		}
	}
	return o
}

// --- verdicts ---

type vrow struct {
	Domain  string
	Uni     string // a name in Russian or other letters, as it is written; Domain is its punycode
	Addr    bool   // a bare address with a verdict of its own
	Fam     int    // a whole domain: its clean subdomains
	Verdict string
	Reason  string
	Decided time.Time
	Expires time.Time
	Idle    bool // see ctl.DirectEntry.Idle
	Node    string
}

type verdicts struct {
	Cat    string
	Q      string
	Rows   []vrow
	Counts map[string]int
}

// Query: the tab and the filter for the parts that refresh themselves. It
// was written into their address unescaped: "c++" came back as "c  ", and
// "50%" as no filter at all.
func (d verdicts) Query() string { return url.Values{"cat": {d.Cat}, "q": {d.Q}}.Encode() }

// unicodeName: a punycode name as it is written, "" for any other
func unicodeName(dom string) string {
	if !strings.Contains(dom, "xn--") {
		return ""
	}
	u, err := idna.ToUnicode(dom)
	if err != nil || u == dom {
		return ""
	}
	return u
}

// verdictCats: the verdict table's tabs and what goes under each
var verdictCats = map[string]func(v probe.Verdict) bool{
	"blocked": func(v probe.Verdict) bool {
		switch v {
		case probe.BlockedTCP, probe.BlockedTLS, probe.BlockedQUIC, probe.MITM, probe.ContentDiff:
			return true
		}
		return false
	},
	"slow":    func(v probe.Verdict) bool { return v == probe.Slower },
	"unknown": func(v probe.Verdict) bool { return v == probe.Inconcl },
}

func verdictsData(r *http.Request) verdicts {
	d := verdicts{Cat: r.URL.Query().Get("cat"), Q: strings.TrimSpace(r.URL.Query().Get("q"))}
	if _, ok := verdictCats[d.Cat]; !ok {
		d.Cat = "direct"
	}
	snap := ctl.LoadCached(paths.State())
	d.Counts = map[string]int{"direct": len(snap.Details)}
	for _, o := range snap.Others {
		for k, in := range verdictCats {
			if in(probe.Verdict(o.Verdict)) {
				d.Counts[k]++
			}
		}
	}
	// a row is found by what it shows: a whole domain by its "+.", a name
	// in Russian letters by them as well as by its punycode
	q := strings.ToLower(d.Q)
	keep := func(r vrow) bool {
		return q == "" || strings.Contains(r.Domain, q) || strings.Contains(r.Uni, q)
	}
	row := func(e ctl.DirectEntry) vrow {
		r := vrow{Domain: e.Domain, Verdict: e.Verdict, Reason: e.Reason,
			Decided: e.DecidedAt, Expires: e.ExpiresAt, Idle: e.Idle, Node: e.TestedIP}
		if strings.HasPrefix(r.Domain, "@") {
			r.Domain, r.Addr = r.Domain[1:], true
		}
		r.Uni = unicodeName(r.Domain)
		return r
	}
	add := func(r vrow) {
		if keep(r) {
			d.Rows = append(d.Rows, r)
		}
	}
	if d.Cat == "direct" {
		for _, f := range snap.Families {
			r := vrow{Domain: "+." + f.Domain, Fam: f.Clean}
			if u := unicodeName(f.Domain); u != "" {
				r.Uni = "+." + u
			}
			add(r)
		}
		for _, e := range snap.Details {
			add(row(e))
		}
		return d
	}
	for _, e := range snap.Others {
		if verdictCats[d.Cat](probe.Verdict(e.Verdict)) {
			add(row(e))
		}
	}
	return d
}

// VName: a verdict in words.
func (v *view) VName(verdict string) string {
	switch probe.Verdict(verdict) {
	case probe.BlockedTCP:
		return v.T("connection cut")
	case probe.BlockedTLS:
		return v.T("TLS cut by site name")
	case probe.BlockedQUIC:
		return v.T("QUIC blocked")
	case probe.MITM:
		return v.T("certificate spoofed")
	case probe.ContentDiff:
		return v.T("response tampered")
	case probe.Slower:
		return v.T("slower than tunnel")
	case probe.Inconcl:
		return v.T("unverified")
	}
	return verdict
}

// --- routing lists ---

type lists struct {
	Direct, Tunnel, Block []string
	Online                []netprocs.Proc
}

func listsData() lists {
	l := lists{Direct: readEntries(paths.DirectList), Tunnel: readEntries(paths.TunnelList),
		Block: readEntries(paths.BlockList)}
	l.Online = onlineApps(append(append(append([]string{}, l.Direct...), l.Tunnel...), l.Block...))
	return l
}

// onlineApps: the programs with open sockets, less the ones already listed
func onlineApps(listed []string) []netprocs.Proc {
	have := map[string]bool{}
	for _, a := range listed {
		have[strings.ToLower(a)] = true
	}
	// one row per name: the list adds a program by name, and two copies of
	// one program in different folders were two rows adding the same line
	var out []netprocs.Proc
	at := map[string]int{}
	for _, p := range netprocs.Active("mihomo.exe", "dpiswitch.exe") {
		name := strings.ToLower(p.Name)
		if have[name] || have[strings.ToLower(p.Path)] {
			continue
		}
		if i, ok := at[name]; ok {
			out[i].Conns += p.Conns
			continue
		}
		at[name] = len(out)
		out = append(out, p)
	}
	return out
}

// --- second tunnel ---

type preset struct {
	presets.Preset
	Rules int
	On    bool
}

type awg2 struct {
	Presets []preset
	Hosts   []string
	Online  []netprocs.Proc
	// a preset's save refused: its dialog opens again on what was sent
	Draft *presetDraft
	// a shipped preset deleted or edited: there is something to put back
	Restorable bool
}

func awg2Data() awg2 {
	on := map[string]bool{}
	for _, id := range ctl.LoadSettings(paths.Settings()).Awg2Presets {
		on[id] = true
	}
	d := awg2{Hosts: readEntries(paths.Awg2List)}
	d.Online = onlineApps(d.Hosts)
	all := presets.Load()
	for _, p := range all {
		d.Presets = append(d.Presets, preset{Preset: p, Rules: len(ctl.PresetRules(p)), On: on[p.ID]})
	}
	d.Restorable = presets.Restorable(all)
	return d
}

// --- settings ---

type durOpt struct {
	Min   int
	Label string
}

type settings struct {
	S       ctl.Settings
	ConfDNS string
	Durs    []durOpt
	// the setting just changed, and what came of it: the message is shown
	// in that setting's row
	Field string
	Res   *flash
}

// MsgFor: the result to show in a setting's row, if it was the one changed
func (d settings) MsgFor(field string) *flash {
	if d.Field == field {
		return d.Res
	}
	return nil
}

var durs = []durOpt{{10, "10 min"}, {30, "30 min"}, {60, "1 h"}, {180, "3 h"}, {360, "6 h"},
	{480, "8 h"}, {720, "12 h"}, {1440, "1 day"}, {4320, "3 days"}, {10080, "7 days"}, {43200, "30 days"}}

func settingsData() settings {
	d := settings{S: ctl.LoadSettings(paths.Settings()), Durs: durs}
	if c, err := awgconf.ParseFile(paths.SourceConf()); err == nil {
		d.ConfDNS = strings.Join(c.DNS(), ", ")
	}
	return d
}

// DurOpts: the choices of a term the settings let it take, with a value set
// by hand in the file among them -- shown, not lost on the next save.
func (d settings) DurOpts(field string, cur int) []durOpt {
	lo, hi := d.S.TermRange(field)
	out := []durOpt{}
	added := false
	for _, o := range d.Durs {
		if o.Min < lo || o.Min > hi {
			continue
		}
		if !added && cur <= o.Min {
			if cur < o.Min {
				out = append(out, durOpt{cur, "" /* shown in minutes */})
			}
			added = true
		}
		out = append(out, o)
	}
	if !added {
		out = append(out, durOpt{cur, ""})
	}
	return out
}

// --- logs ---

type logs struct {
	Name string
	Text string
}

// logFiles: the log tabs. The controller runs inside the service and logs
// there; tray.log, in the user's profile, is the tray's own (see
// paths.TrayLog).
var logFiles = map[string]func() string{
	"service": paths.ServiceLog,
	"core":    paths.MihomoLog,
	"tray":    paths.TrayLog,
}

func logsData(r *http.Request) logs {
	d := logs{Name: r.URL.Query().Get("name")}
	if _, ok := logFiles[d.Name]; !ok {
		d.Name = "service"
	}
	t, err := tail(logFiles[d.Name](), 400)
	if err != nil || t == "" {
		t = "—"
	}
	d.Text = t
	return d
}
