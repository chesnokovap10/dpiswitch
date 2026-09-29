package ctl

import (
	"context"
	"log"
	"net/netip"
	"slices"
	"strings"
	"time"

	"dpiswitch/internal/paths"
)

// Turning auto-switch off takes effect within a second. The main loop reads
// the settings once a minute, and not at all while a cycle's probes run --
// and even once it emptied the lists, the connections already open kept
// going direct: the core routes a connection once, when it opens. A browser
// holds its connections for minutes, so the sites looked as if the setting
// had not taken, until a service restart cut everything.

// autoOff: auto-switch has been turned off, and the lists emptied. Shared by
// every copy of the Config (a nil one is never off): a cycle started before
// holds Apply true, and its sync must not write the rules back.
func (cfg Config) off() bool { return cfg.autoOff != nil && cfg.autoOff.Load() }

// modeNow: the auto-switch mode chosen, see Settings.Mode; shared the same
// way. A Config without it (the tests') is on.
func (cfg Config) modeNow() string {
	if cfg.mode != nil {
		if m, ok := cfg.mode.Load().(string); ok {
			return m
		}
	}
	return ModeOn
}

func (cfg Config) setMode(m string) {
	if cfg.mode != nil {
		cfg.mode.Store(m)
	}
}

// disableAuto empties both lists and closes the connections they sent
// direct -- unless observe only is what it was turned off for: everything
// goes direct then, and those connections with it. Once: a second call
// finds it done.
func disableAuto(cfg Config, a *api, closeDirect bool) {
	listMu.Lock()
	if cfg.autoOff != nil && !cfg.autoOff.CompareAndSwap(false, true) {
		listMu.Unlock()
		return
	}
	b := "# auto-switch disabled -- everything goes through the tunnel\n"
	err := replaceList(a, cfg.ListPath, cfg.Provider, b)
	if err == nil && cfg.AddrListPath != "" {
		err = replaceList(a, cfg.AddrListPath, cfg.AddrProvider, b)
	}
	if err != nil && cfg.autoOff != nil {
		// the next look tries again
		cfg.autoOff.Store(false)
	}
	listMu.Unlock()
	if err != nil {
		log.Print(err)
		return
	}
	if !closeDirect {
		log.Printf("auto-switch disabled: the detector's lists emptied")
		return
	}
	n := closeDetectorDirect(cfg, a)
	log.Printf("auto-switch disabled: direct path removed from all domains, %d open connections closed", n)
}

// enableAuto lets the lists be written again; the main loop writes them.
func enableAuto(cfg Config) {
	if cfg.autoOff == nil {
		return
	}
	listMu.Lock()
	cfg.autoOff.Store(false)
	listMu.Unlock()
}

// turnOn carries out auto-switch turned back on, at once, as disableAuto
// does turning it off: the lists are written from memory and the open
// connections they now send direct are closed. It only woke the main loop,
// which took it after the cycle it was in -- and even then the connections
// a browser already held kept going through the tunnel: speedtest.ru showed
// the tunnel's address for a minute after the switch.
func turnOn(cfg Config, a *api, st *state) {
	enableAuto(cfg)
	id := st.current()
	if id == "" || id == "unknown" {
		return // the main loop writes them once it knows the network
	}
	syncList(cfg, a, st, id, true)
	if n := closeTunnelledNowDirect(cfg, a, st, id); n > 0 {
		log.Printf("auto-switch enabled: %d open connections the lists now send direct closed", n)
	}
}

// closeTunnelledNowDirect closes the open tunnel connections the detector's
// lists now send direct: the core routes a connection once, when it opens.
// The user's own lists stand above the detector's, so what they routed is
// left alone; so are the prober's own connections.
func closeTunnelledNowDirect(cfg Config, a *api, st *state, id string) int {
	conns, err := a.connections()
	if err != nil {
		log.Printf("cannot read connections: %v", err)
		return 0
	}
	rules := listRules(cfg.ListPath)
	direct := func(c connection) bool {
		if dom := c.domain(); dom != "" {
			for _, r := range rules {
				if MatchDomainRule(r, dom) {
					return true
				}
			}
			return false
		}
		return cfg.AddrListPath != "" && strings.EqualFold(c.Metadata.Network, "tcp") &&
			len(st.onNode(id, c.Metadata.DestinationIP, c.port())) > 0
	}
	n := 0
	for _, c := range conns {
		if c.ID == "" || !c.viaTunnel(cfg.ProxyName) || c.pinned() || c.fromProbe() || !direct(c) {
			continue
		}
		if err := a.closeConnection(c.ID); err != nil {
			log.Printf("connection %s not closed: %v", c.ID, err)
			continue
		}
		n++
	}
	return n
}

// closeDetectorDirect closes the open connections the detector's lists sent
// direct. The user's own lists, and everything in the tunnel, stay open.
func closeDetectorDirect(cfg Config, a *api) int {
	conns, err := a.connections()
	if err != nil {
		log.Printf("cannot read connections: %v", err)
		return 0
	}
	n := 0
	for _, c := range conns {
		if c.ID == "" || !(c.byProvider(cfg.Provider) ||
			cfg.AddrProvider != "" && c.byProvider(cfg.AddrProvider)) {
			continue
		}
		if err := a.closeConnection(c.ID); err != nil {
			log.Printf("connection %s not closed: %v", c.ID, err)
			continue
		}
		n++
	}
	return n
}

// settingsPoll: how often watchSettings reads the file; the tests shorten it
var settingsPoll = time.Second

// watchSettings reads the settings file every second. Auto-switch turned
// off is carried out here, whatever the main loop is busy with; any other
// change wakes the main loop, which applies it between cycles.
func watchSettings(ctx context.Context, cfg Config, a *api, st *state, last Settings, haveLast bool, wake chan<- struct{}) {
	t := time.NewTicker(settingsPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		ns, ok := readSettings(cfg)
		if !ok || haveLast && ns.Equal(last) {
			continue
		}
		was, awg2Was := ModeOn, true
		if haveLast {
			was, awg2Was = last.Mode(), last.Awg2Active()
		}
		last, haveLast = ns, true
		cfg.setMode(ns.Mode())
		switch now := ns.Mode(); {
		case now != was:
			// the settings as they are now: this copy may have started
			// with auto-switch off, Apply false
			switchMode(ns.apply(cfg), a, st, was, now, awg2Was != ns.Awg2Active())
		case now == ModeOn:
			enableAuto(cfg)
		default:
			disableAuto(cfg, a, now != ModeObserve)
		}
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}

// switchMode carries out a change of auto-switch mode at once. The files the
// mode decides are written first -- the catch-all of observe only, the
// direct lists tunnel only sets aside -- since a connection closed after
// reconnects at once, and must meet the new rules. Then the detector's
// lists, then every open connection the new mode sends another way -- the
// second tunnel's too, when the new mode has it switched otherwise.
func switchMode(cfg Config, a *api, st *state, from, to string, awg2Flipped bool) {
	listMu.Lock()
	syncUserFiles(a)
	syncTunnelLists(a)
	listMu.Unlock()
	if to == ModeOn {
		turnOn(cfg, a, st)
	} else {
		disableAuto(cfg, a, false)
	}
	var awg2 func(connection) bool
	if awg2Flipped {
		awg2 = awg2Moved()
	}
	n := closeRerouted(cfg, a, from, to, awg2)
	log.Printf("auto-switch: %s -> %s, %d open connections sent the new way", from, to, n)
}

// closeRerouted closes the open connections a change of mode moves: the core
// routes a connection once, when it opens. Observe only sends everything
// direct but what the always-tunnel list names, tunnel only everything
// through the tunnels; on sends back what observe only took, and what the
// user's direct lists take again after tunnel only. awg2, when not nil,
// picks the connections the second tunnel switched on or off moves. The
// endpoints, the tunnels' inside and the local networks are routed by rules
// no mode touches, and are left alone.
func closeRerouted(cfg Config, a *api, from, to string, awg2 func(connection) bool) int {
	conns, err := a.connections()
	if err != nil {
		log.Printf("cannot read connections: %v", err)
		return 0
	}
	var userDirect func(connection) bool
	if to == ModeOn && from == ModeTunnel {
		userDirect = userListsDirect()
	}
	n := 0
	for _, c := range conns {
		if c.ID == "" || c.fromProbe() || c.Rule != "RuleSet" && c.Rule != "Match" {
			continue
		}
		var moved bool
		switch to {
		case ModeObserve:
			moved = !c.viaDirect() && !c.byList(paths.TunnelList)
		case ModeTunnel:
			moved = c.viaDirect()
		default:
			moved = c.byProvider(ObserveProvider) || userDirect != nil && !c.viaDirect() && userDirect(c)
		}
		moved = moved || awg2 != nil && awg2(c)
		if !moved {
			continue
		}
		if err := a.closeConnection(c.ID); err != nil {
			log.Printf("connection %s not closed: %v", c.ID, err)
			continue
		}
		n++
	}
	return n
}

// userListsDirect: whether the user's direct list, as the core now reads it,
// sends a connection direct. A program in it stands above every other list;
// its names and addresses only above the detector's rules and MATCH, so
// those only take a connection one of these routed -- an address only one
// that carries no name, as the core's rule asks no resolving.
func userListsDirect() func(connection) bool {
	apps := listRules(paths.ForceDirectApps())
	names := listRules(paths.ForceDirect())
	var nets []netip.Prefix
	for _, r := range listRules(paths.Data(paths.IPList(paths.DirectList))) {
		if p, err := netip.ParsePrefix(r); err == nil {
			nets = append(nets, p)
		}
	}
	return func(c connection) bool {
		for _, r := range apps {
			kind, v, _ := strings.Cut(r, ",")
			if strings.EqualFold(kind, "PROCESS-NAME") && strings.EqualFold(v, c.Metadata.Process) ||
				strings.EqualFold(kind, "PROCESS-PATH") && strings.EqualFold(v, c.Metadata.ProcessPath) {
				return true
			}
		}
		if c.Rule != "Match" {
			return false
		}
		dom := c.domain()
		if dom == "" {
			a, err := netip.ParseAddr(c.Metadata.DestinationIP)
			for _, p := range nets {
				if err == nil && p.Contains(a.Unmap()) {
					return true
				}
			}
			return false
		}
		for _, r := range names {
			if MatchDomainRule(r, dom) {
				return true
			}
		}
		return false
	}
}

// byList: the connection was routed by one of a user list's rule-providers
func (c connection) byList(name string) bool {
	return slices.ContainsFunc(ListProviders(name), c.byProvider)
}

// awg2Moved: the connections the second tunnel switched on or off moves --
// the ones its presets and list routed, and the ones their files, as the
// core now reads them, take. Read after the files are written.
func awg2Moved() func(connection) bool {
	takes := awg2Takes()
	return func(c connection) bool {
		return c.byProvider(PresetsProvider) || c.byList(paths.Awg2List) || takes(c)
	}
}

// Awg2Moved: awg2Moved for CloseConns -- the UI's switch of the second
// tunnel. The files are read at the first call: after the service took it.
func Awg2Moved() func(Conn) bool {
	var m func(connection) bool
	return func(v Conn) bool {
		if m == nil {
			m = awg2Moved()
		}
		var c connection
		if v.RulePayload != "" {
			c.Rule, c.RulePayload = "RuleSet", v.RulePayload
		}
		c.Metadata.Host, c.Metadata.DestinationIP = v.Host, v.IP
		c.Metadata.Process, c.Metadata.ProcessPath = v.Process, v.ProcessPath
		return m(c)
	}
}

// awg2Takes: whether the second tunnel's files, as the core now reads them,
// take a connection. A program by its name or path; a name by the presets'
// suffixes and the list's lines; an address only on a connection with no
// name, as those rules ask no resolving.
func awg2Takes() func(connection) bool {
	var apps, names []string
	var nets []netip.Prefix
	for _, r := range append(listRules(paths.Presets()), listRules(paths.Data(paths.AppList(paths.Awg2List)))...) {
		f := strings.Split(r, ",")
		if len(f) < 2 {
			continue
		}
		switch strings.ToUpper(f[0]) {
		case "PROCESS-NAME", "PROCESS-PATH":
			apps = append(apps, strings.ToUpper(f[0])+","+f[1])
		case "DOMAIN-SUFFIX":
			names = append(names, "+."+f[1])
		case "DOMAIN":
			names = append(names, f[1])
		case "IP-CIDR", "IP-CIDR6":
			if p, err := netip.ParsePrefix(f[1]); err == nil {
				nets = append(nets, p)
			}
		}
	}
	names = append(names, listRules(paths.Awg2Hosts())...)
	for _, r := range listRules(paths.Data(paths.IPList(paths.Awg2List))) {
		if p, err := netip.ParsePrefix(r); err == nil {
			nets = append(nets, p)
		}
	}
	return func(c connection) bool {
		for _, r := range apps {
			kind, v, _ := strings.Cut(r, ",")
			if kind == "PROCESS-NAME" && strings.EqualFold(v, c.Metadata.Process) ||
				kind == "PROCESS-PATH" && strings.EqualFold(v, c.Metadata.ProcessPath) {
				return true
			}
		}
		dom := c.domain()
		if dom == "" {
			a, err := netip.ParseAddr(c.Metadata.DestinationIP)
			for _, p := range nets {
				if err == nil && p.Contains(a.Unmap()) {
					return true
				}
			}
			return false
		}
		for _, r := range names {
			if MatchDomainRule(r, dom) {
				return true
			}
		}
		return false
	}
}
