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

// disableAuto empties the detector's direct lists and closes the
// connections they sent direct -- unless observe only is what it was turned
// off for: everything goes direct then, and those connections with it. The
// ClientHello cut's list is the mode's, see splitNames: observe only keeps
// it. Once: a second call finds it done.
func disableAuto(cfg Config, a *api, st *state, closeDirect bool) {
	listMu.Lock()
	if cfg.autoOff != nil && !cfg.autoOff.CompareAndSwap(false, true) {
		listMu.Unlock()
		return
	}
	b := "# auto-switch disabled -- everything goes through the tunnel\n"
	var err error
	// observe only with the cut on keeps them: see directLists
	if !directLists(cfg) {
		err = replaceList(a, cfg.ListPath, cfg.Provider, b)
		if err == nil && cfg.AddrListPath != "" {
			err = replaceList(a, cfg.AddrListPath, cfg.AddrProvider, b)
		}
	}
	if err == nil && cfg.SplitListPath != "" {
		err = writeSplit(cfg, a, st, st.current(), splitNames(cfg, st, st.current()), true)
	}
	// inheritance is On's alone: emptied here whatever the mode turned to
	if err == nil {
		err = writeInherit(cfg, a, st, st.current(), nil, true)
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
		// observe only: with the cut on the lists stay (see directLists)
		if directLists(cfg) {
			log.Printf("observe only with the ClientHello cut: the detector's lists kept")
		} else {
			log.Printf("observe only: the detector's lists emptied")
		}
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
	if id == "" || id == noNetwork {
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
	if cfg.SplitListPath != "" {
		rules = append(rules, listRules(cfg.SplitListPath)...)
	}
	// inheritance by domain; by network it needs the name's address, and a
	// connection it misses is routed so at its next opening
	if cfg.InheritPath != "" {
		rules = append(rules, listRules(cfg.InheritPath)...)
	}
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
			cfg.AddrProvider != "" && c.byProvider(cfg.AddrProvider) ||
			cfg.SplitProvider != "" && c.byProvider(cfg.SplitProvider) || c.inherited()) {
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

// closeByProvider closes the open connections a rule of this provider routed
func closeByProvider(a *api, provider string) int {
	return closeByProviderNet(a, provider, "")
}

// closeByProviderNet: closeByProvider for one network only, tcp or udp;
// empty -- both
func closeByProviderNet(a *api, provider, network string) int {
	if provider == "" {
		return 0
	}
	conns, err := a.connections()
	if err != nil {
		log.Printf("cannot read connections: %v", err)
		return 0
	}
	n := 0
	for _, c := range conns {
		if c.ID == "" || !c.byProvider(provider) || network != "" && !strings.EqualFold(c.Metadata.Network, network) {
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
		was, awg2Was := ModeOn, Awg2Attached()
		if haveLast {
			was, awg2Was = last.Mode(), last.Awg2Carries()
		}
		last, haveLast = ns, true
		cfg.setMode(ns.Mode())
		switch now := ns.Mode(); {
		case now != was:
			// the settings as they are now: this copy may have started
			// with auto-switch off, Apply false
			switchMode(ns.apply(cfg), a, st, was, now, awg2Was != ns.Awg2Carries())
		case now == ModeOn:
			enableAuto(cfg)
		default:
			disableAuto(ns.apply(cfg), a, st, now != ModeObserve)
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
	syncRoutes(a)
	listMu.Unlock()
	if to == ModeOn {
		turnOn(cfg, a, st)
	} else {
		disableAuto(cfg, a, st, false)
		// off already, observe only and tunnel only one after the other:
		// the cut's list follows the mode all the same
		if id := st.current(); id != "" && id != noNetwork {
			syncList(cfg, a, st, id, false)
		}
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
// through the tunnels but what the always-direct list names; on sends back
// what observe only took. awg2, when not nil, picks the connections the
// second tunnel switched on or off moves. The endpoints, the tunnels'
// inside and the local networks are routed by rules no mode touches, and
// are left alone.
func closeRerouted(cfg Config, a *api, from, to string, awg2 func(connection) bool) int {
	conns, err := a.connections()
	if err != nil {
		log.Printf("cannot read connections: %v", err)
		return 0
	}
	n := 0
	for _, c := range conns {
		if c.ID == "" || c.fromProbe() || c.Rule != "RuleSet" && c.Rule != "Match" && !c.inherited() {
			continue
		}
		var moved bool
		switch to {
		case ModeObserve:
			moved = !c.viaDirect() && !c.byList(paths.TunnelList)
		case ModeTunnel:
			moved = c.viaDirect() && !c.byList(paths.DirectList)
		default:
			moved = c.byProvider(ObserveProvider) || c.byProvider(ObserveSplitProvider)
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
		if line := PresetNameLine(r); line != "" {
			names = append(names, line)
			continue
		}
		switch strings.ToUpper(f[0]) {
		case "PROCESS-NAME", "PROCESS-PATH":
			apps = append(apps, strings.ToUpper(f[0])+","+f[1])
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

// closeOnNetworkChange closes the open connections the detector's lists
// routed: the verdicts are a network's own, and the lists were just
// rewritten for the new one. The core routes a connection once, when it
// opens -- a site through the tunnel on one network and direct on the next
// kept the tunnel for as long as the browser held it. The user's lists,
// the presets and the local network stay: their way is the same on every
// network. Tunnel only routes nothing by the detector.
func closeOnNetworkChange(cfg Config, a *api) int {
	if cfg.mode != nil && cfg.modeNow() == ModeTunnel {
		return 0
	}
	conns, err := a.connections()
	if err != nil {
		log.Printf("cannot read connections: %v", err)
		return 0
	}
	byDetector := map[string]bool{}
	for _, p := range []string{cfg.Provider, cfg.AddrProvider, cfg.SplitProvider, cfg.NoQUICProvider, cfg.NoTCPProvider,
		ObserveSplitProvider, ObserveProvider, HoldProvider, InheritProvider, FamilyDirectProvider, FamilyTunnelProvider} {
		if p != "" {
			byDetector[p] = true
		}
	}
	n := 0
	for _, c := range conns {
		if c.ID == "" || c.fromProbe() {
			continue
		}
		if !(c.Rule == "Match" || c.inherited() || c.Rule == "RuleSet" && byDetector[c.RulePayload]) {
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
