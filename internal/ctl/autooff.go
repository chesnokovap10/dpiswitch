package ctl

import (
	"context"
	"log"
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
		was := ModeOn
		if haveLast {
			was = last.Mode()
		}
		last, haveLast = ns, true
		cfg.setMode(ns.Mode())
		switch now := ns.Mode(); {
		case now != was:
			// the settings as they are now: this copy may have started
			// with auto-switch off, Apply false
			switchMode(ns.apply(cfg), a, st, was, now)
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
// lists, then every open connection the new mode sends another way.
func switchMode(cfg Config, a *api, st *state, from, to string) {
	listMu.Lock()
	syncUserFiles(a)
	listMu.Unlock()
	if to == ModeOn {
		turnOn(cfg, a, st)
	} else {
		disableAuto(cfg, a, false)
	}
	n := closeRerouted(cfg, a, from, to)
	log.Printf("auto-switch: %s -> %s, %d open connections sent the new way", from, to, n)
}

// closeRerouted closes the open connections a change of mode moves: the core
// routes a connection once, when it opens. Observe only sends everything
// direct, tunnel only everything through the tunnels; on sends back what
// observe only took, and what the user's direct lists take again after
// tunnel only. The endpoints, the tunnels' inside and the local networks are
// routed by rules no mode touches, and are left alone.
func closeRerouted(cfg Config, a *api, from, to string) int {
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
			moved = !c.viaDirect()
		case ModeTunnel:
			moved = c.viaDirect()
		default:
			moved = c.byProvider(ObserveProvider) || userDirect != nil && !c.viaDirect() && userDirect(c)
		}
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

// userListsDirect: whether the user's direct lists, as the core now reads
// them, send a connection direct. An excluded program stands above every
// list; the always-direct names only above the detector's rules and MATCH,
// so those only take a connection one of these routed.
func userListsDirect() func(connection) bool {
	apps := listRules(paths.ForceDirectApps())
	names := listRules(paths.ForceDirect())
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
		for _, r := range names {
			if MatchDomainRule(r, dom) {
				return true
			}
		}
		return false
	}
}
