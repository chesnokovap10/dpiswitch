package ctl

import (
	"context"
	"log"
	"time"
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

// disableAuto empties both lists and closes the connections they sent
// direct. Once: a second call finds it done.
func disableAuto(cfg Config, a *api) {
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
func watchSettings(ctx context.Context, cfg Config, a *api, last Settings, haveLast bool, wake chan<- struct{}) {
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
		last, haveLast = ns, true
		if ns.AutoSwitch {
			enableAuto(cfg)
		} else {
			disableAuto(cfg, a)
		}
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}
