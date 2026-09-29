package ctl

import (
	"os"
	"sort"

	"context"
	"dpiswitch/internal/probe"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"dpiswitch/internal/paths"
)

// Defaults: default settings derived from the data directory.
func Defaults() Config {
	return Config{
		DirectAddr:    "127.0.0.1:7892",
		TunnelAddr:    "127.0.0.1:7891", // listener bound directly to awg
		APIAddr:       "127.0.0.1:9090",
		CfgPath:       paths.Config(),
		ProxyName:     "awg",
		Provider:      "direct-verified",
		ListPath:      paths.Verified(),
		AddrProvider:  "direct-verified-addr",
		AddrListPath:  paths.VerifiedAddr(),
		StatePath:     paths.State(),
		JSONLPath:     paths.Reports(),
		Interval:      60 * time.Second,
		WatchInterval: time.Second,
		TTL:           7 * 24 * time.Hour,
		FailTTL:       time.Hour,
		MaxBackoff:    24 * time.Hour,
		Idle:          idleTerm,
		SettingsPath:  paths.Settings(),
		Families:      true,
		DirectDNS:     DefaultSettings().apply(Config{}).DirectDNS,
		Timeout:       8 * time.Second,
		Attempts:      3,
		Workers:       4,
		PerCycle:      20,
		Apply:         false,
		// cloudflare-ech.com is the outer name of every Cloudflare site a
		// browser reaches with Encrypted Client Hello: the sniffer sees only
		// it. The probe sends a plain ClientHello, so its verdict would be
		// about other traffic than the one it routes -- and while it was
		// CLEAN, every ECH connection to Cloudflare went direct.
		SkipSuffix:  []string{"in-addr.arpa", "local", "lan", "cloudflare-ech.com"},
		PinnedLists: pinnedLists(),
		ResetPath:   paths.ResetRequest(),
	}
}

// pinnedLists: the rule-provider files routing names above the detector --
// the forbidden ones too: a probe would reach them past the rules. The
// presets' file holds the ones switched on only.
func pinnedLists() []string {
	return []string{paths.Awg2Hosts(), paths.ForceTunnel(), paths.ForceBlock(), paths.Presets()}
}

// Run loops until the context is cancelled. It is the single
// implementation of the controller logic.
func Run(ctx context.Context, cfg Config) {
	secret := secretFromConfig(cfg.CfgPath)
	if secret == "" {
		log.Printf("warning: secret not found in %s, calling the API without auth", cfg.CfgPath)
	}
	a := newAPI(cfg.APIAddr, secret)
	cfg.autoOff = new(atomic.Bool)
	cfg.mode = new(atomic.Value)
	cfg.stop = ctx.Done()
	st := loadState(cfg.StatePath)
	netID := resolveNetwork(cfg, st)
	st.setCurrent(netID)
	_ = st.save()

	// the user's settings file overrides the service values; if it is missing,
	// whatever was passed at start stays
	set, haveSet := readSettings(cfg)
	if haveSet {
		cfg = set.apply(cfg)
	}

	// a reset asked for while the controller was not running is taken now,
	// before the verdicts it drops are applied: the list used to be written
	// from them first
	takeReset(cfg, a, st)

	mode := "APPLY"
	switch cfg.modeNow() {
	case ModeObserve:
		mode = "OBSERVE (everything direct but the forbidden and the tunnel lists)"
	case ModeTunnel:
		mode = "TUNNEL ONLY (everything goes through the tunnels)"
	}
	if !haveSet && !cfg.Apply {
		mode = "OBSERVE (nothing is changed)"
	}
	log.Printf("network %s | mode: %s | clean TTL %s, blocked TTL %s", netID, mode, cfg.TTL, cfg.FailTTL)
	if n := len(st.verified(netID)); n > 0 {
		log.Printf("memory already holds %d direct domains for this network", n)
	}

	// sync the file with memory RIGHT AWAY, without waiting for a verdict change.
	// otherwise the list and the state diverge after a migration, a manual edit
	// or a panic reset -- and accumulated verdicts are simply not applied
	if cfg.Apply {
		applyList(cfg, a, st, netID)
	} else if haveSet {
		// disabled by the user: the list from the previous run must not
		// keep sending sites direct
		disableAuto(cfg, a, set.Mode() != ModeObserve)
	}

	w := newWatcher(ctx, cfg, a)
	go watchReset(ctx, cfg, a, st)

	wake := make(chan struct{}, 1)
	go watchSettings(ctx, cfg, a, st, set, haveSet, wake)
	settingsChanged := func() {
		ns, ok := readSettings(cfg)
		if !ok || haveSet && ns.Equal(set) {
			return
		}
		if coreChanged(ns, set, haveSet) && cfg.OnCoreChange != nil {
			log.Printf("core settings changed (DNS: direct %v, tunnel %v; IPv6 %v) -- restarting the core",
				ns.DirectDNS, ns.TunnelDNS, ns.IPv6)
			cfg.OnCoreChange()
		}
		cfg = onSettingsChanged(cfg, ns, a, st, netID)
		set, haveSet = ns, true
	}

	t := time.NewTicker(cfg.Interval)
	offline := false // no gateway right now (see the tick below)
	defer t.Stop()
	g := &gate{interval: cfg.Interval}
	health := func() (bool, string, error) { return a.tunnelHealth(cfg.ProxyName) }
	if g.allow(time.Now().Round(0), health) {
		cycle(cfg, a, st, netID, w)
	}
	for {
		select {
		case <-wake:
			// a change the watcher saw: applied now, not at the next tick
			settingsChanged()
		case <-t.C:
			settingsChanged()
			// the network may have changed -- another network's verdicts do not apply
			id := resolveNetwork(cfg, st)
			if id == "unknown" {
				// no gateway: Wi-Fi reconnecting, sleep, cable out. This is not
				// a new network -- switching to an empty memory used to send every
				// site into the tunnel for the duration of a one-minute Wi-Fi blip.
				// Keep the current memory and skip probing: without a network
				// every probe would fail anyway.
				if !offline {
					log.Printf("no network, keeping memory of %s and pausing probes", netID)
					offline = true
				}
				continue
			}
			if offline {
				log.Printf("network is back")
				offline = false
			}
			if id != netID {
				log.Printf("network changed: %s -> %s, switching memory", netID, id)
				netID = id
				st.setCurrent(id)
				_ = st.save()
				if cfg.Apply {
					applyList(cfg, a, st, netID)
				}
			}
			if !g.allow(time.Now().Round(0), health) {
				// the list still follows memory: verdicts expire all the same
				if cfg.Apply {
					syncList(cfg, a, st, netID, false)
				}
				continue
			}
			cycle(cfg, a, st, netID, w)
		case <-ctx.Done():
			log.Println("controller stopped")
			_ = st.save()
			return
		}
	}
}

// Snapshot: a summary for the UI.
type Snapshot struct {
	NetworkID string         `json:"network_id"`
	Counts    map[string]int `json:"counts"`
	Direct    []string       `json:"direct"`
	Details   []DirectEntry  `json:"details"`
	Families  []family       `json:"families"`
	// everything that does NOT go direct: blocked, slower, unverified
	Others []DirectEntry `json:"others"`
}

// Blocked: the names the direct path was found tampered with -- cut at any
// stage, a spoofed certificate, a changed answer. The UI's status card and
// its "Blocked" tab, and the tray, all count by this: the card counted
// BLOCKED_TLS alone, the tray three kinds, the tab five -- 31, 35 and 38.
func (s Snapshot) Blocked() int {
	n := 0
	for v, c := range s.Counts {
		switch probe.Verdict(v) {
		case probe.BlockedTCP, probe.BlockedTLS, probe.BlockedQUIC, probe.MITM, probe.ContentDiff:
			n += c
		}
	}
	return n
}

// DirectEntry: a row of the verdict tables in the UI
type DirectEntry struct {
	Domain    string    `json:"domain"`
	DecidedAt time.Time `json:"decided_at"`
	ExpiresAt time.Time `json:"expires_at"`
	TestedIP  string    `json:"tested_ip"`
	Reason    string    `json:"reason"`
	Verdict   string    `json:"verdict,omitempty"`
	// Idle: the term is over and nothing has gone to the name for the idle
	// term -- it is checked again when something does (see state.expired).
	// The UI said "due now" for days.
	Idle bool `json:"idle,omitempty"`
}

// idleTerm: Config.Idle as the service runs it
const idleTerm = 24 * time.Hour

func directEntry(dom string, e *entry, now time.Time) DirectEntry {
	return DirectEntry{dom, e.DecidedAt, e.ExpiresAt, e.TestedIP, e.Reason, string(e.Verdict),
		now.After(e.ExpiresAt) && !e.lastSeen().After(now.Add(-idleTerm))}
}

func Load(statePath string) Snapshot {
	st := loadState(statePath)
	id := st.Current
	if id == "" {
		id = networkID()
	}
	s := Snapshot{NetworkID: id, Counts: map[string]int{}}
	st.mu.Lock()
	for _, e := range st.Networks[id] {
		s.Counts[string(e.Verdict)]++
	}
	st.mu.Unlock()
	// names, and bare addresses with a CLEAN of their own: both go direct,
	// and the counts already held the addresses the list left out
	s.Direct = append(st.verified(id), st.cleanAddrs(id)...)
	if LoadSettings(paths.Settings()).Families {
		s.Families = st.families(id)
	}
	now := time.Now()
	for _, d := range s.Direct {
		if e, ok := st.get(id, d); ok {
			s.Details = append(s.Details, directEntry(d, e, now))
		}
	}
	st.mu.Lock()
	for dom, e := range st.Networks[id] {
		if e.Verdict != probe.Clean {
			s.Others = append(s.Others, directEntry(dom, e, now))
		}
	}
	st.mu.Unlock()
	sort.Slice(s.Others, func(i, j int) bool { return s.Others[i].Domain < s.Others[j].Domain })
	return s
}

// snapCache: see LoadCached
var snapCache struct {
	sync.Mutex
	path string
	mod  time.Time
	size int64
	at   time.Time
	snap Snapshot
}

// LoadCached: Load for the readers that poll the same file -- the tray every
// ten seconds, the UI every five and twice over. The state is a few hundred
// KB and took 2.2 ms to parse each time. It is parsed again when the file
// changes, or after a minute: the direct count follows the clock too, as
// verdicts expire. The snapshot is shared: callers must not change it.
func LoadCached(path string) Snapshot {
	fi, err := os.Stat(path)
	c := &snapCache
	c.Lock()
	defer c.Unlock()
	if err == nil && c.path == path && fi.ModTime().Equal(c.mod) && fi.Size() == c.size &&
		time.Since(c.at) < time.Minute {
		return c.snap
	}
	c.snap, c.at, c.path = Load(path), time.Now(), path
	c.mod, c.size = time.Time{}, 0
	if err == nil {
		c.mod, c.size = fi.ModTime(), fi.Size()
	}
	return c.snap
}

// coreChanged: whether new settings need a core restart. The core runs on
// what its config was built from -- while there was no settings file, the
// defaults. The first save used to restart nothing, and the core kept the
// default resolvers while the prober asked the new ones: other CDN nodes.
func coreChanged(ns, set Settings, haveSet bool) bool {
	if !haveSet {
		set = DefaultSettings()
	}
	return !ns.SameCore(set)
}

func readSettings(cfg Config) (Settings, bool) {
	if cfg.SettingsPath == "" {
		return Settings{}, false
	}
	if _, err := os.Stat(cfg.SettingsPath); err != nil {
		return Settings{}, false
	}
	return LoadSettings(cfg.SettingsPath), true
}

// onSettingsChanged applies new settings to verdicts already made,
// not only to future ones: if the TTL was shortened there is no need to wait out the old one
func onSettingsChanged(cfg Config, s Settings, a *api, st *state, netID string) Config {
	was, old := cfg.Apply, cfg
	cfg = s.apply(cfg)
	log.Printf("settings: auto-switch %s, direct TTL %s, blocked TTL %s, cap %s, tolerance +%d%%, attempts %d",
		s.Mode(), cfg.TTL, cfg.FailTTL, cfg.MaxBackoff, s.SlowPct, cfg.Attempts)

	// Terms follow the setting they come from, and only when it changed.
	// The other verdicts' terms were left as they were -- a blocked re-check
	// shortened to 5 minutes still waited out the old hour -- and every
	// save, whatever it changed, reset the CLEAN ones, a CLEAN measured
	// slower once among them (see entry.SlowOnce).
	failChanged := cfg.FailTTL != old.FailTTL || cfg.MaxBackoff != old.MaxBackoff
	st.mu.Lock()
	for _, m := range st.Networks {
		for _, e := range m {
			switch {
			case e.Verdict == probe.Clean:
				if cfg.TTL != old.TTL && !e.SlowOnce {
					e.ExpiresAt = e.DecidedAt.Add(cfg.TTL)
				}
			case failChanged:
				e.ExpiresAt = e.DecidedAt.Add(failTerm(cfg, e.Streak, e.Reverts))
			}
		}
	}
	st.mu.Unlock()
	if err := st.save(); err != nil {
		log.Printf("state not saved: %v", err)
	}

	switch {
	case was && !cfg.Apply:
		// disabled -- the detector's lists are emptied at once, not when
		// verdicts expire; memory is kept. Usually the watcher has done it.
		disableAuto(cfg, a, s.Mode() != ModeObserve)
	default:
		if cfg.Apply {
			enableAuto(cfg)
		}
		applyList(cfg, a, st, netID)
	}
	return cfg
}
