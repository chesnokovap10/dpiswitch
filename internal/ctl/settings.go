package ctl

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
	"dpiswitch/internal/probe"
)

// Settings: what the user edits in the UI. Stored
// in a separate file, not in config.yaml: the core config is ACL-locked
// (it holds the private key), while the tray must write these values itself.
//
// The controller re-reads the file every cycle -- no service restart
// is needed to change a TTL.
type Settings struct {
	// auto-switch: false -- observe only, everything goes direct
	AutoSwitch bool `json:"auto_switch"`
	// with auto-switch off: everything goes through the tunnels instead of
	// direct, see Mode
	TunnelOnly bool `json:"tunnel_only"`
	// how long a domain stays direct before a re-check
	CleanTTLMin int `json:"clean_ttl_min"`
	// when to re-check a blocked domain
	FailTTLMin int `json:"fail_ttl_min"`
	// pause cap for domains that have lost their direct path before
	MaxBackoffMin int `json:"max_backoff_min"`
	// how much slower than the tunnel the direct path may be, in percent
	SlowPct int `json:"slow_pct"`
	// attempts per probe; the best measurement counts
	Attempts int `json:"attempts"`
	// extend the verdict to the whole domain when it has several clean
	// subdomains and no blocked ones
	Families bool `json:"families"`
	// IPv6 through the tunnel: TUN gets IPv6 and a route
	IPv6 bool `json:"ipv6"`
	// second tunnel (awg2): the IDs of the presets switched on
	Awg2Presets []string `json:"awg2_presets"`
	// second tunnel switched on or off by hand, by auto-switch mode: each
	// mode keeps its own, see Awg2Active
	Awg2On map[string]bool `json:"awg2_on,omitempty"`
	// direct-path resolvers: the core and the prober reach them directly,
	// so CDNs hand out nodes closest to the user's ISP
	DirectDNS []string `json:"direct_dns"`
	// resolvers inside the tunnel; empty -- DNS from the .conf
	TunnelDNS []string `json:"tunnel_dns"`
	// resolvers inside the second tunnel; empty -- DNS from its .conf. Its
	// own: the first server's resolver may answer inside the first tunnel only
	TunnelDNS2 []string `json:"tunnel_dns2"`
}

// Yandex: verified reachable directly, does not tamper with answers
// for blocked domains, picks CDN nodes for
// Russian ISPs. DoH and DoT on different addresses: if one protocol
// or address gets blocked, the other remains.
var defaultDirectDNS = []string{"https://77.88.8.8/dns-query", "tls://77.88.8.1"}

// SameCore: whether anything that goes into the core config changed (resolvers,
// IPv6). Such settings need a core restart; the rest
// are picked up on the fly
func (s Settings) SameCore(o Settings) bool {
	return reflect.DeepEqual(s.DirectDNS, o.DirectDNS) &&
		reflect.DeepEqual(s.TunnelDNS, o.TunnelDNS) && reflect.DeepEqual(s.TunnelDNS2, o.TunnelDNS2) &&
		s.IPv6 == o.IPv6
}

func (s Settings) Equal(o Settings) bool { return reflect.DeepEqual(s, o) }

// the three auto-switch modes, see Mode. The detector probes and records in
// every one; they differ in where the traffic goes.
const (
	ModeOn      = "on"      // verdicts applied: unblocked sites direct, the rest by the lists
	ModeObserve = "observe" // everything direct but the forbidden and the user's tunnel lists
	ModeTunnel  = "tunnel"  // everything through awg and awg2, the user's direct lists included
)

// Mode: auto-switch on outranks tunnel only, so a hand edit setting
// auto_switch alone means what it says. A file written before tunnel_only
// existed is read in LoadSettings.
func (s Settings) Mode() string {
	switch {
	case s.AutoSwitch:
		return ModeOn
	case s.TunnelOnly:
		return ModeTunnel
	}
	return ModeObserve
}

// SetMode: the two fields for one of the modes; false for an unknown one.
// Observe only chosen starts with the second tunnel off, whatever it was
// switched to there before: that mode is plain direct, and the tunnels only
// take what the user asks of them there.
func (s *Settings) SetMode(m string) bool {
	switch m {
	case ModeOn, ModeObserve, ModeTunnel:
		if m == ModeObserve && s.Mode() != ModeObserve {
			delete(s.Awg2On, ModeObserve)
		}
		s.AutoSwitch, s.TunnelOnly = m == ModeOn, m == ModeTunnel
		return true
	}
	return false
}

// Awg2Active: whether the second tunnel takes its presets and list in the
// mode chosen. Switched off, they route nothing: what they name goes the
// way the other lists and the mode send it. Each mode keeps what it was
// switched to by hand; one never switched is on, observe only off.
func (s Settings) Awg2Active() bool {
	if on, ok := s.Awg2On[s.Mode()]; ok {
		return on
	}
	return s.Mode() != ModeObserve
}

// SetAwg2: the second tunnel switched on or off in the mode chosen.
func (s *Settings) SetAwg2(on bool) {
	if s.Awg2On == nil {
		s.Awg2On = map[string]bool{}
	}
	s.Awg2On[s.Mode()] = on
}

func DefaultSettings() Settings {
	return Settings{
		AutoSwitch: true,
		Families:   true,
		IPv6:       true,
		// every preset off by default: the second tunnel is optional, and a
		// preset silently pinning traffic to a tunnel the user has not set up
		// is worse than no preset at all
		Awg2Presets:   []string{},
		CleanTTLMin:   7 * 24 * 60,
		FailTTLMin:    60,
		MaxBackoffMin: 24 * 60,
		SlowPct:       20,
		Attempts:      3,
		DirectDNS:     append([]string(nil), defaultDirectDNS...),
		TunnelDNS:     []string{},
		TunnelDNS2:    []string{},
	}
}

// LoadSettings: a missing or broken file is not an error,
// defaults are used. The same for missing fields.
func LoadSettings(path string) Settings {
	s := DefaultSettings()
	// the user's file, read by the service as SYSTEM: not through a link
	if b, err := paths.ReadUserFile(path, 1<<20); err == nil {
		_ = json.Unmarshal(b, &s)
		oldObserve(b, &s)
	}
	s.clamp()
	return s
}

// oldObserve: auto-switch off meant everything through the tunnel, with the
// verdicts recorded, up to 1.4.2 -- what tunnel only does now; observe only
// sends everything direct. Every file those versions wrote lacks
// tunnel_only, and one with auto-switch off read as observe only would have
// taken a user's traffic out of the tunnel on update. Such a file is read
// as tunnel only; the next save writes tunnel_only.
func oldObserve(b []byte, s *Settings) {
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil {
		return
	}
	if _, has := raw["tunnel_only"]; !has && !s.AutoSwitch {
		s.TunnelOnly = true
	}
}

// PatchSettings saves what a UI form sent over what the file holds: a field
// the form does not carry keeps its value. The settings form has no second
// tunnel presets -- they live in their own block -- and saving it used to
// write them empty. The preset files stayed as they were until the next
// service start rebuilt them from the file: Stop-Start turned every preset off.
func PatchSettings(path string, body []byte) error {
	_, err := UpdateSettings(path, func(s *Settings) error {
		return json.Unmarshal(body, s)
	})
	return err
}

// settingsMu makes a read-modify-write of the file one step. The UI sends
// every control the moment it changes, so two changes in quick succession
// are two requests served at once: both read the old file and the second
// save wrote the first change back out.
var settingsMu sync.Mutex

// UpdateSettings reads the file, lets change edit it and saves the result,
// with no other save in between. Nothing is written if change fails.
func UpdateSettings(path string, change func(*Settings) error) (Settings, error) {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	s := LoadSettings(path)
	if err := change(&s); err != nil {
		return s, err
	}
	return s, saveSettings(path, s)
}

func SaveSettings(path string, s Settings) error {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	return saveSettings(path, s)
}

func saveSettings(path string, s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// a temporary file of its own, moved over the old one: two writers
	// sharing one name could interleave into a broken file, and the
	// settings are read every second -- by the controller's watcher, the
	// UI, the tray -- which a plain rename meets as "Access is denied"
	return paths.ReplaceFile(path, b)
}

// the bounds of the numeric settings, in minutes and percent: the UI's
// Validate refuses a value outside them, and clamp replaces one read from
// a file -- a hand-edited one included
const (
	cleanTTLMin, cleanTTLMax = 10, 30 * 24 * 60
	failTTLMin, failTTLMax   = 5, 7 * 24 * 60
	maxBackoffMax            = 30 * 24 * 60
	slowPctMax               = 500
)

// TermRange: the values Validate lets a term take, in minutes, by its
// field. The settings page offers no choice outside them: the blocked
// re-check once offered 30 days, and picking it was always refused.
func (s Settings) TermRange(field string) (lo, hi int) {
	switch field {
	case "clean_ttl_min":
		return cleanTTLMin, cleanTTLMax
	case "fail_ttl_min":
		return failTTLMin, failTTLMax
	case "max_backoff_min":
		return s.FailTTLMin, maxBackoffMax
	}
	return 0, 0
}

func (s Settings) Validate() error {
	switch {
	case s.CleanTTLMin < cleanTTLMin || s.CleanTTLMin > cleanTTLMax:
		return fmt.Errorf("direct TTL: from 10 minutes to 30 days")
	case s.FailTTLMin < failTTLMin || s.FailTTLMin > failTTLMax:
		return fmt.Errorf("blocked re-check: from 5 minutes to 7 days")
	// the pause cap limits re-checking of BLOCKED domains after a revert,
	// it is unrelated to the direct TTL: 7 days direct and a 1 day
	// cap is a valid combination. It used to be compared against it,
	// and such a save was silently rejected
	case s.MaxBackoffMin < s.FailTTLMin || s.MaxBackoffMin > maxBackoffMax:
		return fmt.Errorf("pause cap: no less than the blocked re-check and no more than 30 days")
	case s.SlowPct < 0 || s.SlowPct > slowPctMax:
		return fmt.Errorf("latency tolerance: from 0 to 500%%")
	case s.Attempts < 1 || s.Attempts > 10:
		return fmt.Errorf("attempts: from 1 to 10")
	case len(s.DirectDNS) == 0:
		return fmt.Errorf("at least one DNS server for direct sites is required")
	}
	known := presets.Known()
	for _, id := range s.Awg2Presets {
		if !known[id] {
			return fmt.Errorf("unknown preset %q", id)
		}
	}
	for _, list := range [][]string{s.DirectDNS, s.TunnelDNS, s.TunnelDNS2} {
		for _, d := range list {
			if _, err := probe.ParseResolver(d); err != nil {
				return err
			}
		}
	}
	return nil
}

// clamp repairs a hand-broken file instead of refusing to work:
// the service must not fail over a typo in the settings. Only the lower
// bounds used to be enforced here -- Validate guards the UI, not the file
// -- and a hand-edited 999999999 minutes overflowed time.Duration into a
// negative term.
func (s *Settings) clamp() {
	d := DefaultSettings()
	s.SetMode(s.Mode())
	if s.CleanTTLMin < cleanTTLMin || s.CleanTTLMin > cleanTTLMax {
		s.CleanTTLMin = d.CleanTTLMin
	}
	if s.FailTTLMin < failTTLMin || s.FailTTLMin > failTTLMax {
		s.FailTTLMin = d.FailTTLMin
	}
	if s.MaxBackoffMin > maxBackoffMax {
		s.MaxBackoffMin = d.MaxBackoffMin
	}
	if s.MaxBackoffMin < s.FailTTLMin {
		s.MaxBackoffMin = s.FailTTLMin
	}
	if s.SlowPct < 0 || s.SlowPct > slowPctMax {
		s.SlowPct = d.SlowPct
	}
	if s.Attempts < 1 || s.Attempts > 10 {
		s.Attempts = d.Attempts
	}
	// a preset deleted meanwhile is switched off with it. The settings are
	// read every second, the presets' file only when a preset is on.
	var ps []string
	if len(s.Awg2Presets) > 0 {
		known := presets.Known()
		for _, id := range s.Awg2Presets {
			if known[id] {
				ps = append(ps, id)
			}
		}
	}
	if ps == nil {
		ps = []string{}
	}
	s.Awg2Presets = ps
	// the modes there are, and none left empty: the file read back holds
	// nil, and Equal must not see a change in that
	for m := range s.Awg2On {
		if m != ModeOn && m != ModeObserve && m != ModeTunnel {
			delete(s.Awg2On, m)
		}
	}
	if len(s.Awg2On) == 0 {
		s.Awg2On = nil
	}
	s.DirectDNS = cleanDNS(s.DirectDNS)
	s.TunnelDNS = cleanDNS(s.TunnelDNS)
	s.TunnelDNS2 = cleanDNS(s.TunnelDNS2)
	if len(s.DirectDNS) == 0 {
		s.DirectDNS = d.DirectDNS
	}
}

// cleanDNS drops empty and unparseable entries: the core will not start
// with a broken resolver, and leaving the user offline over
// a typo is not acceptable
func cleanDNS(in []string) []string {
	out := []string{}
	for _, d := range in {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if _, err := probe.ParseResolver(d); err == nil {
			out = append(out, d)
		}
	}
	return out
}

func (s Settings) apply(cfg Config) Config {
	cfg.Apply = s.AutoSwitch
	cfg.setMode(s.Mode())
	cfg.TTL = time.Duration(s.CleanTTLMin) * time.Minute
	cfg.FailTTL = time.Duration(s.FailTTLMin) * time.Minute
	cfg.MaxBackoff = time.Duration(s.MaxBackoffMin) * time.Minute
	cfg.Attempts = s.Attempts
	cfg.Families = s.Families
	cfg.DirectDNS = nil
	for _, d := range s.DirectDNS {
		if r, err := probe.ParseResolver(d); err == nil {
			cfg.DirectDNS = append(cfg.DirectDNS, r)
		}
	}
	probe.SetSlowFactor(1 + float64(s.SlowPct)/100)
	return cfg
}
