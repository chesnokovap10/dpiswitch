package ctl

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

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
	// auto-switch: false -- observe only, everything goes through the tunnel
	AutoSwitch bool `json:"auto_switch"`
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
	// second tunnel (awg2) presets: youtube, telegram, ai
	Awg2Presets []string `json:"awg2_presets"`
	// direct-path resolvers: the core and the prober reach them directly,
	// so CDNs hand out nodes closest to the user's ISP
	DirectDNS []string `json:"direct_dns"`
	// resolvers inside the tunnel; empty -- DNS from the .conf
	TunnelDNS []string `json:"tunnel_dns"`
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
		reflect.DeepEqual(s.TunnelDNS, o.TunnelDNS) && s.IPv6 == o.IPv6
}

func (s Settings) Equal(o Settings) bool { return reflect.DeepEqual(s, o) }

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
	}
}

// LoadSettings: a missing or broken file is not an error,
// defaults are used. The same for missing fields.
func LoadSettings(path string) Settings {
	s := DefaultSettings()
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	s.clamp()
	return s
}

// PatchSettings saves what a UI form sent over what the file holds: a field
// the form does not carry keeps its value. The settings form has no second
// tunnel presets -- they live in their own block -- and saving it used to
// write them empty. The preset files stayed as they were until the next
// service start rebuilt them from the file: Stop-Start turned every preset off.
func PatchSettings(path string, body []byte) error {
	s := LoadSettings(path)
	if err := json.Unmarshal(body, &s); err != nil {
		return err
	}
	return SaveSettings(path, s)
}

func SaveSettings(path string, s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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
	for _, id := range s.Awg2Presets {
		if !presets.Valid(id) {
			return fmt.Errorf("unknown preset %q", id)
		}
	}
	for _, list := range [][]string{s.DirectDNS, s.TunnelDNS} {
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
	var ps []string
	for _, id := range s.Awg2Presets {
		if presets.Valid(id) {
			ps = append(ps, id)
		}
	}
	if ps == nil {
		ps = []string{}
	}
	s.Awg2Presets = ps
	s.DirectDNS = cleanDNS(s.DirectDNS)
	s.TunnelDNS = cleanDNS(s.TunnelDNS)
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
