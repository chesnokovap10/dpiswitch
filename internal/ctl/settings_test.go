package ctl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dpiswitch/internal/probe"
)

func TestSettingsRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	if s := LoadSettings(p); !s.Equal(DefaultSettings()) {
		t.Fatalf("without a file expected defaults, got %+v", s)
	}
	want := DefaultSettings()
	want.CleanTTLMin = 480
	want.AutoSwitch = false
	if err := SaveSettings(p, want); err != nil {
		t.Fatal(err)
	}
	got := LoadSettings(p)
	if !got.Equal(want) {
		t.Fatalf("%+v != %+v", got, want)
	}
	cfg := got.apply(Defaults())
	if cfg.TTL != 8*time.Hour || cfg.Apply {
		t.Fatalf("not applied: TTL %s apply %v", cfg.TTL, cfg.Apply)
	}

	// a real user combination: 7 days direct, 1 day cap -- it used to be
	// rejected by mistake
	ok := DefaultSettings()
	ok.CleanTTLMin, ok.FailTTLMin, ok.MaxBackoffMin = 7*24*60, 60, 24*60
	if err := SaveSettings(p, ok); err != nil {
		t.Fatalf("a valid combination was rejected: %v", err)
	}
	bad := ok
	bad.MaxBackoffMin = 30 // below the blocked re-check interval (60)
	if SaveSettings(p, bad) == nil {
		t.Fatal("a cap below the blocked re-check interval must be rejected")
	}
	// a hand-broken file must not crash the service
	os.WriteFile(p, []byte(`{"clean_ttl_min":-5,"attempts":99}`), 0o644)
	if s := LoadSettings(p); s.CleanTTLMin != 7*24*60 || s.Attempts != 3 {
		t.Fatalf("clamp did not work: %+v", s)
	}
}

// Three modes in two fields: auto-switch on outranks tunnel only, so a file
// from before tunnel_only, or a hand edit of auto_switch alone, means what it
// always did.
func TestSettingsMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	for _, m := range []string{ModeOn, ModeObserve, ModeTunnel} {
		s := DefaultSettings()
		if !s.SetMode(m) {
			t.Fatalf("%s refused", m)
		}
		if err := SaveSettings(p, s); err != nil {
			t.Fatal(err)
		}
		if got := LoadSettings(p).Mode(); got != m {
			t.Fatalf("saved %s, read %s", m, got)
		}
	}
	if s := DefaultSettings(); s.SetMode("off") || s.Mode() != ModeOn {
		t.Fatalf("an unknown mode was taken: %s", s.Mode())
	}
	os.WriteFile(p, []byte(`{"auto_switch":true,"tunnel_only":true}`), 0o644)
	if s := LoadSettings(p); s.Mode() != ModeOn || s.TunnelOnly {
		t.Fatalf("auto_switch set by hand: %+v", s)
	}
	os.WriteFile(p, []byte(`{"auto_switch":false}`), 0o644)
	if s := LoadSettings(p); s.Mode() != ModeObserve {
		t.Fatalf("a file from before tunnel only: %s", s.Mode())
	}
}

// The core is built from the defaults while there is no settings file: the
// first save with other resolvers or IPv6 needs a restart, one with only
// controller values does not.
func TestCoreChanged(t *testing.T) {
	d := DefaultSettings()
	ttl := d
	ttl.CleanTTLMin = 60
	if coreChanged(ttl, Settings{}, false) {
		t.Error("first save of controller values only: no restart needed")
	}
	dns := d
	dns.DirectDNS = []string{"tls://1.1.1.1"}
	if !coreChanged(dns, Settings{}, false) {
		t.Error("first save with other resolvers must restart the core")
	}
	if coreChanged(dns, dns, true) {
		t.Error("nothing changed since the last read")
	}
	noV6 := dns
	noV6.IPv6 = false
	if !coreChanged(noV6, dns, true) {
		t.Error("IPv6 switched off must restart the core")
	}
}

// A settings file edited by hand past the bounds is put back within them:
// 999999999 minutes used to overflow into a negative term.
func TestClampUpperBounds(t *testing.T) {
	s := Settings{CleanTTLMin: 999999999, FailTTLMin: 999999999, MaxBackoffMin: 999999999,
		SlowPct: 999999999, Attempts: 3}
	s.clamp()
	d := DefaultSettings()
	if s.CleanTTLMin != d.CleanTTLMin || s.FailTTLMin != d.FailTTLMin ||
		s.MaxBackoffMin != d.MaxBackoffMin || s.SlowPct != d.SlowPct {
		t.Fatalf("got %+v", s)
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("clamped settings do not validate: %v", err)
	}
	cfg := s.apply(Config{})
	if cfg.TTL <= 0 || cfg.FailTTL <= 0 || cfg.MaxBackoff <= 0 {
		t.Fatalf("terms %s %s %s", cfg.TTL, cfg.FailTTL, cfg.MaxBackoff)
	}
	probe.SetSlowFactor(1.2)
}

// The settings form carries no presets: saving it must keep the ones the
// second tunnel block turned on, and the other way round.
func TestPatchSettingsKeepsOtherFields(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	s := DefaultSettings()
	s.Awg2Presets = []string{"youtube", "ai"}
	if err := SaveSettings(p, s); err != nil {
		t.Fatal(err)
	}
	form := `{"auto_switch":false,"families":true,"ipv6":true,"clean_ttl_min":480,
		"fail_ttl_min":60,"max_backoff_min":1440,"slow_pct":20,"attempts":3,
		"direct_dns":["tls://77.88.8.1"],"tunnel_dns":[]}`
	if err := PatchSettings(p, []byte(form)); err != nil {
		t.Fatal(err)
	}
	got := LoadSettings(p)
	if got.AutoSwitch || got.CleanTTLMin != 480 {
		t.Fatalf("the form was not applied: %+v", got)
	}
	if len(got.Awg2Presets) != 2 || got.Awg2Presets[0] != "youtube" || got.Awg2Presets[1] != "ai" {
		t.Fatalf("presets lost: %v", got.Awg2Presets)
	}
	if PatchSettings(p, []byte(`{"attempts":99}`)) == nil {
		t.Fatal("an invalid value must be rejected")
	}
	if LoadSettings(p).Attempts != 3 {
		t.Fatal("a rejected save must leave the file as it was")
	}
}

// A DoH address without a path is saved with the one the test asked: the
// core asks "/" otherwise, and the server that passed the test answers 404.
// A file written before this is read the same way.
func TestDoHPathSaved(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	_, err := UpdateSettings(p, func(s *Settings) error {
		s.DirectDNS = []string{"https://84.252.75.74:8443", "tls://77.88.8.1"}
		s.TunnelDNS = []string{"https://1.1.1.1/dns-query"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), `"https://84.252.75.74:8443/dns-query"`) {
		t.Fatalf("path not written:\n%s", b)
	}
	got := LoadSettings(p)
	if got.DirectDNS[1] != "tls://77.88.8.1" || got.TunnelDNS[0] != "https://1.1.1.1/dns-query" {
		t.Fatalf("other entries changed: %v %v", got.DirectDNS, got.TunnelDNS)
	}

	old := `{"direct_dns":["https://77.88.8.8"],"tunnel_dns":["https://9.9.9.9:5053"]}`
	if err := os.WriteFile(p, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	got = LoadSettings(p)
	if got.DirectDNS[0] != "https://77.88.8.8/dns-query" || got.TunnelDNS[0] != "https://9.9.9.9:5053/dns-query" {
		t.Fatalf("old file not repaired: %v %v", got.DirectDNS, got.TunnelDNS)
	}
}
