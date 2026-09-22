package ctl

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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
