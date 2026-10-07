package ctl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The UDP guard is off in a fresh settings file and in one an older version
// wrote, is kept across a save, and is no setting of the core's: switching
// it restarts nothing.
func TestSettingsUDPGuard(t *testing.T) {
	if DefaultSettings().UDPGuard {
		t.Fatal("on by default: it cuts off what needs UDP out of the adapter")
	}
	path := filepath.Join(t.TempDir(), "settings.json")

	// a file from before the setting existed
	if err := os.WriteFile(path, []byte(`{"auto_switch": true, "clean_ttl_min": 60}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if LoadSettings(path).UDPGuard {
		t.Fatal("an older file reads as on")
	}

	// the name it is saved under is the one the UI and a hand-edit use
	s := DefaultSettings()
	s.UDPGuard = true
	if err := SaveSettings(path, s); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), `"udp_guard": true`) {
		t.Fatalf("not saved as udp_guard:\n%s", b)
	}
	if !LoadSettings(path).UDPGuard {
		t.Fatal("not read back")
	}

	// a form that does not carry it keeps it, as it keeps the presets
	if err := PatchSettings(path, []byte(`{"slow_pct": 30}`)); err != nil {
		t.Fatal(err)
	}
	if got := LoadSettings(path); !got.UDPGuard || got.SlowPct != 30 {
		t.Fatalf("a patch of another field: %+v", got)
	}

	// the core is not asked to restart for it
	on, off := DefaultSettings(), DefaultSettings()
	on.UDPGuard = true
	if !on.SameCore(off) || !off.SameCore(on) {
		t.Error("the guard counts as a setting the core is built from")
	}
	if on.Equal(off) {
		t.Error("the guard is not among what makes two settings differ: the controller would not see the change")
	}
}
