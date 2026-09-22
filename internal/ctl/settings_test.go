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
		t.Fatalf("без файла ждал умолчания, получил %+v", s)
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
		t.Fatalf("не применилось: TTL %s apply %v", cfg.TTL, cfg.Apply)
	}

	// сочетание со скриншота пользователя: 7 дней напрямую, 1 день
	// потолка -- раньше отклонялось по ошибке
	ok := DefaultSettings()
	ok.CleanTTLMin, ok.FailTTLMin, ok.MaxBackoffMin = 7*24*60, 60, 24*60
	if err := SaveSettings(p, ok); err != nil {
		t.Fatalf("законное сочетание отклонено: %v", err)
	}
	bad := ok
	bad.MaxBackoffMin = 30 // меньше перепроверки заблокированных (60)
	if SaveSettings(p, bad) == nil {
		t.Fatal("потолок меньше перепроверки заблокированных должен отклоняться")
	}
	// испорченный руками файл не валит службу
	os.WriteFile(p, []byte(`{"clean_ttl_min":-5,"attempts":99}`), 0o644)
	if s := LoadSettings(p); s.CleanTTLMin != 7*24*60 || s.Attempts != 3 {
		t.Fatalf("clamp не сработал: %+v", s)
	}
}
