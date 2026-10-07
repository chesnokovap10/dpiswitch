package ctl

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"dpiswitch/internal/probe"
)

// Two resets asked at once -- two pages, two networks -- are two files,
// and both are taken: one file was overwritten by the second, and the
// first asker was told its reset was done.
func TestResetTwoAtOnce(t *testing.T) {
	s := newScenario(t)
	dir := t.TempDir()
	s.cfg.ResetPath = filepath.Join(dir, "reset-*.request")
	s.st.setCurrent("n")
	for _, n := range []string{"m", "k"} {
		s.st.put(n, "x.example.org", &entry{Verdict: probe.Clean, DecidedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	}
	for i, n := range []string{"m", "k"} {
		if err := os.WriteFile(filepath.Join(dir, "reset-"+string(rune('1'+i))+".request"), []byte("now\n"+NetworkLine(n)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if !takeReset(s.cfg, s.api, s.st) {
		t.Fatal("no request taken")
	}
	for _, n := range []string{"m", "k"} {
		if _, ok := s.st.get(n, "x.example.org"); ok {
			t.Errorf("network %s kept its verdict", n)
		}
	}
	if left, _ := filepath.Glob(s.cfg.ResetPath); len(left) != 0 {
		t.Errorf("requests left: %v", left)
	}
}
