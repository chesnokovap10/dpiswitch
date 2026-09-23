package ctl

import (
	"testing"
	"time"

	"dpiswitch/internal/probe"
)

func TestExpiredOnlyWhileInUse(t *testing.T) {
	const idle = 24 * time.Hour
	now := time.Now()
	st := &state{Networks: map[string]map[string]*entry{"net": {
		// expired and still requested -- re-check it
		"live.example": {Verdict: probe.BlockedTLS, DecidedAt: now.Add(-2 * time.Hour),
			ExpiresAt: now.Add(-time.Hour), LastSeen: now.Add(-time.Minute)},
		// expired, but nothing has gone there for days: a CDN node that no
		// longer exists. Re-probing it every hour buys nothing.
		"gone.example": {Verdict: probe.BlockedTLS, DecidedAt: now.Add(-72 * time.Hour),
			ExpiresAt: now.Add(-71 * time.Hour), LastSeen: now.Add(-72 * time.Hour)},
		// in use but the verdict still holds
		"fresh.example": {Verdict: probe.Clean, DecidedAt: now.Add(-time.Hour),
			ExpiresAt: now.Add(time.Hour), LastSeen: now},
	}}}

	got := st.expired("net", idle)
	if len(got) != 1 || got[0] != "live.example" {
		t.Fatalf("expired: got %v, want [live.example]", got)
	}

	// a request revives it: the next sweep picks it up again
	st.touch("net", []string{"gone.example"})
	if got := st.expired("net", idle); len(got) != 2 {
		t.Fatalf("after touch: got %v, want both", got)
	}
}

func TestForgetDropsUnusedOnly(t *testing.T) {
	now := time.Now()
	st := &state{Networks: map[string]map[string]*entry{"net": {
		"old.example":  {Verdict: probe.Clean, DecidedAt: now.Add(-20 * 24 * time.Hour), LastSeen: now.Add(-20 * 24 * time.Hour)},
		"used.example": {Verdict: probe.Clean, DecidedAt: now.Add(-20 * 24 * time.Hour), LastSeen: now.Add(-time.Hour)},
		// written before last_seen existed: the decision time stands in for it
		"legacy.example": {Verdict: probe.Clean, DecidedAt: now.Add(-time.Hour)},
	}}}
	if n := st.forget("net", 10*24*time.Hour); n != 1 {
		t.Fatalf("forgot %d, want 1", n)
	}
	if _, ok := st.Networks["net"]["old.example"]; ok {
		t.Error("the unused name is still there")
	}
	for _, keep := range []string{"used.example", "legacy.example"} {
		if _, ok := st.Networks["net"][keep]; !ok {
			t.Errorf("%s must be kept", keep)
		}
	}
}
