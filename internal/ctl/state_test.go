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

// The tested node of each live CLEAN name, as a host route, for connections
// that reach a bare address (a speedtest client does).
func TestVerifiedIPs(t *testing.T) {
	now := time.Now()
	live := now.Add(time.Hour)
	st := &state{Networks: map[string]map[string]*entry{"net": {
		"tula.qms.ru":  {Verdict: probe.Clean, ExpiresAt: live, TestedIP: "212.12.2.243"},
		"alias.qms.ru": {Verdict: probe.Clean, ExpiresAt: live, TestedIP: "212.12.2.243"}, // same node once
		"v6.example":   {Verdict: probe.Clean, ExpiresAt: live, TestedIP: "2001:db8::1"},
		"blocked.ru":   {Verdict: probe.BlockedTLS, ExpiresAt: live, TestedIP: "192.0.2.1"},
		"stale.ru":     {Verdict: probe.Clean, ExpiresAt: now.Add(-time.Hour), TestedIP: "192.0.2.2"},
		"noip.ru":      {Verdict: probe.Clean, ExpiresAt: live},
	}}}
	got := st.verifiedIPs("net")
	want := []string{"2001:db8::1/128", "212.12.2.243/32"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// A client dialling bare addresses never produces a name; its servers must
// still count as in use, or an expired verdict is never re-checked.
func TestTouchIPs(t *testing.T) {
	old := time.Now().Add(-72 * time.Hour)
	st := &state{Networks: map[string]map[string]*entry{"net": {
		"kirov.qms.ru": {Verdict: probe.Clean, TestedIP: "46.61.250.186", DecidedAt: old, ExpiresAt: old},
		"other.ru":     {Verdict: probe.Clean, TestedIP: "192.0.2.9", DecidedAt: old, ExpiresAt: old},
	}}}
	if got := st.expired("net", 24*time.Hour); len(got) != 0 {
		t.Fatalf("before: %v should look abandoned", got)
	}
	if n := st.touchIPs("net", []string{"46.61.250.186", "not-an-ip"}); n != 1 {
		t.Fatalf("touched %d, want 1", n)
	}
	got := st.expired("net", 24*time.Hour)
	if len(got) != 1 || got[0] != "kirov.qms.ru" {
		t.Fatalf("after: got %v, want [kirov.qms.ru]", got)
	}
}

// Names the user's lists route themselves, and skipped ones, keep no
// verdict: a pinned host's CLEAN made its siblings a family.
func TestDropPinnedAndSkipped(t *testing.T) {
	live := time.Now().Add(time.Hour)
	st := &state{Networks: map[string]map[string]*entry{"n": {
		"cloudflare-ech.com": {Verdict: probe.Clean, ExpiresAt: live},
		"a.ex.com":           {Verdict: probe.Clean, ExpiresAt: live},
		"b.ex.com":           {Verdict: probe.Clean, ExpiresAt: live},
		"c.ex.com":           {Verdict: probe.Clean, ExpiresAt: live},
	}}}
	cfg := Defaults()
	pinned := map[string]bool{"c.ex.com": true}
	if n := st.drop("n", func(d string) bool { return pinned[d] || skipped(cfg, d) }); n != 2 {
		t.Fatalf("dropped %d, want 2", n)
	}
	if len(st.families("n")) != 0 {
		t.Error("two CLEAN left after the pinned one went: no family")
	}

	force := connection{Rule: "RuleSet", RulePayload: "force-tunnel"}
	preset := connection{Rule: "RuleSet", RulePayload: "preset-youtube"}
	ours := connection{Rule: "RuleSet", RulePayload: "direct-verified"}
	if !force.pinned() || !preset.pinned() || ours.pinned() {
		t.Error("pinned: force-tunnel and presets yes, the detector's own list no")
	}
}

// CLEAN verdicts made on QUIC alone are re-checked now, not a week later.
func TestQuicOnly(t *testing.T) {
	now := time.Now()
	live := now.Add(time.Hour)
	st := &state{Networks: map[string]map[string]*entry{"n": {
		"quic.example":  {Verdict: probe.Clean, ExpiresAt: live, LastSeen: now, Endpoints: []string{"quic/443"}},
		"both.example":  {Verdict: probe.Clean, ExpiresAt: live, LastSeen: now, Endpoints: []string{"quic/443", "tcp/443"}},
		"idle.example":  {Verdict: probe.Clean, ExpiresAt: live, LastSeen: now.Add(-72 * time.Hour), Endpoints: []string{"quic/443"}},
		"block.example": {Verdict: probe.BlockedQUIC, ExpiresAt: live, LastSeen: now, Endpoints: []string{"quic/443"}},
	}}}
	if got := st.quicOnly("n", 24*time.Hour); len(got) != 1 || got[0] != "quic.example" {
		t.Fatalf("got %v, want [quic.example]", got)
	}
}
