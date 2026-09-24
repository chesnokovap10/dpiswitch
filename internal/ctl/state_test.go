package ctl

import (
	"reflect"
	"sort"
	"strings"
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

// The tested node of each live CLEAN verdict, for connections that reach a
// bare address (a speedtest client does) -- only on the TCP ports probed by
// plain connect, and only for a connection that carries no name.
func TestVerifiedAddrs(t *testing.T) {
	now := time.Now()
	live := now.Add(time.Hour)
	st := &state{Networks: map[string]map[string]*entry{"net": {
		"tula.qms.ru": {Verdict: probe.Clean, ExpiresAt: live, TestedIP: "212.12.2.243",
			Endpoints: []string{"tcp/20000", "tcp/443", "quic/443"}},
		// the same node under another name: one rule, the ports joined
		"alias.qms.ru": {Verdict: probe.Clean, ExpiresAt: live, TestedIP: "212.12.2.243",
			Endpoints: []string{"tcp/8080"}},
		"v6.example": {Verdict: probe.Clean, ExpiresAt: live, TestedIP: "2001:db8::1",
			Endpoints: []string{"tcp/5228"}},
		// a name's 443 and 80 are TLS and HTTP with that name: no rule
		"web.example": {Verdict: probe.Clean, ExpiresAt: live, TestedIP: "192.0.2.3",
			Endpoints: []string{"tcp/443", "tcp/80"}},
		// a bare address was probed by plain connect on every port it has
		"@192.0.2.4": {Verdict: probe.Clean, ExpiresAt: live, TestedIP: "192.0.2.4", Endpoints: []string{"tcp/80"}},
		"blocked.ru": {Verdict: probe.BlockedTLS, ExpiresAt: live, TestedIP: "192.0.2.1", Endpoints: []string{"tcp/20000"}},
		"stale.ru":   {Verdict: probe.Clean, ExpiresAt: now.Add(-time.Hour), TestedIP: "192.0.2.2", Endpoints: []string{"tcp/20000"}},
		"noip.ru":    {Verdict: probe.Clean, ExpiresAt: live, Endpoints: []string{"tcp/20000"}},
		"legacy.ru":  {Verdict: probe.Clean, ExpiresAt: live, TestedIP: "192.0.2.5"}, // probed on 443 before ports were kept
	}}}
	got := st.verifiedAddrs("net")
	nameless := ",(NOT,((DOMAIN-REGEX,.))))"
	want := []string{
		"AND,((NETWORK,TCP),(DST-PORT,8080/20000),(IP-CIDR,212.12.2.243/32,no-resolve)" + nameless,
		"AND,((NETWORK,TCP),(DST-PORT,5228),(IP-CIDR6,2001:db8::1/128,no-resolve)" + nameless,
		"AND,((NETWORK,TCP),(DST-PORT,80),(IP-CIDR,192.0.2.4/32,no-resolve)" + nameless,
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
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

// A nameless connection the address rules sent direct, open with nothing
// back: the verdicts behind that node and port are re-checked at once.
func TestSuspectAddress(t *testing.T) {
	live := time.Now().Add(time.Hour)
	st := &state{Networks: map[string]map[string]*entry{"n": {
		"@192.0.2.4":   {Verdict: probe.Clean, ExpiresAt: live, TestedIP: "192.0.2.4", Endpoints: []string{"tcp/20000"}},
		"a.qms.ru":     {Verdict: probe.Clean, ExpiresAt: live, TestedIP: "192.0.2.4", Endpoints: []string{"tcp/20000", "tcp/443"}},
		"b.qms.ru":     {Verdict: probe.Clean, ExpiresAt: live, TestedIP: "192.0.2.4", Endpoints: []string{"tcp/8080"}},
		"other.qms.ru": {Verdict: probe.Clean, ExpiresAt: live, TestedIP: "192.0.2.9", Endpoints: []string{"tcp/20000"}},
	}}}
	conn := func(port string, down int64, age time.Duration) connection {
		c := connection{Chains: []string{"DIRECT"}, Rule: "RuleSet", RulePayload: "direct-verified-addr",
			Download: down, Start: time.Now().Add(-age).Format(time.RFC3339Nano)}
		c.Metadata.DestinationIP, c.Metadata.DestinationPort, c.Metadata.Network = "192.0.2.4", port, "tcp"
		return c
	}
	cfg := Config{AddrProvider: "direct-verified-addr"}
	got := suspectDirect(cfg, st, "n", []connection{conn("20000", 0, time.Minute)})
	if want := []string{"@192.0.2.4", "a.qms.ru"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// data came back, or it has only just opened: nothing suspicious
	if got := suspectDirect(cfg, st, "n", []connection{conn("20000", 10, time.Minute), conn("20000", 0, time.Second)}); len(got) != 0 {
		t.Fatalf("got %v, want nothing", got)
	}
	if got := st.cleanAddrs("n"); len(got) != 1 || got[0] != "@192.0.2.4" {
		t.Fatalf("clean addresses for the UI: %v", got)
	}
}
