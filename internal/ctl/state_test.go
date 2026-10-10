package ctl

import (
	"os"
	"path/filepath"
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

// Another network nothing has gone through for the term goes whole, its
// IPv6 memo with it; one used within it stays whole, and so does the one the
// machine is on, however old its names.
func TestDropStaleNetworks(t *testing.T) {
	now := time.Now()
	old := now.Add(-40 * 24 * time.Hour)
	st := &state{
		Networks: map[string]map[string]*entry{
			"home":  {"a.example": {Verdict: probe.Clean, DecidedAt: old, LastSeen: old}},
			"hotel": {"b.example": {Verdict: probe.Clean, DecidedAt: old, LastSeen: old}, "c.example": {DecidedAt: old}},
			"phone": {"d.example": {DecidedAt: old, LastSeen: old}, "e.example": {DecidedAt: old, LastSeen: now.Add(-time.Hour)}},
			"empty": {},
		},
		V6: map[string]*v6Memo{"hotel": {Misses: 1}},
	}
	nets, names := st.dropStale("home", staleNetwork)
	if nets != 2 || names != 2 {
		t.Fatalf("dropped %d networks, %d names; want 2, 2", nets, names)
	}
	for _, id := range []string{"hotel", "empty"} {
		if _, ok := st.Networks[id]; ok {
			t.Errorf("%s kept", id)
		}
	}
	if _, ok := st.V6["hotel"]; ok {
		t.Error("the dropped network's IPv6 memo kept")
	}
	if len(st.Networks["home"]) != 1 || len(st.Networks["phone"]) != 2 {
		t.Fatalf("left: %v", st.Networks)
	}
}

// What a start offline filed under no network is not loaded, nor is that
// taken for the network the machine is on.
func TestLoadStateDropsNoNetwork(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	b := `{"networks":{"unknown":{"x.example":{"verdict":"CLEAN"}},"AS1":{"y.example":{"verdict":"CLEAN"}}},` +
		`"current":"unknown","v6":{"unknown":{"misses":2}}}`
	if err := os.WriteFile(p, []byte(b), 0o644); err != nil {
		t.Fatal(err)
	}
	st := loadState(p)
	if _, ok := st.Networks[noNetwork]; ok || len(st.Networks["AS1"]) != 1 || st.Current != "" || st.V6[noNetwork] != nil {
		t.Fatalf("%+v", st)
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
	held := func(d string) bool { return pinned[d] || skipped(cfg, d) }
	if n := st.park("n", held); n != 2 {
		t.Fatalf("set aside %d, want 2", n)
	}
	if len(st.families("n")) != 0 {
		t.Error("two CLEAN left after the pinned one went: no family")
	}
	if n := st.unpark("n", held); n != 0 {
		t.Fatalf("put back %d while still held, want 0", n)
	}

	// the list lets c.ex.com go: its verdict comes back, not a new check;
	// one made meanwhile wins over the one set aside
	pinned = map[string]bool{}
	st.Networks["n"]["c.ex.com"] = &entry{Verdict: probe.BlockedTLS, ExpiresAt: live}
	if n := st.unpark("n", held); n != 0 {
		t.Fatalf("put back %d, want 0: c.ex.com has a newer verdict", n)
	}
	if e, _ := st.get("n", "c.ex.com"); e.Verdict != probe.BlockedTLS {
		t.Errorf("c.ex.com: %v, want the newer BLOCKED_TLS", e.Verdict)
	}
	if _, ok := st.Parked["n"]["c.ex.com"]; ok {
		t.Error("c.ex.com still set aside")
	}
	if _, ok := st.Parked["n"]["cloudflare-ech.com"]; !ok {
		t.Error("cloudflare-ech.com is skipped: it stays aside")
	}
	st.Networks["n"]["c.ex.com"] = &entry{Verdict: probe.Clean, ExpiresAt: live}
	st.park("n", func(d string) bool { return d == "c.ex.com" })
	if n := st.unpark("n", held); n != 1 {
		t.Fatalf("put back %d, want 1", n)
	}
	if len(st.families("n")) != 1 {
		t.Error("c.ex.com back: the family of three again")
	}

	// a reset and a forgotten name take what is aside too
	st.park("n", func(d string) bool { return d == "a.ex.com" })
	st.forgetVerdicts("n", []string{"a.ex.com"})
	if _, ok := st.Parked["n"]["a.ex.com"]; ok {
		t.Error("a.ex.com forgotten from the UI, still set aside")
	}
	st.resetVerdicts("n")
	if len(st.Parked["n"]) != 0 {
		t.Errorf("after a reset %d still set aside", len(st.Parked["n"]))
	}

	force := connection{Rule: "RuleSet", RulePayload: "force-tunnel"}
	preset := connection{Rule: "RuleSet", RulePayload: PresetsProvider}
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

// The watcher looks less often as the connection table grows, never less
// than every five steps.
func TestWatchStep(t *testing.T) {
	for _, tc := range []struct {
		conns int
		want  time.Duration
	}{
		{0, time.Second}, {44, time.Second}, {399, time.Second},
		{400, 2 * time.Second}, {1000, 3 * time.Second},
		{1599, 4 * time.Second}, {1600, 5 * time.Second}, {50000, 5 * time.Second},
	} {
		if got := watchStep(time.Second, tc.conns); got != tc.want {
			t.Errorf("%d connections: %s, want %s", tc.conns, got, tc.want)
		}
	}
}

// A reset drops the names waiting for their check after being dropped by
// hand, and a gateway's memory folded into its ISP's takes along what was set
// aside and dropped under it.
func TestResetAndMergeCarryTheRest(t *testing.T) {
	st := &state{Networks: map[string]map[string]*entry{}}
	now := time.Now()
	e := func() *entry { return &entry{Verdict: probe.Clean, DecidedAt: now, ExpiresAt: now.Add(time.Hour)} }
	st.put("gw", "a.ex.com", e())
	st.put("gw", "b.ex.com", e())
	st.put("gw", "held.ex.com", e())
	st.park("gw", func(d string) bool { return d == "held.ex.com" })
	st.forgetVerdicts("gw", []string{"b.ex.com"})
	st.attach("gw", "AS1", "192.0.2.1")
	st.learnV6("gw", v6Misses, false)
	st.mergeInto("AS1")
	if !st.directNoV6("AS1") || st.V6["gw"] != nil {
		t.Error("what the gateway's probes showed of IPv6 did not go to the ISP's memory")
	}
	// a name dropped by hand long ago waits for nothing: forget drops it,
	// and a network dropped whole takes its own along
	st.Pending["AS1"]["old.ex.com"] = now.Add(-2 * pendingTerm)
	st.Pending["gone"] = map[string]time.Time{"x.ex.com": now}
	st.Networks["gone"] = map[string]*entry{}
	st.forget("AS1", time.Hour)
	st.dropStale("AS1", time.Hour)
	if _, ok := st.Pending["AS1"]["old.ex.com"]; ok || st.Pending["gone"] != nil {
		t.Errorf("names past their wait, or of a network dropped, still wait: %v", st.Pending)
	}
	if _, ok := st.Parked["AS1"]["held.ex.com"]; !ok {
		t.Error("the verdict set aside under the gateway did not go to the ISP's memory")
	}
	if _, ok := st.Pending["AS1"]["b.ex.com"]; !ok {
		t.Error("the name dropped by hand under the gateway did not go to the ISP's memory")
	}
	if len(st.Parked["gw"])+len(st.Pending["gw"]) != 0 {
		t.Error("the gateway's memory kept what was set aside or dropped")
	}
	st.resetVerdicts("AS1")
	if len(st.Pending["AS1"]) != 0 {
		t.Errorf("after a reset %d names still wait for a check", len(st.Pending["AS1"]))
	}
	// a verdict read is a copy: changing it changes nothing in memory
	st.put("AS1", "c.ex.com", e())
	got, _ := st.get("AS1", "c.ex.com")
	got.Verdict = probe.BlockedTLS
	if again, _ := st.get("AS1", "c.ex.com"); again.Verdict != probe.Clean {
		t.Error("a verdict read was memory's own, not a copy")
	}
}
