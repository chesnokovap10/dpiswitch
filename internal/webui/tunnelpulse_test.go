package webui

import (
	"encoding/json"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dpiswitch/internal/paths"
)

func assertPendingTunnels(t *testing.T, p *tunnelPulse, note string) {
	t.Helper()
	states := p.snapshot()
	for _, name := range pulseTunnels {
		st, ok := states[name]
		if !ok || st.Alive || st.Note != note {
			t.Fatalf("%s: %+v (present=%v), want pending %q", name, st, ok, note)
		}
	}
}

func TestTunnelPulseCoreLifecycle(t *testing.T) {
	var calls int
	p := newTunnelPulse(func(string) (bool, string) {
		calls++
		return true, "42 ms"
	}, func(string) {})
	p.coreState("run1", false)
	p.look(time.Now())
	for _, name := range pulseTunnels {
		p.recv[name], p.fail[name], p.asked[name] = time.Now(), time.Now(), time.Now()
	}
	p.expectRestart("run1")
	assertPendingTunnels(t, p, "core API not responding: restarting")
	if len(p.recv)+len(p.fail)+len(p.asked) != 0 {
		t.Fatal("traffic from the previous core survived the reset")
	}
	p.coreState("run1", false) // the outgoing core can still answer
	p.look(time.Now())
	if calls != 2 {
		t.Fatal("queried the outgoing core while waiting for its replacement")
	}
	assertPendingTunnels(t, p, "core API not responding: restarting")
	p.coreState("", true)
	p.coreState("run2", false)
	assertPendingTunnels(t, p, "not checked yet")
	p.look(time.Now())
	if st, _ := p.get("awg1"); !st.Alive {
		t.Fatal("new core's health result was not published")
	}
	// A restart entirely between two live polls still invalidates both.
	p.coreState("run3", false)
	assertPendingTunnels(t, p, "not checked yet")
	p.look(time.Now())
	p.coreState("run3", false)
	p.expectRestart("run2") // a late save response must not reset run3
	if st, _ := p.get("awg1"); !st.Alive {
		t.Fatal("same run or a late response reset an already checked core")
	}
}

func TestTunnelPulseRejectsPreviousRunResults(t *testing.T) {
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var block atomic.Bool
	block.Store(true)
	p := newTunnelPulse(func(name string) (bool, string) {
		if name == "awg2" && block.Load() {
			close(entered)
			<-release
		}
		return true, "42 ms"
	}, func(string) {})
	p.coreState("run1", false)
	go func() { defer close(done); p.look(time.Now()) }()
	// The first result must not appear alone while the second is pending.
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("health call did not start")
	}
	assertPendingTunnels(t, p, "not checked yet")
	p.expectRestart("run1")
	p.coreState("run2", false)
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("old health call did not finish")
	}
	assertPendingTunnels(t, p, "not checked yet")
	block.Store(false)
	p.look(time.Now())
	for name, st := range p.snapshot() {
		if !st.Alive || st.Note != "42 ms" {
			t.Fatalf("new result for %s: %+v", name, st)
		}
	}
}

// The traffic says when the last check is out of date: dials failing with
// nothing coming in, on a tunnel found alive; bytes coming in, on one found
// dead. Then, and then only, the core is asked to check it now -- not more
// often than pulseAgain -- and a change is told at once.
func TestTunnelPulse(t *testing.T) {
	alive := map[string]bool{"awg1": true, "awg2": true}
	var asked []string
	p := newTunnelPulse(
		func(x string) (bool, string) { return alive[x], "note" },
		func(x string) {
			asked = append(asked, x)
			alive[x] = !alive[x] // the check finds what the traffic said
		})
	drain := func() bool {
		select {
		case <-p.changed:
			return true
		default:
			return false
		}
	}
	now := time.Now()
	p.look(now)
	if !drain() || len(asked) != 0 {
		t.Fatalf("first look: asked %v", asked)
	}
	// quiet: nothing to say, nothing asked
	p.look(now.Add(time.Second))
	if drain() || len(asked) != 0 {
		t.Fatalf("quiet: asked %v", asked)
	}
	// dials through awg1 fail, nothing comes in: checked now, found dead
	now = now.Add(10 * time.Second)
	p.fail["awg1"] = now
	p.look(now)
	if len(asked) != 1 || asked[0] != "awg1" {
		t.Fatalf("failing: asked %v", asked)
	}
	if s, ok := p.get("awg1"); !ok || s.Alive || !drain() {
		t.Fatalf("not told dead: %+v %v", s, ok)
	}
	// bytes come in through it at once: too soon to ask again
	p.recv["awg1"] = now.Add(time.Second)
	p.look(now.Add(time.Second))
	if len(asked) != 1 {
		t.Fatalf("asked again within %v: %v", pulseAgain, asked)
	}
	// and later: checked, found alive
	now = now.Add(pulseAgain + time.Second)
	p.recv["awg1"] = now
	p.look(now)
	if len(asked) != 2 {
		t.Fatalf("bytes on a dead tunnel: asked %v", asked)
	}
	if s, _ := p.get("awg1"); !s.Alive || !drain() {
		t.Fatal("not told alive")
	}
	// dials failing while bytes still come in: the tunnel works, the sites
	// do not -- nothing asked
	now = now.Add(pulseAgain + time.Second)
	p.recv["awg1"], p.fail["awg1"] = now, now
	p.look(now)
	if len(asked) != 2 {
		t.Fatalf("failing sites took for a dead tunnel: %v", asked)
	}
}

// The tunnels' answer names the network the service works in: a page that
// sees it change draws itself anew at once.
func TestTunnelsSayNetwork(t *testing.T) {
	s, _ := testServer(t)
	if err := os.WriteFile(paths.State(), []byte(`{"networks":{"AS7":{}},"current":"AS7"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	b := do(t, s.Handler(), "GET", "/api/tunnels", nil, nil).Body.String()
	if !strings.Contains(b, `"net":"AS7"`) {
		t.Fatalf("no network in %s", b)
	}
}

// Only the tunnels the core's config has are asked after: one it has not
// was asked every second all the same.
func TestTunnelPulseAsksItsTunnels(t *testing.T) {
	var asked []string
	p := newTunnelPulse(func(x string) (bool, string) { asked = append(asked, x); return true, "note" }, func(string) {})
	p.names = func() []string { return []string{"awg1"} }
	p.look(time.Now())
	if len(asked) != 1 || asked[0] != "awg1" {
		t.Errorf("asked after %v, want awg1 alone", asked)
	}
	if _, ok := p.get("awg2"); ok {
		t.Error("a state kept for a tunnel the config has not")
	}
}

// The tunnels' answer carries the header's chip and the overview's pill
// drawn by the templates the pages are drawn by: ui.js only puts them in.
func TestTunnelsDrawn(t *testing.T) {
	s, _ := testServer(t)
	pulse.mu.Lock()
	was := pulse.state
	pulse.state = map[string]tunnelState{
		"awg1": {Alive: true, Note: "42 ms", at: time.Now()},
		"awg2": {Alive: false, Note: "", at: time.Now()},
	}
	pulse.mu.Unlock()
	t.Cleanup(func() { pulse.mu.Lock(); pulse.state = was; pulse.mu.Unlock() })
	var got struct{ Awg1, Awg2 struct{ Chip, Pill string } }
	b := do(t, s.Handler(), "GET", "/api/tunnels", nil, nil).Body.Bytes()
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	if c := got.Awg1.Chip; !strings.Contains(c, `class="dot ok"`) || !strings.Contains(c, "awg1 42 ms") {
		t.Fatalf("awg1's chip: %q", c)
	}
	if p := got.Awg1.Pill; !strings.Contains(p, `class="pill ok"`) || !strings.Contains(p, "responding · 42 ms") {
		t.Fatalf("awg1's pill: %q", p)
	}
	if c := got.Awg2.Chip; !strings.Contains(c, `class="dot bad"`) || !strings.Contains(c, "not responding") {
		t.Fatalf("awg2's chip: %q", c)
	}
	if p := got.Awg2.Pill; !strings.Contains(p, `class="pill bad"`) {
		t.Fatalf("awg2's pill: %q", p)
	}
}

// Both render paths use the same wording and warning color for states
// that have no check result yet. Neither implies a healthy or dead tunnel.
func TestTunnelPendingRendering(t *testing.T) {
	for _, tc := range []struct {
		note   string
		alive  bool
		en, ru string
	}{
		{"not checked yet", true, "Checking connection…", "проверка соединения…"},
		{"core API not responding: EOF", false, "Waiting for core…", "ожидание ядра…"},
	} {
		for lang, label := range map[string]string{"en": tc.en, "ru": tc.ru} {
			a := tunArg{V: &view{Lang: lang}, Name: "awg1", Alive: tc.alive, Note: tc.note}
			for _, name := range []string{"tunchip", "tunpill"} {
				body, err := drawn(name, a)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(body, label) || !strings.Contains(body, "warn") ||
					strings.Contains(body, `class="dot ok"`) || strings.Contains(body, `class="pill bad"`) {
					t.Fatalf("%s %s %q: %s", lang, name, tc.note, body)
				}
			}
		}
	}
}
