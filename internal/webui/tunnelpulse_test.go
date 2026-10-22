package webui

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"dpiswitch/internal/paths"
)

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
