package webui

import (
	"testing"
	"time"
)

// The traffic says when the last check is out of date: dials failing with
// nothing coming in, on a tunnel found alive; bytes coming in, on one found
// dead. Then, and then only, the core is asked to check it now -- not more
// often than pulseAgain -- and a change is told at once.
func TestTunnelPulse(t *testing.T) {
	alive := map[string]bool{"awg": true, "awg2": true}
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
	// dials through awg fail, nothing comes in: checked now, found dead
	now = now.Add(10 * time.Second)
	p.fail["awg"] = now
	p.look(now)
	if len(asked) != 1 || asked[0] != "awg" {
		t.Fatalf("failing: asked %v", asked)
	}
	if s, ok := p.get("awg"); !ok || s.Alive || !drain() {
		t.Fatalf("not told dead: %+v %v", s, ok)
	}
	// bytes come in through it at once: too soon to ask again
	p.recv["awg"] = now.Add(time.Second)
	p.look(now.Add(time.Second))
	if len(asked) != 1 {
		t.Fatalf("asked again within %v: %v", pulseAgain, asked)
	}
	// and later: checked, found alive
	now = now.Add(pulseAgain + time.Second)
	p.recv["awg"] = now
	p.look(now)
	if len(asked) != 2 {
		t.Fatalf("bytes on a dead tunnel: asked %v", asked)
	}
	if s, _ := p.get("awg"); !s.Alive || !drain() {
		t.Fatal("not told alive")
	}
	// dials failing while bytes still come in: the tunnel works, the sites
	// do not -- nothing asked
	now = now.Add(pulseAgain + time.Second)
	p.recv["awg"], p.fail["awg"] = now, now
	p.look(now)
	if len(asked) != 2 {
		t.Fatalf("failing sites took for a dead tunnel: %v", asked)
	}
}
