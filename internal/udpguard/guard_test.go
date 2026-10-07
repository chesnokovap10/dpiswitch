package udpguard

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeEngine stands in for the Windows Filtering Platform: the tests have no
// right to put filters into it, and no wish to.
type fakeEngine struct {
	p      plan
	dead   bool // the engine restarted: the filters are gone
	closed int
	drops  map[[2]netip.AddrPort]bool // the packets it reports dropped
}

func (f *fakeEngine) alive() bool { return !f.dead }
func (f *fakeEngine) close()      { f.closed++ }
func (f *fakeEngine) dropped(local, remote netip.AddrPort, since time.Time) bool {
	return f.drops[[2]netip.AddrPort{local, remote}]
}

type fakeWorld struct {
	engines []*fakeEngine
	fail    error // what the next opens answer
}

func (w *fakeWorld) guard() *Guard {
	return &Guard{open: func(p plan) (engine, error) {
		if w.fail != nil {
			return nil, w.fail
		}
		e := &fakeEngine{p: p}
		w.engines = append(w.engines, e)
		return e, nil
	}}
}

func otherExe(t *testing.T) string {
	t.Helper()
	p := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	if _, err := os.Stat(p); err != nil {
		t.Skip("no cmd.exe to stand in for another core")
	}
	return p
}

// One installation, looked at on every call after it and not made twice.
func TestEnsurePutsOnce(t *testing.T) {
	var w fakeWorld
	g := w.guard()
	exe := testExe(t)
	for i := 0; i < 3; i++ {
		ch, err := g.Ensure(exe)
		if err != nil {
			t.Fatal(err)
		}
		if want := map[bool]Change{true: Put, false: Kept}[i == 0]; ch != want {
			t.Errorf("call %d: %v, want %v", i, ch, want)
		}
	}
	if len(w.engines) != 1 || g.Rules() != 8 || w.engines[0].p.core != exe {
		t.Fatalf("engines %d, rules %d", len(w.engines), g.Rules())
	}
}

// The engine drops dynamic filters when its service restarts, and the guard
// is none then. The next call finds that and puts it in again, the old
// session let go.
func TestEnsureReplacesWhatTheEngineLost(t *testing.T) {
	var w fakeWorld
	g := w.guard()
	exe := testExe(t)
	if _, err := g.Ensure(exe); err != nil {
		t.Fatal(err)
	}
	w.engines[0].dead = true
	ch, err := g.Ensure(exe)
	if err != nil || ch != Replaced {
		t.Fatalf("%v, %v", ch, err)
	}
	if len(w.engines) != 2 || w.engines[0].closed != 1 || w.engines[1].closed != 0 {
		t.Fatalf("the dead session was not let go, or the new one was: %d engines, closed %d/%d",
			len(w.engines), w.engines[0].closed, w.engines[1].closed)
	}
	// and the new one is kept
	if ch, _ := g.Ensure(exe); ch != Kept {
		t.Fatalf("the new one is not kept: %v", ch)
	}
}

// A core at another path -- the service's own binary replaced and extracted
// elsewhere -- is let through by its own path, not the old one's.
func TestEnsureFollowsTheCore(t *testing.T) {
	var w fakeWorld
	g := w.guard()
	if _, err := g.Ensure(testExe(t)); err != nil {
		t.Fatal(err)
	}
	other := otherExe(t)
	if ch, err := g.Ensure(other); err != nil || ch != Replaced {
		t.Fatalf("%v, %v", ch, err)
	}
	if len(w.engines) != 2 || w.engines[1].p.core != other || w.engines[0].closed != 1 {
		t.Fatalf("%d engines", len(w.engines))
	}
}

// A refusal leaves no guard half in place, is told as what it is, and the
// next call tries again.
func TestEnsureFails(t *testing.T) {
	var w fakeWorld
	g := w.guard()
	exe := testExe(t)

	w.fail = &EngineError{errors.New("RPC server unavailable")}
	_, err := g.Ensure(exe)
	if err == nil || Why(err) != WhyEngine {
		t.Fatalf("%v is not an engine failure", err)
	}
	if g.Rules() != 0 || g.Lift() {
		t.Fatal("a guard is held after a refusal")
	}

	w.fail = errors.New("a filter refused")
	if _, err := g.Ensure(exe); err == nil || Why(err) != WhyOther {
		t.Fatalf("%v is not another failure", err)
	}

	w.fail = nil
	if ch, err := g.Ensure(exe); err != nil || ch != Put {
		t.Fatalf("no new try after the refusals: %v, %v", ch, err)
	}

	// a core that is not there: nothing is opened at all
	n := len(w.engines)
	if _, err := w.guard().Ensure(`C:\no\such\mihomo.exe`); err == nil || len(w.engines) != n {
		t.Fatalf("a plan was opened for a core that is not there: %v", err)
	}
}

// A guard whose engine lost it is replaced, and if that cannot be done it is
// not held as if it were there.
func TestEnsureLostAndNotReplaced(t *testing.T) {
	var w fakeWorld
	g := w.guard()
	exe := testExe(t)
	if _, err := g.Ensure(exe); err != nil {
		t.Fatal(err)
	}
	w.engines[0].dead = true
	w.fail = &EngineError{errors.New("the service is stopped")}
	if _, err := g.Ensure(exe); err == nil {
		t.Fatal("no error with the engine gone")
	}
	if g.Rules() != 0 {
		t.Fatalf("%d rules held for a guard that is not there", g.Rules())
	}
	if g.Lift() {
		t.Fatal("a lift of nothing said it lifted something")
	}
}

func TestLift(t *testing.T) {
	var w fakeWorld
	g := w.guard()
	if g.Lift() {
		t.Fatal("lifted what was never put")
	}
	if _, err := g.Ensure(testExe(t)); err != nil {
		t.Fatal(err)
	}
	if !g.Lift() || w.engines[0].closed != 1 || g.Rules() != 0 {
		t.Fatal("the guard was not taken out")
	}
	if g.Lift() || w.engines[0].closed != 1 {
		t.Fatal("a second lift took something out again")
	}
	// and it can be put again after
	if ch, err := g.Ensure(testExe(t)); err != nil || ch != Put || len(w.engines) != 2 {
		t.Fatalf("%v, %v", ch, err)
	}
}

// The guard answers for the engine's record of dropped packets, and for none
// with no guard in place.
func TestDropped(t *testing.T) {
	var w fakeWorld
	g := w.guard()
	local, remote := netip.MustParseAddrPort("192.168.31.250:50000"), netip.MustParseAddrPort("192.0.2.1:9")
	if g.Dropped(local, remote, time.Now()) {
		t.Fatal("a drop reported with no guard in place")
	}
	if _, err := g.Ensure(testExe(t)); err != nil {
		t.Fatal(err)
	}
	if g.Dropped(local, remote, time.Now()) {
		t.Fatal("a drop reported that the engine did not record")
	}
	w.engines[0].drops = map[[2]netip.AddrPort]bool{{local, remote}: true}
	if !g.Dropped(local, remote, time.Now()) {
		t.Fatal("the engine's record of a drop is not passed on")
	}
	if g.Dropped(netip.MustParseAddrPort("192.168.31.250:50001"), remote, time.Now()) {
		t.Fatal("another flow's drop taken for this one's")
	}
	g.Lift()
	if g.Dropped(local, remote, time.Now()) {
		t.Fatal("a drop reported after the lift")
	}
}
