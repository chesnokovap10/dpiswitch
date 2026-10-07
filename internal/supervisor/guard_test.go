package supervisor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/udpguard"
)

type fakeGuard struct {
	mu      sync.Mutex
	in      bool
	ensures int
	lifts   int
	err     error // what Ensure answers; nothing is put in then
	cores   []string
	// the engine's record: the packets, by local address, it reports dropped
	drops map[netip.AddrPort]bool
}

func (f *fakeGuard) Ensure(core string) (udpguard.Change, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensures++
	f.cores = append(f.cores, core)
	if f.err != nil {
		f.in = false
		return udpguard.Put, f.err
	}
	if f.in {
		return udpguard.Kept, nil
	}
	f.in = true
	return udpguard.Put, nil
}

func (f *fakeGuard) Lift() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.in {
		return false
	}
	f.in = false
	f.lifts++
	return true
}

func (f *fakeGuard) Rules() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.in {
		return 8
	}
	return 0
}

func (f *fakeGuard) Dropped(local, remote netip.AddrPort, since time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.in && remote == leakDst && f.drops[local]
}

func (f *fakeGuard) drop(local netip.AddrPort) {
	f.mu.Lock()
	if f.drops == nil {
		f.drops = map[netip.AddrPort]bool{}
	}
	f.drops[local] = true
	f.mu.Unlock()
}

func (f *fakeGuard) look() (in bool, ensures, lifts int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.in, f.ensures, f.lifts
}

func (f *fakeGuard) setErr(err error) {
	f.mu.Lock()
	f.err = err
	f.mu.Unlock()
}

// guardWorld: the setting, the adapter and the file the UI reads, as the
// tests have them
type guardWorld struct {
	mu   sync.Mutex
	on   bool
	tun  tunState
	says []udpguard.Status
	// what the test packet finds, and how many are sent
	checked bool
	probes  int
}

func (w *guardWorld) set(on bool, tun tunState) {
	w.mu.Lock()
	w.on, w.tun = on, tun
	w.mu.Unlock()
}

func (w *guardWorld) env() guardEnv {
	return guardEnv{
		on:   func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.on },
		tun:  func() tunState { w.mu.Lock(); defer w.mu.Unlock(); return w.tun },
		core: func() string { return `C:\Program Files\DPI Switch\core\mihomo.exe` },
		say:  func(st udpguard.Status) { w.mu.Lock(); w.says = append(w.says, st); w.mu.Unlock() },
		probe: func(context.Context, udpGuard) bool {
			w.mu.Lock()
			defer w.mu.Unlock()
			w.probes++
			return w.checked
		},
	}
}

func (w *guardWorld) last() udpguard.Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.says) == 0 {
		return udpguard.Status{}
	}
	return w.says[len(w.says)-1]
}

func (w *guardWorld) said() []udpguard.Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]udpguard.Status(nil), w.says...)
}

var (
	tunOK      = tunState{known: true, up: true}
	tunGone    = tunState{known: true}
	tunCut     = tunState{known: true, up: true, blocked: true}
	tunUnknown = tunState{}
)

func fastGuard(t *testing.T) {
	t.Helper()
	p, r := guardPeriod, guardRetry
	guardPeriod, guardRetry = 5*time.Millisecond, 60*time.Millisecond
	t.Cleanup(func() { guardPeriod, guardRetry = p, r })
}

// hold runs holdGuard for a core; the returned function ends it, as the
// core's stop does, and waits for it to be out
func hold(g udpGuard, w *guardWorld) (end func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); holdGuard(ctx, g, w.env()) }()
	return func() { cancel(); <-done }
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// Off, it is never put in, and the file says so.
func TestGuardOffDoesNothing(t *testing.T) {
	fastGuard(t)
	g, w := &fakeGuard{}, &guardWorld{}
	w.set(false, tunOK)
	end := hold(g, w)
	waitFor(t, "the off status", func() bool { return w.last().State == udpguard.StateOff })
	time.Sleep(40 * time.Millisecond)
	end()
	if _, ensures, _ := g.look(); ensures != 0 {
		t.Fatalf("Ensure called %d times with the setting off", ensures)
	}
	if st := w.said(); len(st) != 1 {
		t.Errorf("the status written %d times for one state: %+v", len(st), st)
	}
}

// On, it waits for the adapter, is put in when it is up and taken out when it
// goes -- and the file follows each step, once.
func TestGuardFollowsTheAdapter(t *testing.T) {
	fastGuard(t)
	g, w := &fakeGuard{}, &guardWorld{}
	w.set(true, tunGone)
	end := hold(g, w)
	defer end()

	waitFor(t, "waiting for the adapter", func() bool {
		st := w.last()
		return st.State == udpguard.StateWait && st.Why == udpguard.WhyAdapter
	})
	if in, ensures, _ := g.look(); in || ensures != 0 {
		t.Fatal("put in with no adapter")
	}

	w.set(true, tunOK)
	waitFor(t, "the guard on", func() bool { return w.last().State == udpguard.StateOn })
	if st := w.last(); st.Rules != 8 {
		t.Errorf("the status says %d filters", st.Rules)
	}
	if in, _, _ := g.look(); !in {
		t.Fatal("the status says on and the guard is not in")
	}
	// the core's own path is what it is let through by
	if g.cores[0] != `C:\Program Files\DPI Switch\core\mihomo.exe` {
		t.Errorf("Ensure for %q", g.cores[0])
	}

	// the adapter is removed under a core that goes on running
	w.set(true, tunGone)
	waitFor(t, "the guard lifted", func() bool {
		st := w.last()
		return st.State == udpguard.StateWait && st.Why == udpguard.WhyAdapter
	})
	if in, _, lifts := g.look(); in || lifts != 1 {
		t.Fatalf("in %v, lifted %d times", in, lifts)
	}

	// back: put in again
	w.set(true, tunOK)
	waitFor(t, "the guard on again", func() bool { return w.last().State == udpguard.StateOn })

	// no repeat in the file: wait, on, wait, on
	var states []string
	for _, st := range w.said() {
		states = append(states, st.State)
	}
	want := []string{"wait", "on", "wait", "on"}
	if len(states) < len(want) {
		t.Fatalf("states written: %v", states)
	}
	for i, s := range want {
		if states[i] != s {
			t.Errorf("states written: %v, want %v first", states, want)
			break
		}
	}
	for i := 1; i < len(states); i++ {
		if states[i] == states[i-1] && w.said()[i].Same(w.said()[i-1]) {
			t.Errorf("the same status written twice in a row at %d: %v", i, states)
		}
	}
}

// A core whose adapter takes nothing is no carrier: with Windows keeping the
// programs' traffic from it, blocking the physical adapters would cut every
// UDP off, and the guard is not put in.
func TestGuardWaitsWhenTheAdapterTakesNothing(t *testing.T) {
	fastGuard(t)
	g, w := &fakeGuard{}, &guardWorld{}
	w.set(true, tunCut)
	end := hold(g, w)
	defer end()
	waitFor(t, "the traffic status", func() bool {
		st := w.last()
		return st.State == udpguard.StateWait && st.Why == udpguard.WhyTraffic
	})
	time.Sleep(30 * time.Millisecond)
	if _, ensures, _ := g.look(); ensures != 0 {
		t.Fatalf("put in %d times over an adapter that takes nothing", ensures)
	}
}

// What cannot be read changes nothing: a guard in place stays in place, and
// none is put in on a guess.
func TestGuardLeavesAsIsWhenTheAdapterCannotBeRead(t *testing.T) {
	fastGuard(t)
	g, w := &fakeGuard{}, &guardWorld{}
	w.set(true, tunOK)
	end := hold(g, w)
	defer end()
	waitFor(t, "on", func() bool { return w.last().State == udpguard.StateOn })

	w.set(true, tunUnknown)
	time.Sleep(50 * time.Millisecond)
	if in, _, lifts := g.look(); !in || lifts != 0 {
		t.Fatalf("a guard in place was lifted for an unreadable adapter (in %v, lifts %d)", in, lifts)
	}
	if w.last().State != udpguard.StateOn {
		t.Errorf("the status changed to %+v", w.last())
	}
}

// Switched off with the guard in place, it is taken out.
func TestGuardSwitchedOff(t *testing.T) {
	fastGuard(t)
	g, w := &fakeGuard{}, &guardWorld{}
	w.set(true, tunOK)
	end := hold(g, w)
	defer end()
	waitFor(t, "on", func() bool { return w.last().State == udpguard.StateOn })

	w.set(false, tunOK)
	waitFor(t, "off", func() bool { return w.last().State == udpguard.StateOff })
	if in, _, lifts := g.look(); in || lifts != 1 {
		t.Fatalf("in %v, lifts %d", in, lifts)
	}
}

// A refusal is told in the file with its reason, tried again after a pause --
// not at every look -- and the guard goes in when a try gets through.
func TestGuardRefusedAndRetried(t *testing.T) {
	fastGuard(t)
	g, w := &fakeGuard{}, &guardWorld{}
	g.setErr(&udpguard.EngineError{Err: errors.New("The RPC server is unavailable.")})
	w.set(true, tunOK)
	end := hold(g, w)
	defer end()

	waitFor(t, "the failure", func() bool { return w.last().State == udpguard.StateFail })
	st := w.last()
	if st.Why != udpguard.WhyEngine || st.Err != "The RPC server is unavailable" {
		t.Fatalf("%+v", st)
	}
	// 300 ms is five retry periods and sixty looks: the tries are the pause's
	time.Sleep(300 * time.Millisecond)
	_, ensures, _ := g.look()
	if ensures < 2 || ensures > 8 {
		t.Fatalf("%d tries in 300 ms with a retry pause of 60 ms and a look every 5", ensures)
	}

	g.setErr(nil)
	waitFor(t, "the guard on after the engine is back", func() bool { return w.last().State == udpguard.StateOn })
	if in, _, _ := g.look(); !in {
		t.Fatal("on in the file, and not in")
	}
}

// A refusal of another kind is told as such.
func TestGuardRefusedByAFilter(t *testing.T) {
	fastGuard(t)
	g, w := &fakeGuard{}, &guardWorld{}
	g.setErr(errors.New("DPI Switch UDP guard: UDP to the local network (IPv6): refused"))
	w.set(true, tunOK)
	end := hold(g, w)
	defer end()
	waitFor(t, "the failure", func() bool { return w.last().State == udpguard.StateFail })
	if st := w.last(); st.Why != udpguard.WhyOther || st.Err == "" {
		t.Fatalf("%+v", st)
	}
}

// The core's end -- a stop for a restart, a crash -- takes the guard out and
// leaves the file saying what is so after it: waiting for the core when the
// setting is on, off when it is not.
func TestGuardEndsWithTheCore(t *testing.T) {
	fastGuard(t)
	for _, on := range []bool{true, false} {
		g, w := &fakeGuard{}, &guardWorld{}
		w.set(on, tunOK)
		end := hold(g, w)
		if on {
			waitFor(t, "on", func() bool { return w.last().State == udpguard.StateOn })
		} else {
			waitFor(t, "off", func() bool { return w.last().State == udpguard.StateOff })
		}
		end()
		in, _, _ := g.look()
		st := w.last()
		if in {
			t.Errorf("setting %v: the guard is still in after the core", on)
		}
		if on && (st.State != udpguard.StateWait || st.Why != udpguard.WhyCore) {
			t.Errorf("setting on: the file says %+v after the core", st)
		}
		if !on && st.State != udpguard.StateOff {
			t.Errorf("setting off: the file says %+v after the core", st)
		}
	}
}

// The adapter's state: up, ours, with a default route through it -- none of
// the three alone is enough.
func TestTunUp(t *testing.T) {
	meta := adapter{index: 34, name: "Meta", up: true}
	wifi := adapter{index: 11, name: "Wi-Fi", up: true}
	routes := map[uint32]bool{34: true, 11: true}
	for _, c := range []struct {
		name   string
		ads    []adapter
		routes map[uint32]bool
		want   bool
	}{
		{"up with a route", []adapter{wifi, meta}, routes, true},
		{"no adapter", []adapter{wifi}, routes, false},
		{"adapter down", []adapter{wifi, {index: 34, name: "Meta"}}, routes, false},
		{"no route through it", []adapter{wifi, meta}, map[uint32]bool{11: true}, false},
		{"its range, not its name", []adapter{wifi, {index: 40, name: "Tun2", up: true, v4: []net.IP{net.IPv4(198, 18, 0, 1)}}}, map[uint32]bool{40: true}, true},
		{"another VPN's adapter", []adapter{wifi, {index: 50, name: "OpenVPN", up: true}}, map[uint32]bool{50: true}, false},
		{"nothing", nil, nil, false},
	} {
		if got := tunUp(c.ads, c.routes); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// Stopping the core stops the guard first and waits for it to be out; one
// that was never started, or is stopped twice, is no trouble.
func TestStopGuard(t *testing.T) {
	fastGuard(t)
	s := New()
	s.stopGuard() // none started

	g, w := &fakeGuard{}, &guardWorld{}
	w.set(true, tunOK)
	s.guard = g
	// startGuard reads the real environment; the run it makes is here the tests'
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gctx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	s.mu.Lock()
	s.guardStop, s.guardDone = stop, done
	s.mu.Unlock()
	go func() { defer close(done); holdGuard(gctx, g, w.env()) }()
	waitFor(t, "on", func() bool { return w.last().State == udpguard.StateOn })

	s.stopGuard()
	if in, _, _ := g.look(); in {
		t.Fatal("stopGuard returned with the guard in")
	}
	s.stopGuard() // again
}

// The test packet is tried the way a program that binds to the adapter sends:
// out of every adapter that leads out, from its address. A block gives the
// sender no error, so the guard holds when the engine's record has each packet
// dropped -- and says nothing when it has not.
func TestGuardHolds(t *testing.T) {
	wifi := adapter{index: 11, name: "Wi-Fi", up: true, v4: []net.IP{net.IPv4(192, 168, 31, 250)}}
	eth := adapter{index: 12, name: "Ethernet", up: true, v4: []net.IP{net.IPv4(10, 0, 0, 5)}}
	meta := adapter{index: 34, name: "Meta", up: true, v4: []net.IP{net.IPv4(198, 18, 0, 1)}}
	apipa := adapter{index: 13, name: "Dead", up: true, v4: []net.IP{net.IPv4(169, 254, 3, 3)}}
	hyperv := adapter{index: 20, name: "Hyper-V", up: true, v4: []net.IP{net.IPv4(172, 20, 0, 1)}}
	routes := map[uint32]bool{11: true, 12: true, 34: true, 13: true}
	wifiPkt := netip.MustParseAddrPort("192.168.31.250:50001")
	ethPkt := netip.MustParseAddrPort("10.0.0.5:50002")
	unreachable := errors.New("network is unreachable")

	for _, c := range []struct {
		name       string
		ads        []adapter
		dropped    []netip.AddrPort // what the engine's record has
		sendErr    map[string]error // by address: a send that failed
		want       bool
		wantSentTo []string
	}{
		{"every packet recorded dropped", []adapter{wifi, eth}, []netip.AddrPort{wifiPkt, ethPkt}, nil, true,
			[]string{"192.168.31.250", "10.0.0.5"}},
		{"one is not in the record: the guard is not shown to hold", []adapter{wifi, eth}, []netip.AddrPort{wifiPkt}, nil, false,
			[]string{"192.168.31.250", "10.0.0.5"}},
		{"none in the record", []adapter{wifi}, nil, nil, false, []string{"192.168.31.250"}},
		{"a send that failed is not counted", []adapter{wifi, eth}, []netip.AddrPort{wifiPkt},
			map[string]error{"10.0.0.5": unreachable}, true, []string{"192.168.31.250", "10.0.0.5"}},
		{"every send failed: nothing was tried", []adapter{wifi}, nil,
			map[string]error{"192.168.31.250": unreachable}, false, []string{"192.168.31.250"}},
		{"the TUN, a link-local address, an adapter with no route are not tried", []adapter{meta, apipa, hyperv, wifi},
			[]netip.AddrPort{wifiPkt}, nil, true, []string{"192.168.31.250"}},
		{"an adapter that is down is not tried", []adapter{{index: 11, name: "Wi-Fi", v4: wifi.v4}}, nil, nil, false, nil},
		{"no adapter", nil, nil, nil, false, nil},
	} {
		g := &fakeGuard{in: true}
		for _, d := range c.dropped {
			g.drop(d)
		}
		var sent []string
		ports := map[string]netip.AddrPort{"192.168.31.250": wifiPkt, "10.0.0.5": ethPkt}
		send := func(src net.IP) (netip.AddrPort, error) {
			sent = append(sent, src.String())
			if err := c.sendErr[src.String()]; err != nil {
				return netip.AddrPort{}, err
			}
			return ports[src.String()], nil
		}
		if got := guardHolds(context.Background(), c.ads, routes, g, send, 20*time.Millisecond); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
		if strings.Join(sent, ",") != strings.Join(c.wantSentTo, ",") {
			t.Errorf("%s: sent from %v, want %v", c.name, sent, c.wantSentTo)
		}
	}
}

// The engine's record takes moments to have a drop in it: the guard is waited
// on for it, not asked once.
func TestGuardHoldsWaitsForTheRecord(t *testing.T) {
	wifi := adapter{index: 11, name: "Wi-Fi", up: true, v4: []net.IP{net.IPv4(192, 168, 31, 250)}}
	routes := map[uint32]bool{11: true}
	pkt := netip.MustParseAddrPort("192.168.31.250:50001")
	send := func(net.IP) (netip.AddrPort, error) { return pkt, nil }

	g := &fakeGuard{in: true}
	go func() { time.Sleep(80 * time.Millisecond); g.drop(pkt) }()
	start := time.Now()
	if !guardHolds(context.Background(), []adapter{wifi}, routes, g, send, 2*time.Second) {
		t.Fatal("not shown to hold, with the drop in the record 80 ms late")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("waited %v for a drop that was there at 80 ms", time.Since(start))
	}

	// and the wait ends: a record that never has it is no reason to wait for good
	g2 := &fakeGuard{in: true}
	start = time.Now()
	if guardHolds(context.Background(), []adapter{wifi}, routes, g2, send, 150*time.Millisecond) {
		t.Fatal("shown to hold with nothing in the record")
	}
	if d := time.Since(start); d < 100*time.Millisecond || d > time.Second {
		t.Fatalf("waited %v with a wait of 150 ms", d)
	}
}

// A stop of the core -- the context ends -- does not wait out the record.
func TestGuardHoldsEndsWithTheCore(t *testing.T) {
	wifi := adapter{index: 11, name: "Wi-Fi", up: true, v4: []net.IP{net.IPv4(192, 168, 31, 250)}}
	routes := map[uint32]bool{11: true}
	send := func(net.IP) (netip.AddrPort, error) { return netip.MustParseAddrPort("192.168.31.250:50001"), nil }
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(40 * time.Millisecond); cancel() }()
	start := time.Now()
	if guardHolds(ctx, []adapter{wifi}, routes, &fakeGuard{in: true}, send, 30*time.Second) {
		t.Fatal("shown to hold with nothing in the record")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("a stop of the core waited %v for the record", d)
	}
}

// The packet goes where nothing is: the documentation range, never routed.
func TestLeakDestinationIsNowhere(t *testing.T) {
	if !netip.MustParsePrefix("192.0.2.0/24").Contains(leakDst.Addr()) {
		t.Fatalf("%v is no address of the documentation range", leakDst)
	}
}

// The test packet is sent when the guard goes in -- not at each look -- and
// what it found is in the file.
func TestGuardProbesOnceAndSaysWhatItFound(t *testing.T) {
	fastGuard(t)
	for _, checked := range []bool{true, false} {
		g, w := &fakeGuard{}, &guardWorld{}
		w.checked = checked
		w.set(true, tunOK)
		end := hold(g, w)
		waitFor(t, "on", func() bool { return w.last().State == udpguard.StateOn })
		time.Sleep(40 * time.Millisecond) // many looks
		if st := w.last(); st.Checked != checked {
			t.Errorf("found %v, the file says %+v", checked, st)
		}
		w.mu.Lock()
		n := w.probes
		w.mu.Unlock()
		if n != 1 {
			t.Errorf("%d test packets for one installation", n)
		}

		// lifted and put in again: tried again
		w.set(true, tunGone)
		waitFor(t, "lifted", func() bool { return w.last().State == udpguard.StateWait })
		w.set(true, tunOK)
		waitFor(t, "on again", func() bool { return w.last().State == udpguard.StateOn })
		w.mu.Lock()
		n = w.probes
		w.mu.Unlock()
		if n != 2 {
			t.Errorf("%d test packets for two installations", n)
		}
		end()
	}
}

// At the service's start the UI is told what is so now -- waiting for the
// core with the setting on, off with it off -- whatever a service before this
// one left in the file.
func TestResetGuardStatus(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	// what the service before left: the guard in
	if err := (udpguard.Status{State: udpguard.StateOn, Rules: 8, Checked: true}).Save(paths.UDPGuard()); err != nil {
		t.Fatal(err)
	}
	resetGuardStatus()
	if st, ok := udpguard.Load(paths.UDPGuard()); !ok || st.State != udpguard.StateOff {
		t.Fatalf("with the setting off: %+v, %v", st, ok)
	}
	if _, err := ctl.UpdateSettings(paths.Settings(), func(s *ctl.Settings) error { s.UDPGuard = true; return nil }); err != nil {
		t.Fatal(err)
	}
	resetGuardStatus()
	if st, ok := udpguard.Load(paths.UDPGuard()); !ok || st.State != udpguard.StateWait || st.Why != udpguard.WhyCore || st.Checked {
		t.Fatalf("with the setting on: %+v, %v", st, ok)
	}
}
