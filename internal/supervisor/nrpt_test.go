package supervisor

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"dpiswitch/internal/nrpt"
)

// fakeNRPT: the registry's rule, in memory
type fakeNRPT struct {
	mu     sync.Mutex
	in     bool
	policy bool
	putErr error
	// ignored: the DNS client's table lacks the rule written; effErr: it
	// cannot be read
	ignored bool
	effErr  error
}

func (f *fakeNRPT) Effective(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.in && !f.ignored, f.effErr
}

func (f *fakeNRPT) Put() (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.putErr != nil {
		return false, f.putErr
	}
	was := f.in
	f.in = true
	return !was, nil
}

func (f *fakeNRPT) Lift() (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	was := f.in
	f.in = false
	return was, nil
}

func (f *fakeNRPT) Overridden() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.policy
}

func (f *fakeNRPT) set(fn func(*fakeNRPT)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeNRPT) isIn() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.in
}

// The rule stands while the setting is on and the adapter up and taking the
// traffic, and goes the moment any of it stops -- and with the core.
func TestHoldNRPT(t *testing.T) {
	was := guardPeriod
	guardPeriod = 5 * time.Millisecond
	defer func() { guardPeriod = was }()

	var mu sync.Mutex
	on, tun := true, tunState{known: true, up: true}
	var said []nrpt.Status
	env := nrptEnv{
		on:  func() bool { mu.Lock(); defer mu.Unlock(); return on },
		tun: func() tunState { mu.Lock(); defer mu.Unlock(); return tun },
		say: func(st nrpt.Status) { mu.Lock(); said = append(said, st); mu.Unlock() },
	}
	last := func() nrpt.Status {
		mu.Lock()
		defer mu.Unlock()
		if len(said) == 0 {
			return nrpt.Status{}
		}
		return said[len(said)-1]
	}
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for end := time.Now().Add(2 * time.Second); !cond(); {
			if time.Now().After(end) {
				t.Fatalf("%s: last said %+v", what, last())
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
	r := &fakeNRPT{}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { holdNRPT(ctx, r, env); close(done) }()

	waitFor("put in", func() bool { return r.isIn() && last().State == nrpt.StateOn })

	mu.Lock()
	tun.up = false
	mu.Unlock()
	waitFor("the adapter gone", func() bool { return !r.isIn() && last().Why == nrpt.WhyAdapter })

	mu.Lock()
	tun.up = true
	tun.blocked = true
	mu.Unlock()
	waitFor("the traffic kept from the adapter", func() bool { return !r.isIn() && last().Why == nrpt.WhyTraffic })

	mu.Lock()
	tun.blocked = false
	mu.Unlock()
	waitFor("back", func() bool { return r.isIn() })

	// unread adapters change nothing: the rule stays
	mu.Lock()
	tun.known = false
	mu.Unlock()
	time.Sleep(30 * time.Millisecond)
	if !r.isIn() {
		t.Fatal("taken out with the adapters unread")
	}
	mu.Lock()
	tun.known = true
	mu.Unlock()

	r.set(func(f *fakeNRPT) { f.policy = true })
	waitFor("Group Policy's rules", func() bool { return !r.isIn() && last().Why == nrpt.WhyPolicy })
	r.set(func(f *fakeNRPT) { f.policy = false; f.putErr = errors.New("Access is denied.") })
	waitFor("refused", func() bool { s := last(); return s.State == nrpt.StateFail && s.Err == "Access is denied" })
	r.set(func(f *fakeNRPT) { f.putErr = nil })
	waitFor("put in again", func() bool { return r.isIn() && last().State == nrpt.StateOn })

	mu.Lock()
	on = false
	mu.Unlock()
	waitFor("switched off", func() bool { return !r.isIn() && last().State == nrpt.StateOff })
	mu.Lock()
	on = true
	mu.Unlock()
	waitFor("on again", func() bool { return r.isIn() })

	// written, and the DNS client does not apply it: not said in place
	// (the review of 20.10); once it does, it is
	wasRecheck := nrptRecheck
	nrptRecheck = 20 * time.Millisecond
	defer func() { nrptRecheck = wasRecheck }()
	r.set(func(f *fakeNRPT) { f.ignored = true })
	mu.Lock()
	on = false
	mu.Unlock()
	waitFor("off before the ignored one", func() bool { return last().State == nrpt.StateOff })
	mu.Lock()
	on = true
	mu.Unlock()
	waitFor("not applied", func() bool { s := last(); return r.isIn() && s.State == nrpt.StateFail && s.Why == nrpt.WhyIgnored })
	r.set(func(f *fakeNRPT) { f.ignored = false })
	waitFor("applied later", func() bool { return last().State == nrpt.StateOn })
	// a table that cannot be read leaves the rule taken as written
	r.set(func(f *fakeNRPT) { f.ignored, f.effErr = true, errors.New("no PowerShell") })
	mu.Lock()
	on = false
	mu.Unlock()
	waitFor("off before the unreadable one", func() bool { return last().State == nrpt.StateOff })
	mu.Lock()
	on = true
	mu.Unlock()
	waitFor("unreadable: in place", func() bool { return r.isIn() && last().State == nrpt.StateOn })
	time.Sleep(50 * time.Millisecond)
	if last().State != nrpt.StateOn {
		t.Fatalf("unreadable table taken for not applied: %+v", last())
	}
	r.set(func(f *fakeNRPT) { f.ignored, f.effErr = false, nil })

	// the core's end takes it out, and says the setting waits for a core
	stop()
	<-done
	if r.isIn() {
		t.Fatal("left in place after the core")
	}
	if s := last(); s.State != nrpt.StateWait || s.Why != nrpt.WhyCore {
		t.Fatalf("after the core: %+v", s)
	}
}

// The tests' supervisors have no rule: they leave the registry be.
func TestNRPTNilSupervisor(t *testing.T) {
	s := &Supervisor{}
	s.startNRPT(context.Background())
	s.stopNRPT()
	s.resetNRPT()
}
