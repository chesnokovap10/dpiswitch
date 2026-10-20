package supervisor

import (
	"context"
	"log"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/nrpt"
	"dpiswitch/internal/paths"
)

// The DNS policy (see nrpt) lives by the core's run as the UDP guard does:
// a rule that sends every name to the TUN adapter's DNS is right only while
// the adapter is up and takes the traffic. With the core down the same rule
// leaves nothing to ask, and no name resolves. So it is written once the
// adapter is up, and taken out at once when the core is stopped, ends on its
// own, the adapter goes, or the setting is switched off. One left by a
// service that died is taken out at the next one's start.
//
// One holdNRPT runs for each core, from its start to its stop.

// nrptRule: what holdNRPT asks of the registry: the nrpt package, or the tests'
type nrptRule interface {
	Put() (bool, error)
	Lift() (bool, error)
	Overridden() bool
}

type realNRPT struct{}

func (realNRPT) Put() (bool, error)  { return nrpt.Put() }
func (realNRPT) Lift() (bool, error) { return nrpt.Lift() }
func (realNRPT) Overridden() bool    { return nrpt.Overridden() }

// nrptEnv: what holdNRPT looks at and writes besides the rule
type nrptEnv struct {
	on  func() bool       // the setting
	tun func() tunState   // the adapter
	say func(nrpt.Status) // the state, for the UI: given when it changes
}

func realNRPTEnv() nrptEnv {
	return nrptEnv{
		on:  func() bool { return ctl.LoadSettings(paths.Settings()).NRPT },
		tun: readTun,
		say: saveNRPTStatus,
	}
}

func saveNRPTStatus(st nrpt.Status) {
	if err := st.Save(paths.NRPT()); err != nil {
		log.Printf("DNS policy: status not saved: %v", err)
	}
}

// holdNRPT keeps the rule as the setting and the adapter ask, until the
// context -- the core's run, or the part of it before it is stopped -- ends,
// and takes it out then.
func holdNRPT(ctx context.Context, r nrptRule, env nrptEnv) {
	var (
		cur    nrpt.Status
		logged string // the failure last logged: one text is said once
	)
	say := func(st nrpt.Status) {
		if !st.Same(cur) {
			cur = st
			env.say(st)
		}
	}
	once := func(text string) {
		if text != logged {
			logged = text
			log.Print(text)
		}
	}
	lift := func(why string) bool {
		removed, err := r.Lift()
		if err != nil {
			once("DNS policy not taken out: " + err.Error())
			say(nrpt.Status{State: nrpt.StateFail, Why: nrpt.WhyOther, Err: errText(err)})
			return false
		}
		if removed {
			log.Printf("DNS policy taken out: %s", why)
		}
		return true
	}
	defer func() {
		if !lift("the core stopped") {
			return
		}
		if env.on() {
			say(nrpt.Status{State: nrpt.StateWait, Why: nrpt.WhyCore})
		} else {
			say(nrpt.Status{State: nrpt.StateOff})
		}
	}()
	step := func() {
		if !env.on() {
			if lift("switched off in the settings") {
				say(nrpt.Status{State: nrpt.StateOff})
			}
			return
		}
		tun := env.tun()
		switch {
		case !tun.known:
			return // nothing read: nothing changes
		case !tun.up:
			if lift("the DPI Switch adapter is gone") {
				say(nrpt.Status{State: nrpt.StateWait, Why: nrpt.WhyAdapter})
			}
			return
		case tun.blocked:
			if lift("Windows keeps the programs' traffic from the DPI Switch adapter") {
				say(nrpt.Status{State: nrpt.StateWait, Why: nrpt.WhyTraffic})
			}
			return
		case r.Overridden():
			// Windows reads Group Policy's rules alone: ours would do nothing
			if lift("Group Policy has DNS rules of its own") {
				once("DNS policy not put in place: Group Policy has rules of its own, and Windows reads no other")
				say(nrpt.Status{State: nrpt.StateFail, Why: nrpt.WhyPolicy})
			}
			return
		}
		changed, err := r.Put()
		if err != nil {
			once("DNS policy not put in place: " + err.Error())
			say(nrpt.Status{State: nrpt.StateFail, Why: nrpt.WhyOther, Err: errText(err)})
			return
		}
		logged = ""
		if changed {
			log.Println("DNS policy in place: every name is asked of the core's DNS, through the DPI Switch adapter alone")
		}
		say(nrpt.Status{State: nrpt.StateOn})
	}
	for {
		step()
		if !sleepCtx(ctx, guardPeriod) {
			return
		}
	}
}

// startNRPT runs holdNRPT for the core that has just started, under its
// context; stopNRPT ends it
func (s *Supervisor) startNRPT(ctx context.Context) {
	if s.nrpt == nil {
		return // a supervisor of the tests'
	}
	nctx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	s.mu.Lock()
	s.nrptStop, s.nrptDone = stop, done
	s.mu.Unlock()
	go func() {
		defer close(done)
		holdNRPT(nctx, s.nrpt, realNRPTEnv())
	}()
}

// stopNRPT takes the rule out and waits for it to be out. Asked for a stop
// of the core, it comes before the TUN adapter is taken down: names asked of
// it in the seconds that takes would find nothing. Safe to ask again, and
// with none running.
func (s *Supervisor) stopNRPT() {
	s.mu.Lock()
	stop, done := s.nrptStop, s.nrptDone
	s.mu.Unlock()
	if stop == nil {
		return
	}
	stop()
	<-done
}

// resetNRPT, at the service's start: a rule a service before this one left
// -- it died with the core running -- sends names to an adapter that is not
// there; taken out before anything else. And the UI is told of this one.
func (s *Supervisor) resetNRPT() {
	if s.nrpt == nil {
		return
	}
	if removed, err := s.nrpt.Lift(); err != nil {
		log.Printf("DNS policy left by the run before not taken out: %v", err)
	} else if removed {
		log.Println("DNS policy left by a run that ended without taking it out: taken out")
	}
	if ctl.LoadSettings(paths.Settings()).NRPT {
		saveNRPTStatus(nrpt.Status{State: nrpt.StateWait, Why: nrpt.WhyCore})
		return
	}
	saveNRPTStatus(nrpt.Status{State: nrpt.StateOff})
}
