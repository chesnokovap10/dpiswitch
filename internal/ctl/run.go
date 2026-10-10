// Controller: takes candidates from live mihomo traffic, runs probes,
// keeps a verdict memory with TTLs, bound to the network.
// By default it applies NOTHING -- it only logs what it would do.
package ctl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dpiswitch/internal/dnscache"
	"dpiswitch/internal/logfile"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/probe"
)

type Config struct {
	DirectAddr string
	TunnelAddr string
	// the second tunnel's listener; the detector never probes through it
	Tunnel2Addr string
	APIAddr     string
	CfgPath     string
	ProxyName   string
	Provider    string
	ListPath    string
	// the same verdicts as addresses, see verifiedAddrs
	AddrProvider string
	AddrListPath string
	// the names that go direct with the ClientHello cut, see verifiedSplit
	SplitProvider string
	SplitListPath string
	// of those, the ones whose QUIC the decoy does not get through, see
	// splitNoQUIC
	NoQUICProvider string
	NoQUICListPath string
	// QUICOffPath: the QUICOffProvider's file
	QUICOffPath string
	// and the ones going direct over QUIC alone, their TCP on 443 refused,
	// see splitNoTCP
	NoTCPProvider string
	NoTCPListPath string
	// the inheritance lists, see inherit.go; empty, none is written
	InheritPath   string
	InheritIPPath string
	HoldPath      string
	RefusePath    string
	// see cdnfam.go
	FamilyDirectPath, FamilyTunnelPath string
	// which network owns each probed node, see asnBook; nil, inheritance
	// goes by the domain alone
	book *asnBook
	cdns *cdnBook
	// the core's listener whose outbound cuts the ClientHello
	SplitAddr     string
	StatePath     string
	JSONLPath     string
	Interval      time.Duration
	WatchInterval time.Duration
	TTL           time.Duration
	FailTTL       time.Duration
	MaxBackoff    time.Duration
	// Idle: how long a name may go unrequested before its verdict stops being
	// re-checked on a timer, and, at ten times that, is dropped from memory.
	Idle         time.Duration
	SettingsPath string
	Families     bool // extend verdicts to the whole domain, see family.go
	Split        bool // try a BLOCKED_TLS name with the ClientHello cut (BLOCKED_DPI when it fails too), see Settings.SplitHello
	// IPv6: on in the settings -- a name's IPv6 node is checked too, see
	// probe.CheckProtoV6
	IPv6     bool
	QUICFake bool // with Split: try a BLOCKED_QUIC name through the core's QUIC decoy, see Settings.QUICFake
	// alone: no first tunnel's config is loaded -- nothing to measure
	// against. With the cut switched on the detector still checks it, see
	// probe.CheckAlone; without, it checks nothing.
	alone     bool
	DirectDNS []probe.Resolver // empty -- the prober's built-in DoH
	// DNSCache: the settings have the program's DNS cache answer the core
	// for the direct path; the detector asks it too while it does (see
	// directResolvers)
	DNSCache bool
	// OnNetwork: the network the controller works in, at its start and at
	// every change -- the DNS cache keeps its answers by it
	OnNetwork func(id string)
	// asks for a core restart: changing resolvers or IPv6 changes its config
	OnCoreChange func()
	Timeout      time.Duration
	Attempts     int
	Workers      int
	PerCycle     int
	Apply        bool
	SkipSuffix   []string
	// rule-provider files whose names the detector leaves alone, see pinned.go
	PinnedLists []string
	// where the tray leaves a request to drop every verdict, see takeReset
	ResetPath string
	// the pattern of the UI's requests to drop single verdicts, see takeForget
	ForgetPath string
	// auto-switch turned off since the lists were last written, see autooff.go
	autoOff *atomic.Bool
	// the auto-switch mode chosen, see modeNow
	mode *atomic.Value
	// the cut and the decoy as switched now, see cutNow
	cut *atomic.Value
	// closed when the controller is stopping: a cycle starts no more probes
	stop <-chan struct{}
}

// stopping: the controller is being stopped.
func (cfg Config) stopping() bool {
	select {
	case <-cfg.stop:
		return true
	default:
		return false
	}
}

// checkProto runs one probe; the scenario tests put a script in its place.
var checkProto = probe.CheckProto

// checkSplit: the probe with the ClientHello cut, see probe.CheckSplit
var checkSplit = probe.CheckSplit

// checkSplitQUIC: QUIC through the cut's outbound and its decoy, see
// probe.CheckSplitQUIC
var checkSplitQUIC = probe.CheckSplitQUIC

// checkProtoV6: the probe of a name's IPv6 node, see probe.CheckProtoV6
var checkProtoV6 = probe.CheckProtoV6

// directHasV6: whether the direct path has IPv6, see hasDirectV6; the
// tests put their own
var directHasV6 = hasDirectV6

// checkAlone: the probe with no tunnel, see probe.CheckAlone
var checkAlone = probe.CheckAlone

func cycle(cfg Config, a *api, st *state, netID string, w *watcher) {
	conns, err := a.connections()
	if err != nil {
		log.Printf("cannot read connections: %v", err)
		return
	}

	ports, order := w.drain()

	// everything the core has talked to, whatever route it took: a name
	// still in use keeps its verdict worth re-checking. From the watcher's
	// every-second look, not this snapshot alone -- the snapshot misses the
	// short connections most names live on, and a name missed that way
	// looked abandoned: its expired verdict was never re-checked
	live := w.drainLive()
	for _, c := range conns {
		if d := c.domain(); d != "" && !c.fromProbe() {
			live = append(live, d)
		}
	}
	st.touch(netID, live)
	// and the names behind bare addresses, recognised by the node they
	// were probed on
	st.touchIPs(netID, w.drainBare())
	if n := st.forget(netID, 10*cfg.Idle); n > 0 {
		log.Printf("forgot %d names nothing has gone to in %s", n, 10*cfg.Idle)
	}
	if nets, n := st.dropStale(netID, staleNetwork); nets > 0 {
		log.Printf("dropped the memory of %d networks not used in %s (%d names)", nets, staleNetwork, n)
	}
	// Names a verdict must not exist for: skipped ones, and ones the user's
	// own lists route (force-tunnel, presets). Filtering new candidates was
	// not enough -- a verdict made before stayed, was re-checked while the
	// name was in use, and a pinned host's CLEAN made its siblings a family.
	// The lists as files, plus what connections showed: a preset's address
	// ranges pin names no file spells out. The files are the core's copies:
	// in every mode they route what they hold -- observe only included --
	// and a second tunnel switched off leaves its own empty, so what those
	// name is measured then.
	lists := loadPinned(cfg.PinnedLists)
	seenPinned := map[string]bool{}
	for _, d := range w.drainPinned() {
		seenPinned[d] = true
	}
	leaveAlone := func(dom string) bool {
		return seenPinned[dom] || lists.has(dom) || skipped(cfg, dom)
	}
	if n := st.park(netID, leaveAlone); n > 0 {
		log.Printf("set aside %d verdicts for names that are skipped or pinned by a list", n)
	}
	if n := st.unpark(netID, leaveAlone); n > 0 {
		log.Printf("put back %d verdicts set aside: no list holds their names now", n)
	}
	// the networks owning the probed nodes, learnt beside the cycle: the
	// lists follow once a round learnt any
	if inheritOn(cfg) {
		learn(cfg, a, st, netID)
	}

	// order matters: suspicious first, then expired,
	// and only then new candidates -- rolling back is more urgent than expanding
	// verdicts made with no tunnel go first once there is one: they were
	// measured against nothing
	var madeAlone []string
	if !cfg.alone {
		madeAlone = st.madeAlone(netID, cfg.Idle)
	}
	// and the ones judged by their IPv4 node alone come last: they take the
	// room a cycle has left, and hold up nothing
	var unseenV6 []string
	if checksV6(cfg, st, netID) {
		unseenV6 = st.unseenV6(netID, cfg.Idle)
	}
	queue := dedupe(concat(
		suspectDirect(cfg, st, netID, conns),
		madeAlone,
		st.quicOnly(netID, cfg.Idle),
		st.expired(netID, cfg.Idle),
		pickCandidates(cfg, st, netID, order),
		unseenV6,
	))
	queue = slices.DeleteFunc(queue, leaveAlone)
	if len(queue) == 0 {
		// verdicts expire with no probe running: the list follows anyway --
		// the cut's in observe only too
		syncList(cfg, a, st, netID, false)
		return
	}
	total := len(queue)
	if len(queue) > cfg.PerCycle {
		// the new names without room this cycle wait for the next; the
		// rest -- expired, suspect -- come back from memory by themselves
		var wait []string
		for _, d := range queue[cfg.PerCycle:] {
			if _, had := st.get(netID, d); !had {
				wait = append(wait, d)
			}
		}
		dropped := w.requeue(wait, ports)
		queue = queue[:cfg.PerCycle]
		log.Printf("%d domains queued, taking %d this cycle; %d new ones wait for the next",
			total, cfg.PerCycle, len(wait)-dropped)
		if dropped > 0 {
			log.Printf("  candidate backlog full (%d): the %d oldest dropped", maxBacklog, dropped)
		}
	}
	probeBatch(cfg, a, st, netID, w, queue, ports)
}

// learn runs a round of the network book's lookups, and after one that
// learnt anything writes the lists by it and runs the next: the networks the
// nodes just showed lending have their ranges looked up at once, not a
// cycle later
func learn(cfg Config, a *api, st *state, netID string) {
	// a round runs beside the cycles, for minutes when RIPE is slow: the
	// machine on another network by its end, the lists are that network's --
	// written by this one's memory they sent its names direct there until
	// the next cycle
	here := func() bool { return st.current() == netID }
	cfg.book.round(cfg.DirectAddr, st.unownedNodes(netID, cfg.book), func() {
		if !here() {
			return
		}
		syncList(cfg, a, st, netID, false)
		learn(cfg, a, st, netID)
	})
	if cfg.cdns != nil && inheritOn(cfg) {
		hosts := map[string][]string{}
		for _, c := range cfg.cdns.stale(st.cdnCandidates(netID)) {
			hosts[c] = st.cdnHosts(netID, c)
		}
		cfg.cdns.round(cfg.TunnelAddr, hosts, func() {
			if here() {
				syncList(cfg, a, st, netID, false)
			}
		})
	}
}

// probeBatch probes queue's names and files what they showed: a cycle's
// names, or one the fast lane took the moment it turned up (see fastLane).
// A name another batch is probing is left to it.
func probeBatch(cfg Config, a *api, st *state, netID string, w *watcher, queue []string, ports map[string][]endpoint) {
	queue = claim(queue)
	defer release(queue)
	if len(queue) == 0 {
		return
	}

	// the listeners' password is the API's secret (see awgconf)
	pass := *a.secret.Load()
	direct := probe.Dialer{Addr: cfg.DirectAddr, Timeout: cfg.Timeout, DNS: directResolvers(cfg),
		Established: a.established, NoV6: st.directNoV6(netID), Pass: pass}
	tunnel := probe.Dialer{Addr: cfg.TunnelAddr, Timeout: cfg.Timeout, Established: a.established, Pass: pass}
	split := direct
	split.Addr = cfg.SplitAddr
	v6Too := checksV6(cfg, st, netID)

	// the verdicts are filed under netID: a probe made after the machine
	// moved to another network measured that one
	guard := guardNetwork()
	// and a reset from the tray while they run leaves memory empty
	epoch := st.resetEpoch()
	var (
		wg  sync.WaitGroup
		sem = make(chan struct{}, cfg.Workers)
		mu  sync.Mutex
		// filed only once every probe is done and the network is known to
		// have stayed the same, see guardNetwork
		results []checked
		// names whose probes were cut short, see retry
		cut []string
		// what this cycle showed of IPv6 on the direct path, see learnV6
		v6Missed  int
		v6Reached bool
	)
	// retry: names this cycle took from the watcher and files nothing for
	// -- a probe the core's going away cut short, a cycle whose results are
	// dropped. The watcher let go of them in drain: a new name no connection
	// showed again was never checked. They go back as the ones left over for
	// want of room do; a known name comes back from memory by itself, and on
	// another network every name is new.
	retry := func(doms []string, anyNet bool) {
		var back []string
		for _, d := range doms {
			if _, had := st.get(netID, d); anyNet || !had {
				back = append(back, d)
			}
		}
		if n := w.requeue(back, ports); n > 0 {
			log.Printf("  candidate backlog full (%d): the %d oldest dropped", maxBacklog, n)
		}
	}
	unfiled := func() []string {
		out := append([]string(nil), cut...)
		for _, r := range results {
			out = append(out, r.dom)
		}
		return out
	}
	for _, dom := range queue {
		wg.Add(1)
		go func(dom string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if guard.moved() || cfg.stopping() {
				// the whole cycle is dropped: no use probing on
				mu.Lock()
				cut = append(cut, dom)
				mu.Unlock()
				return
			}

			// mihomo rules are per domain, so a decision applies
			// to all ports at once. Hence every port seen must be checked,
			// and the worst verdict wins.
			// the ports seen this minute plus the ones remembered: a re-check
			// by TTL often runs while the name is idle, and must still probe
			// the ports it is really used on
			var stored []string
			var was probe.Verdict
			if prev, ok := st.get(netID, dom); ok {
				stored, was = prev.Endpoints, prev.Verdict
			}
			eps, unprobed := mergeEndpoints(ports[dom], stored)
			if cfg.alone {
				// with no tunnel only the cut is worth a check: its 443
				eps = slices.DeleteFunc(eps, func(e endpoint) bool { return e.udp || e.port != 443 })
				if _, addr := probe.AddrKey(dom); addr || len(eps) == 0 {
					return
				}
			} else if _, addr := probe.AddrKey(dom); addr {
				// an address is judged by plain TCP only -- 443 would need the
				// name the sniffer could not find (see addrProbeable)
				eps = plainTCP(eps)
				if len(eps) == 0 {
					return
				}
			} else {
				eps = withTCP(eps)
				if len(eps) == 0 {
					eps = []endpoint{{port: 443}}
				}
			}
			var rep probe.Report
			// the TCP ports whose direct side failed -- see entry.DirectDown
			var downs []probe.Report
			noV6 := false // see probe.Report.DirectNoV6
			reachedV6 := false
			reps := make([]probe.Report, 0, len(eps))
			// follow: what a port's check is followed by -- a name blocked by its
			// hello tried with the cut, a QUIC blocked tried through the decoy
			follow := func(r probe.Report, ep endpoint) probe.Report {
				if !cfg.alone && !r.Aborted && cfg.Split && !ep.udp && ep.port == 443 && r.Verdict == probe.BlockedTLS {
					// blocked by its name: once more with the hello cut, on
					// the same node. The cut path's verdict stands for the
					// port when it got through -- clean, or merely slower;
					// otherwise the block the plain path found does.
					s := checkSplit(split, tunnel, r, cfg.Attempts, was)
					appendJSONL(cfg.JSONLPath, s)
					switch {
					case s.Aborted, s.Verdict == probe.CleanSplit, s.Verdict == probe.Slower:
						r = s
					default:
						r.Note = "ClientHello cut: " + string(s.Verdict) + " " + s.Reason
						// blocked with the cut too: the DPI box beats it here.
						// Re-checked like any block, the cut tried again each time
						if isBlocked(s.Verdict) || s.Verdict == probe.MITM {
							r.Verdict = probe.BlockedDPI
						}
					}
				}
				if !cfg.alone && !r.Aborted && cfg.Split && cfg.QUICFake && ep.udp && ep.port == 443 && r.Verdict == probe.BlockedQUIC {
					// QUIC blocked: once more through the cut's outbound,
					// which sends the decoy Initial ahead -- the way the
					// browser's QUIC will go
					s := checkSplitQUIC(split, tunnel, r, cfg.Attempts, was)
					appendJSONL(cfg.JSONLPath, s)
					switch {
					case s.Aborted, s.Verdict == probe.CleanSplit, s.Verdict == probe.Slower:
						r = s
					default:
						r.Note = "QUIC decoy: " + string(s.Verdict) + " " + s.Reason
					}
				}
				return r
			}
			for _, ep := range eps {
				var r probe.Report
				if cfg.alone {
					r = checkAlone(direct, split, dom, cfg.Attempts, was)
				} else {
					r = checkProto(direct, tunnel, dom, ep.port, cfg.Attempts, ep.udp, was)
				}
				appendJSONL(cfg.JSONLPath, r)
				r = follow(r, ep)
				// the name's IPv6 node too, where the direct path has IPv6: the core
				// dials either, and the worse of the two is the port's verdict. A
				// check of the IPv4 node alone called a name clean whose IPv6 one
				// is cut. TCP only: for UDP the core takes the IPv4 node of a name
				// that has one, and QUIC to the IPv6 one is never sent direct.
				if v6Too && !ep.udp && !r.Aborted && r.TestedIP != "" && net.ParseIP(r.TestedIP).To4() != nil {
					if r6, ok := checkProtoV6(direct, tunnel, dom, ep.port, cfg.Attempts, ep.udp, was); ok {
						appendJSONL(cfg.JSONLPath, r6)
						// slower there is no block: the core takes whichever node
						// answers first, and the IPv4 one's speed is the name's.
						// Nor is a node that does not take the connection: the core
						// dials both and goes on with the IPv4 one. On the first day
						// (10.10) download.windowsupdate.com and cloudflare-dns.com
						// were reverted for IPv6 nodes nothing direct ever went to.
						if r6 = follow(r6, ep); r6.Aborted || r6.Verdict != probe.Slower && r6.Verdict != probe.BlockedTCP && worse(r6.Verdict, r.Verdict) {
							r = r6
						}
					}
				}
				if r.Aborted {
					// leave memory alone: the name goes back to the
					// watcher and is checked once the core is back
					mu.Lock()
					cut = append(cut, dom)
					mu.Unlock()
					return
				}
				// QUIC failing direct is left out: most hosts have no QUIC at
				// all, and fail on both paths for that reason alone
				if !ep.udp && directDownOn(r) {
					downs = append(downs, r)
				}
				noV6 = noV6 || r.DirectNoV6
				reachedV6 = reachedV6 || directReachedV6(r)
				reps = append(reps, r)
			}
			rep = worstPort(eps, reps)
			noQUIC := splitNoQUIC(eps, reps)
			// works over QUIC alone: the QUIC port's verdict stands for the
			// name, its TCP on 443 is refused -- and that port's fall is the
			// refused one, not a dead direct path
			noTCP := splitNoTCP(cfg, eps, reps)
			if noTCP {
				rep = quicReport(eps, reps)
				rep.Verdict = probe.CleanSplit
				rep.Note = strings.TrimPrefix(rep.Note+"; TCP blocked even with the ClientHello cut: refused", "; ")
				downs = slices.DeleteFunc(downs, func(r probe.Report) bool { return r.Port == 443 })
			}
			directDown := len(downs) > 0
			var downOn probe.Report
			if directDown {
				downOn = downs[0]
			}
			// A port whose direct side failed while the tunnel failed too is
			// INCONCLUSIVE, and that must not override a definite verdict --
			// but CLEAN is a promise that the name works direct on every port
			// it uses, and on this one it does not. Clean on 443 plus dead
			// direct on 5228 used to come out CLEAN.
			if goesDirect(rep.Verdict) && directDown {
				rep = downOn
				rep.Verdict = probe.Inconcl
				rep.Reason = fmt.Sprintf("direct path fails on %s/%d: %s",
					downOn.Proto, downOn.Port, downOn.Reason)
			}
			mu.Lock()
			if noV6 && !reachedV6 {
				v6Missed++
			}
			v6Reached = v6Reached || reachedV6
			mu.Unlock()

			mu.Lock()
			results = append(results, checked{dom, rep, eps, checkFacts{directDown, noV6, unprobed, noQUIC, noTCP, v6Too}})
			mu.Unlock()
		}(dom)
	}
	wg.Wait()

	if cfg.stopping() {
		// the service is stopping: its stop waits for this cycle, and the
		// core is going away under the probes
		guard.done()
		return
	}
	if !guard.done() {
		// the probes measured another network than the one their verdicts
		// would be filed under. Memory is left alone: the main loop
		// switches to the new network at its next tick, and the names come
		// back to be checked there.
		log.Printf("the network changed during the cycle: %d results dropped", len(results))
		retry(unfiled(), true)
		return
	}
	if len(results) > 0 && !ipStill(cfg, st, guard.start) {
		log.Printf("the public address changed during the cycle: %d results dropped", len(results))
		retry(unfiled(), true)
		return
	}
	// filed under listMu: a reset takes it too, so it comes wholly before
	// this or wholly after
	listMu.Lock()
	if st.resetEpoch() != epoch {
		listMu.Unlock()
		log.Printf("verdicts were reset during the cycle: %d results dropped", len(results))
		retry(unfiled(), true)
		return
	}
	changed := false
	for _, r := range results {
		if record(cfg, st, netID, r.dom, r.rep, r.eps, r.facts) {
			changed = true
		}
	}
	listMu.Unlock()
	retry(cut, false)

	if until, now := st.learnV6(netID, v6Missed, v6Reached); now {
		log.Printf("the direct path here has no IPv6: %d names in a row could not reach "+
			"their IPv6 node direct. IPv6 nodes are not probed until %s",
			v6Misses, until.Format("02.01 15:04"))
	}
	if err := st.save(); err != nil {
		log.Printf("state not saved: %v", err)
	}
	// not only when a verdict changed: a CLEAN expiring changes the list
	// too, and one re-confirmed after it dropped out must come back. With
	// auto-switch off only the cut's list is written, and the rest logged
	// when a verdict changed.
	syncList(cfg, a, st, netID, changed && !cfg.Apply)
}

// checksV6: IPv6 on in the settings, and the direct path has it: a name's
// IPv6 node is checked beside its IPv4 one. With none here the core's dial
// of it fails at once and IPv4 is taken: nothing to check, see learnV6 too
func checksV6(cfg Config, st *state, netID string) bool {
	return cfg.IPv6 && !cfg.alone && !st.directNoV6(netID) && directHasV6()
}

// probing: the names a batch is probing now, so a cycle and the fast lane
// never probe one name at once
var probing = struct {
	sync.Mutex
	names map[string]bool
}{names: map[string]bool{}}

// claim marks the names of queue no batch is probing as this one's, and
// gives them back in their order
func claim(queue []string) []string {
	probing.Lock()
	defer probing.Unlock()
	var out []string
	for _, d := range queue {
		if !probing.names[d] {
			probing.names[d] = true
			out = append(out, d)
		}
	}
	return out
}

func release(queue []string) {
	probing.Lock()
	defer probing.Unlock()
	for _, d := range queue {
		delete(probing.names, d)
	}
}

// checked: one name's probes, waiting to be filed.
type checked struct {
	dom   string
	rep   probe.Report
	eps   []endpoint
	facts checkFacts
}

// checkFacts: what the probes of one name showed over all of its ports.
type checkFacts struct {
	directDown bool // the direct side failed on a TCP port, see entry.DirectDown
	noV6       bool // see probe.Report.DirectNoV6
	unprobed   int  // ports the name was seen on beyond maxEndpoints
	noQUIC     bool // see entry.NoQUIC
	noTCP      bool // see entry.NoTCP
	v6         bool // see entry.V6
}

// record files one name's check in memory and reports whether its verdict
// changed. rep is the name's worst port, eps the endpoints probed.
func record(cfg Config, st *state, netID, dom string, rep probe.Report, eps []endpoint, f checkFacts) bool {
	directDown, noV6 := f.directDown, f.noV6
	// A name used on more ports than a check takes cannot be promised clean:
	// CLEAN sends it direct on all of them, and the ones beyond the cap were
	// never probed. It used to come out CLEAN all the same.
	if goesDirect(rep.Verdict) && f.unprobed > 0 {
		rep.Verdict = probe.Inconcl
		rep.Reason = fmt.Sprintf("used on %d more ports than a check takes (%d)", f.unprobed, maxEndpoints)
	}
	prev, had := st.get(netID, dom)

	// INCONCLUSIVE says nothing about the direct path (usually the
	// tunnel side failed, e.g. right after a Wi-Fi reconnect). It must
	// not replace a definite verdict: a working direct site would be
	// reverted into the tunnel because the TUNNEL was flaky. Keep the
	// previous verdict and just retry later.
	// One exception: an expired CLEAN is not extended. Being CLEAN
	// means "goes direct", and a verdict that could not be confirmed
	// once its term ran out is not evidence the direct path still
	// works -- a false "clean" breaks a site, a false "blocked" only
	// costs a detour. It drops out of the direct list until the next
	// check, without counting as a revert.
	expiredClean := had && goesDirect(prev.Verdict) && time.Now().After(prev.ExpiresAt)
	// Keeping a verdict is for the tunnel side failing. When the
	// DIRECT path itself failed, a CLEAN is not kept either: whatever
	// this means about blocking, the host does not work direct now.
	// On any TCP port it uses, not only the one the report came from --
	// and not over QUIC, which most hosts simply do not have.
	dropClean := had && goesDirect(prev.Verdict) && (expiredClean || directDown || f.unprobed > 0)
	// Nor is a verdict kept against an IPv6 node the direct path does
	// not reach: that is a finding about the direct path, and the
	// BLOCKED it replaces was the old mislabel of the same thing.
	if had && rep.Verdict == probe.Inconcl && prev.Verdict != probe.Inconcl && !dropClean && !noV6 {
		kept := *prev
		kept.Alone = cfg.alone
		kept.V6 = f.v6
		term := cfg.FailTTL
		// A verdict the check measured and could not overturn -- the
		// host fails the same on both paths, say -- backs off as a
		// repeat does: e2cNN.gcp.gvt2.com names came back every hour
		// to fail on both paths again. Not when our own side failed
		// (the resolver, the tunnel): that says nothing about the host.
		if !goesDirect(prev.Verdict) && !rep.Unmeasured {
			kept.Streak++
			term = failTerm(cfg, kept.Streak, kept.Reverts)
		}
		kept.ExpiresAt = time.Now().Add(term)
		kept.Endpoints = endpointStrings(eps)
		st.put(netID, dom, &kept)
		log.Printf("  %s inconclusive (%s), keeping %s, retry in %s",
			dom, rep.Reason, prev.Verdict, term)
		return false
	}

	// One slow measurement of a CLEAN name is often the network's
	// moment, not the path's: at 00:37 on 24.09 four clean names went
	// SLOWER within one minute while the tunnel's own checks failed.
	// The CLEAN is kept and measured again after FailTTL; SLOWER the
	// second time in a row reverts it. The direct path did work, so an
	// expired CLEAN may be kept this way too.
	if had && goesDirect(prev.Verdict) && rep.Verdict == probe.Slower && !prev.SlowOnce && !directDown {
		kept := *prev
		kept.SlowOnce = true
		kept.V6 = f.v6
		kept.ExpiresAt = time.Now().Add(cfg.FailTTL)
		kept.Endpoints = endpointStrings(eps)
		st.put(netID, dom, &kept)
		log.Printf("  %s slower once (%s), keeping %s, measuring again in %s",
			dom, rep.Reason, prev.Verdict, cfg.FailTTL)
		return false
	}

	e := &entry{
		Verdict:    rep.Verdict,
		Reason:     rep.Reason,
		DecidedAt:  time.Now(),
		TestedIP:   rep.TestedIP,
		Endpoints:  endpointStrings(eps),
		DirectDown: rep.Verdict == probe.Inconcl && directDown,
		Alone:      cfg.alone,
		NoQUIC:     rep.Verdict == probe.CleanSplit && f.noQUIC,
		NoTCP:      rep.Verdict == probe.CleanSplit && f.noTCP,
		V6:         f.v6,
	}
	// A new name was just seen by the watcher. A known one keeps its
	// own mark: the probe is not a use. It used to count as one, and
	// every verdict re-checked hourly renewed itself -- names nothing
	// had gone to for days were probed around the clock and never
	// forgotten.
	if had {
		e.LastSeen = prev.lastSeen()
	} else {
		e.LastSeen = time.Now()
	}
	if had {
		e.Reverts = prev.Reverts
		// the same finding again: the wait before the next check grows
		if !goesDirect(rep.Verdict) && sameFinding(prev.Verdict, rep.Verdict) {
			e.Streak = prev.Streak
			if !rep.Unmeasured {
				e.Streak++
			}
		}
	}
	if goesDirect(rep.Verdict) {
		e.ExpiresAt = time.Now().Add(cfg.TTL)
	} else {
		e.ExpiresAt = time.Now().Add(failTerm(cfg, e.Streak, e.Reverts))
	}
	if had {
		// the domain lost its direct path -- the more often this happens,
		// the longer it waits before being re-checked
		if dropClean && rep.Verdict == probe.Inconcl {
			// not a revert: no blocking was shown, the direct path just
			// could not be confirmed. Retry at the normal pace.
			e.ExpiresAt = time.Now().Add(cfg.FailTTL)
			log.Printf("  %s inconclusive (%s), CLEAN not confirmed -- "+
				"through the tunnel until the next check in %s", dom, rep.Reason, cfg.FailTTL)
		} else if prev.Verdict == probe.CleanSplit && !cfg.Split && rep.Verdict == probe.BlockedTLS {
			// the cut was switched off: the name lost nothing it was
			// checked for, and is no revert
		} else if goesDirect(prev.Verdict) && !goesDirect(rep.Verdict) {
			e.Reverts++
			// from the blocked re-check up: the direct term (a week)
			// hit the cap on the very first revert, so it never grew
			e.ExpiresAt = time.Now().Add(failTerm(cfg, 0, e.Reverts))
			log.Printf("REVERT %s: %s (%s), reverts total %d", dom, rep.Verdict, rep.Reason, e.Reverts)
		}
	}

	st.put(netID, dom, e)
	if had && prev.Verdict == rep.Verdict {
		return false
	}
	if goesDirect(rep.Verdict) {
		// log the BEST measurements -- the very ones the decision
		// is based on. The last pass may have been slow by chance,
		// and showing it would be misleading
		log.Printf("%s %s (node %s, direct %s vs tunnel %s)",
			rep.Verdict, dom, rep.TestedIP, msVal(rep.DirectMs, rep.Direct), msVal(rep.TunnelMs, rep.Tunnel))
	} else if !had {
		log.Printf("  %s %s: %s", rep.Verdict, dom, rep.Reason)
	}
	return true
}

// candidates: what the watcher accumulated and we have not decided yet, in
// the order it turned up. protocol and route filters were already applied
// while collecting.
func pickCandidates(cfg Config, st *state, netID string, order []string) []string {
	var out []string
	for _, dom := range order {
		if skipped(cfg, dom) {
			continue
		}
		if _, had := st.get(netID, dom); had {
			continue
		}
		out = append(out, dom)
	}
	return dedupe(out)
}

// direct domains whose connection is open but nothing arrived:
// looks like a cut -- re-check without waiting for the TTL
func suspectDirect(cfg Config, st *state, netID string, conns []connection) []string {
	var out []string
	fams := map[string]bool{}
	if cfg.Families {
		for _, f := range st.families(netID) {
			fams[f.Domain] = true
		}
	}
	for _, c := range conns {
		// a probe still waiting on its answer is not a cut
		if !c.viaDirect() || c.Download > 0 || c.fromProbe() {
			continue
		}
		if ts, err := time.Parse(time.RFC3339, c.Start); err != nil || time.Since(ts) <= 10*time.Second {
			continue
		}
		dom := c.domain()
		if dom == "" {
			// a nameless connection the address rules sent direct: the
			// verdicts behind that node and port. They used to wait out
			// their whole term, however dead the direct path went
			if c.byProvider(cfg.AddrProvider) {
				out = append(out, st.onNode(netID, c.Metadata.DestinationIP, c.port())...)
			}
			continue
		}
		e, had := st.get(netID, dom)
		switch {
		case had && goesDirect(e.Verdict):
		case !had && (fams[familyOf(dom)] || c.inherited()):
			// sent direct by a family or by inheritance, never checked on
			// its own
		case had && e.Verdict == probe.Inconcl && fams[familyOf(dom)]:
			// a family keeps sending it direct while its own check never
			// concluded. Without this it would never be picked again: the
			// entry exists, so it is not "unchecked", and it is not CLEAN
			// either -- and it would sit direct and broken forever.
		default:
			continue
		}
		out = append(out, dom)
	}
	return dedupe(out)
}

// write verdicts to the rule-provider and have the core reload it
func applyList(cfg Config, a *api, st *state, netID string) {
	syncList(cfg, a, st, netID, true)
}

// directLists: whether the detector's direct lists are written: in On, and
// in observe only with the ClientHello cut on -- everything goes the cut's
// way there, and the names the cut harms must go plain (see observeFiles)
func directLists(cfg Config) bool {
	if cfg.modeNow() == ModeObserve && cfg.cutNow().split {
		return true
	}
	// the mode as it is now, not as this copy of the config had it: a cycle
	// begun in observe only and ending after the switch to On emptied the
	// lists the switch had just written (06.10 19:22:36)
	on := cfg.Apply
	if cfg.mode != nil {
		on = cfg.modeNow() == ModeOn
	}
	return on && !cfg.off()
}

// splitNames: what the ClientHello cut's list holds -- its names, while the
// cut is switched on and the mode sends anything direct: On and observe
// only, not tunnel only. Switched off, its names leave the direct path at
// once, not when their verdicts run out.
func splitNames(cfg Config, st *state, netID string) []string {
	cut := cfg.cutNow()
	if !cut.split || cfg.modeNow() == ModeTunnel || netID == "" || netID == noNetwork {
		return nil
	}
	splits := st.verifiedSplit(netID)
	if !cut.quicFake {
		// a name going direct over QUIC alone needs the decoy: without it
		// it has no way direct at all
		noTCP := st.verifiedSplitNoTCP(netID)
		splits = slices.DeleteFunc(splits, func(d string) bool {
			_, ok := slices.BinarySearch(noTCP, d)
			return ok
		})
	}
	return splits
}

// noTCPNames: of the cut's names, the ones going direct over QUIC alone
func noTCPNames(cfg Config, st *state, netID string, splits []string) []string {
	if len(splits) == 0 {
		return nil
	}
	return slices.DeleteFunc(st.verifiedSplitNoTCP(netID), func(d string) bool {
		_, ok := slices.BinarySearch(splits, d)
		return !ok
	})
}

// noQUICNames: of the cut's names, the ones whose QUIC is refused (see
// entry.NoQUIC) -- with the decoy on; off, all of them: direct-split always
// carries the decoy, and only this list keeps QUIC from it
func noQUICNames(cfg Config, st *state, netID string, splits []string) []string {
	if len(splits) == 0 {
		return nil
	}
	if !cfg.cutNow().quicFake {
		return slices.Clone(splits)
	}
	return slices.DeleteFunc(st.verifiedSplitNoQUIC(netID), func(d string) bool {
		_, ok := slices.BinarySearch(splits, d)
		return !ok
	})
}

// writeQUICOff writes the decoy's flag when it differs from the switch as
// it is now; listMu held
func writeQUICOff(cfg Config, a *api) error {
	if cfg.QUICOffPath == "" {
		return nil
	}
	var want []string
	if !cfg.cutNow().quicFake {
		want = []string{"NETWORK,UDP"}
	}
	if slices.Equal(listRules(cfg.QUICOffPath), want) {
		return nil
	}
	var b strings.Builder
	b.WriteString("# generated by the controller, do not edit\n")
	b.WriteString("# the QUIC decoy switched off: UDP matches, and QUIC on the cut's lent ways is refused\n")
	for _, r := range want {
		b.WriteString(r + "\n")
	}
	body := b.String()
	return replaceList(a, cfg.QUICOffPath, QUICOffProvider, body)
}

// splitSame: the cut's lists on disk are what memory makes them
func splitSame(cfg Config, splits, noQUIC, noTCP []string) bool {
	return (cfg.SplitListPath == "" || slices.Equal(listRules(cfg.SplitListPath), splits)) &&
		(cfg.NoQUICListPath == "" || slices.Equal(listRules(cfg.NoQUICListPath), noQUIC)) &&
		(cfg.NoTCPListPath == "" || slices.Equal(listRules(cfg.NoTCPListPath), noTCP))
}

// writeSplit writes the cut's lists when they differ from what is on disk,
// or always when forced; listMu held.
func writeSplit(cfg Config, a *api, st *state, netID string, splits []string, force bool) error {
	noQUIC := noQUICNames(cfg, st, netID, splits)
	if cfg.NoQUICListPath != "" && (force || !slices.Equal(listRules(cfg.NoQUICListPath), noQUIC)) {
		var b strings.Builder
		b.WriteString("# generated by the controller, do not edit\n")
		fmt.Fprintf(&b, "# network %s, updated %s\n", netID, time.Now().Format(time.RFC3339))
		b.WriteString("# going direct with the ClientHello cut, QUIC not getting through even with the decoy: refused\n")
		for _, d := range noQUIC {
			b.WriteString(d + "\n")
		}
		if err := replaceList(a, cfg.NoQUICListPath, cfg.NoQUICProvider, b.String()); err != nil {
			return err
		}
	}
	// the TCP refusals before the names: a name must not go direct on TCP
	// for the moment between the two
	noTCP := noTCPNames(cfg, st, netID, splits)
	if cfg.NoTCPListPath != "" && (force || !slices.Equal(listRules(cfg.NoTCPListPath), noTCP)) {
		var b strings.Builder
		b.WriteString("# generated by the controller, do not edit\n")
		fmt.Fprintf(&b, "# network %s, updated %s\n", netID, time.Now().Format(time.RFC3339))
		b.WriteString("# going direct with the ClientHello cut over QUIC alone, TCP on 443 blocked even with the cut: refused\n")
		for _, d := range noTCP {
			b.WriteString(d + "\n")
		}
		if err := replaceList(a, cfg.NoTCPListPath, cfg.NoTCPProvider, b.String()); err != nil {
			return err
		}
	}
	if cfg.SplitListPath == "" || !force && slices.Equal(listRules(cfg.SplitListPath), splits) {
		return nil
	}
	var b strings.Builder
	b.WriteString("# generated by the controller, do not edit\n")
	fmt.Fprintf(&b, "# network %s, updated %s\n", netID, time.Now().Format(time.RFC3339))
	b.WriteString("# blocked by name, clean with the ClientHello cut: direct through direct-split\n")
	for _, d := range splits {
		b.WriteString(d + "\n")
	}
	if err := replaceList(a, cfg.SplitListPath, cfg.SplitProvider, b.String()); err != nil {
		return err
	}
	if len(splits) > 0 {
		log.Printf("applied: %d domains go direct with the ClientHello cut", len(splits))
	}
	return nil
}

// syncList brings the rule-provider files in line with memory. Unless forced
// it writes only when the rules differ from what is on disk: it runs every
// cycle, because verdicts change the list without any verdict changing --
// a CLEAN expires, or comes back after a re-check that found it the same.
func syncList(cfg Config, a *api, st *state, netID string, force bool) {
	listMu.Lock()
	defer listMu.Unlock()
	// a file already written whose reload failed: the comparison below
	// finds it in line with memory, and without this the core kept the old
	// rules until it restarted
	retryReloads(a)
	if err := writeQUICOff(cfg, a); err != nil {
		log.Print(err)
	}
	doms, fams := directRules(cfg, st, netID)
	splits := splitNames(cfg, st, netID)
	if !directLists(cfg) {
		// observe only sends everything direct already, and the cut's names
		// with the cut; tunnel only, nothing direct, the cut's included
		if err := writeSplit(cfg, a, st, netID, splits, force); err != nil {
			log.Print(err)
		}
		if err := writeInherit(cfg, a, st, netID, fams, force); err != nil {
			log.Print(err)
		}
		// left from observe only with the cut on, or from a cycle begun in On
		for _, l := range [][2]string{{cfg.ListPath, cfg.Provider}, {cfg.AddrListPath, cfg.AddrProvider}} {
			if l[0] != "" && len(listRules(l[0])) > 0 {
				if err := replaceList(a, l[0], l[1], "# auto-switch disabled -- everything goes through the tunnel\n"); err != nil {
					log.Print(err)
				}
			}
		}
		if force && cfg.modeNow() == ModeObserve {
			log.Printf("observe mode: %d domains would go DIRECT (%s)", len(doms), preview(doms))
		}
		return
	}
	var addrs []string
	if cfg.AddrListPath != "" {
		addrs = st.verifiedAddrs(netID)
	}
	// the held names first: a name just blocked leaves inheritance before
	// the direct lists change
	if err := writeInherit(cfg, a, st, netID, fams, force); err != nil {
		log.Print(err)
	}
	if !force && splitSame(cfg, splits, noQUICNames(cfg, st, netID, splits), noTCPNames(cfg, st, netID, splits)) && slices.Equal(listRules(cfg.ListPath), doms) &&
		(cfg.AddrListPath == "" || slices.Equal(listRules(cfg.AddrListPath), addrs)) {
		return
	}
	if err := writeSplit(cfg, a, st, netID, splits, force); err != nil {
		log.Print(err)
	}
	var b strings.Builder
	b.WriteString("# generated by the controller, do not edit\n")
	fmt.Fprintf(&b, "# network %s, updated %s\n", netID, time.Now().Format(time.RFC3339))
	for _, d := range doms {
		b.WriteString(d + "\n")
	}
	if err := replaceList(a, cfg.ListPath, cfg.Provider, b.String()); err != nil {
		log.Print(err)
		return
	}
	// the tested nodes of the same CLEAN verdicts, for connections that
	// arrive with no name at all -- see verifiedAddrs
	if cfg.AddrListPath != "" {
		var ib strings.Builder
		ib.WriteString("# generated by the controller, do not edit\n")
		ib.WriteString("# the node each CLEAN verdict was probed on, with the TCP ports probed\n")
		ib.WriteString("# by plain connect; matched only by connections that carry no name\n")
		for _, r := range addrs {
			ib.WriteString(r + "\n")
		}
		if err := replaceList(a, cfg.AddrListPath, cfg.AddrProvider, ib.String()); err != nil {
			log.Print(err)
		}
	}
	if len(fams) > 0 {
		names := make([]string, len(fams))
		for i, f := range fams {
			names[i] = fmt.Sprintf("%s (%d)", f.Domain, f.Clean)
		}
		log.Printf("applied: %d direct rules, %d of them families: %s",
			len(doms), len(fams), strings.Join(names, ", "))
		return
	}
	log.Printf("applied: %d domains go direct", len(doms))
}

// listMu: one writer of the rule files at a time. A reset asked for from
// the tray must not be overtaken by a cycle's sync that read memory before
// it and would write the dropped rules back.
var listMu sync.Mutex

// reloadPending: the rule-providers whose file was replaced but whose reload
// failed, under listMu. The file on disk is the new one, so a later sync
// finds nothing to write -- the reload has to be asked for again by itself.
var reloadPending = map[string]bool{}

// retryReloads asks the core again to reload the providers a failed reload
// left behind; listMu held.
func retryReloads(a *api) {
	for p := range reloadPending {
		if err := a.reloadProvider(p); err != nil {
			continue // the next sync tries again; logged when it first failed
		}
		delete(reloadPending, p)
		log.Printf("provider %s reloaded on retry", p)
	}
}

// takeReset carries out a reset asked for from the tray ("Everything via
// tunnel") or the verdicts page. The tray used to do it itself: it emptied
// the name list and deleted the state file -- and the controller, holding
// its memory in RAM, wrote every DIRECT rule back within a minute; the
// address list it never touched. The tray now leaves a request; the
// controller drops its own memory, empties both lists, and removes the
// request once done.
//
// A reset is of one network: the one the request names (see
// requestNetwork) -- the verdicts page shows any network kept -- or the
// current one, the tray's. It dropped the verdicts of every network. The
// lists are the current network's: another's reset leaves them be.
//
// Done is the emptied memory saved and both lists written. The request
// used to go whatever failed: a state file not written came back at the
// next start with every verdict in it, and the tray had been told the
// reset was done. It stays now, and the reset is done again the next
// second. A reload the core refused is not a failure: the file is written,
// and the reload is retried (see retryReloads).
func takeReset(cfg Config, a *api, st *state) bool {
	if cfg.ResetPath == "" {
		return false
	}
	// every request waiting, the oldest first; one not taken yet holds the
	// ones after it to the next second
	reqs, _ := filepath.Glob(cfg.ResetPath)
	sort.Strings(reqs)
	took := false
	for _, r := range reqs {
		if !takeResetOne(cfg, a, st, r) {
			break
		}
		took = true
	}
	return took
}

// takeResetOne carries out the reset request in the file req
func takeResetOne(cfg Config, a *api, st *state, req string) bool {
	// the user's file, read as SYSTEM: not through a link, see takeForget
	b, err := paths.ReadUserFile(req, forgetMax)
	switch {
	case errors.Is(err, paths.ErrRefused):
		log.Printf("request %s not taken: %v", req, err)
		if err := os.Remove(req); err != nil {
			log.Printf("request %s not removed: %v", req, err)
		}
		return false
	case err != nil:
		return false // none, or held open a moment: the next second
	}
	cur := st.current()
	id := requestNetwork(b)
	if id == "" {
		id = cur
	}
	if id == "" || id == noNetwork {
		return false // no network known yet: the request waits for one
	}
	listMu.Lock()
	resetDropped += st.resetVerdicts(id)
	err = st.save()
	if err != nil {
		err = fmt.Errorf("state not saved: %w", err)
	}
	body := []byte("# verdicts reset -- everything goes through the tunnel\n")
	// the refusals too, and before the names they are of: left with the
	// names gone, they refused a name's TCP or QUIC on 443 on its way through
	// the tunnel until the next cycle's sync
	for _, l := range [][2]string{{cfg.NoTCPListPath, cfg.NoTCPProvider}, {cfg.NoQUICListPath, cfg.NoQUICProvider},
		{cfg.ListPath, cfg.Provider}, {cfg.AddrListPath, cfg.AddrProvider}, {cfg.SplitListPath, cfg.SplitProvider},
		{cfg.InheritPath, InheritProvider}, {cfg.InheritIPPath, InheritIPProvider}, {cfg.HoldPath, HoldProvider}, {cfg.RefusePath, RefuseProvider},
		{cfg.FamilyDirectPath, FamilyDirectProvider}, {cfg.FamilyTunnelPath, FamilyTunnelProvider}} {
		path, provider := l[0], l[1]
		if path == "" || id != cur {
			continue
		}
		if werr := paths.ReplaceFile(path, body); werr != nil {
			if err == nil {
				err = fmt.Errorf("list %s not written: %w", path, werr)
			}
			continue
		}
		if rerr := a.reloadProvider(provider); rerr != nil {
			reloadPending[provider] = true
			log.Printf("provider %s not reloaded, will retry: %v", provider, rerr)
			continue
		}
		delete(reloadPending, provider)
	}
	if err != nil {
		// said once, not every second the request is taken again
		if resetFailed != err.Error() {
			resetFailed = err.Error()
			log.Printf("verdicts reset, but not for good: %v -- trying again", err)
		}
		listMu.Unlock()
		return false
	}
	n := resetDropped
	resetFailed, resetDropped = "", 0
	listMu.Unlock()
	// the tray waits for the request to go: it goes last
	if err := os.Remove(req); err != nil {
		log.Printf("reset request not removed: %v", err)
	}
	if id == cur {
		log.Printf("verdicts of %s reset: %d dropped, everything goes through the tunnel", id, n)
	} else {
		log.Printf("verdicts of %s reset: %d dropped; the network is not the current one, the lists stay", id, n)
	}
	return true
}

// resetFailed: why the last reset could not be completed, and what the
// attempts at it dropped; listMu held
var (
	resetFailed  string
	resetDropped int
)

// takeForget carries out the requests to drop single verdicts, left by the
// verdicts page: a file each, a name a line (see forgetVerdicts). The names
// go back to the tunnel, and the detector checks them anew when they are
// used. A request goes once its drop is saved and the lists are in line
// with memory: the UI waits for it to go before it closes the connections
// the names had open.
func takeForget(cfg Config, a *api, st *state) {
	if cfg.ForgetPath == "" {
		return
	}
	reqs, _ := filepath.Glob(cfg.ForgetPath)
	// the names by the network they are dropped in: the one a request
	// names, the current one for none
	byNet := map[string][]string{}
	var taken []string
	for _, r := range reqs {
		// the user's file, read as SYSTEM: not through a link (see
		// paths.ReadUserFile). It was read as any file, and what a link
		// pointed at went into the service's log, name by name
		b, err := paths.ReadUserFile(r, forgetMax)
		switch {
		case errors.Is(err, paths.ErrRefused):
			// no request the UI writes, and never one: it goes, unread
			log.Printf("request %s not taken: %v", r, err)
			if err := os.Remove(r); err != nil {
				log.Printf("request %s not removed: %v", r, err)
			}
			continue
		case err != nil:
			continue // gone, or held open a moment: the next second
		}
		id := requestNetwork(b)
		byNet[id] = append(byNet[id], forgetKeys(b)...)
		taken = append(taken, r)
	}
	netID := st.current()
	if len(taken) == 0 || netID == "" || netID == noNetwork {
		return // no network known yet: an empty list would be written
	}
	if keys, ok := byNet[""]; ok {
		delete(byNet, "")
		byNet[netID] = append(byNet[netID], keys...)
	}
	listMu.Lock()
	n := 0
	for id, keys := range byNet {
		n += st.forgetVerdicts(id, keys)
	}
	err := st.save()
	listMu.Unlock()
	if err != nil {
		if forgetFailed != err.Error() {
			forgetFailed = err.Error()
			log.Printf("verdicts dropped, but the state not saved: %v -- trying again", err)
		}
		return
	}
	forgetFailed = ""
	// the lists are the current network's: another's drop leaves them be
	if _, ok := byNet[netID]; ok {
		syncList(cfg, a, st, netID, false)
	}
	for _, r := range taken {
		if err := os.Remove(r); err != nil {
			log.Printf("request %s not removed: %v", r, err)
		}
	}
	for id, keys := range byNet {
		log.Printf("verdicts of %s dropped from the UI: %s", id, strings.Join(keys, ", "))
	}
	log.Printf("verdicts dropped from the UI: %d", n)
}

// forgetFailed: why the last drop could not be saved, said once
var forgetFailed string

// forgetMax: the most of a request read; the UI writes one name
const forgetMax = 64 << 10

// requestPoll: how often watchReset looks; the tests shorten it
var requestPoll = time.Second

// NetworkLine: the line naming the network a request to reset or drop
// verdicts is of (see requestNetwork); the UI writes it.
func NetworkLine(id string) string { return "network " + id + "\n" }

// netIDRe: what a network's name is -- an ISP's (AS12389), a gateway's
// hash (see networkID)
var netIDRe = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)

// ValidNetID: whether id may name a network, as a page sends it
func ValidNetID(id string) bool { return netIDRe.MatchString(id) }

// requestNetwork: the network a request is of -- its "network <id>" line,
// "" for none: the current one
func requestNetwork(b []byte) string {
	for _, l := range strings.Split(string(b), "\n") {
		if id, ok := strings.CutPrefix(strings.TrimSpace(l), "network "); ok && ValidNetID(id) {
			return id
		}
	}
	return ""
}

// forgetKeys: the names a request holds, as memory keys them. What is no
// name -- too long, a space in it -- is left out: the file is the user's
// to write.
func forgetKeys(b []byte) []string {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.ToLower(strings.TrimSpace(l))
		if l == "" || len(l) > 260 || strings.ContainsAny(l, " \t#") {
			continue
		}
		out = append(out, l)
	}
	return out
}

// watchReset looks for a reset request and changed user lists every
// second: the UI waits for both to be taken. cfg is the main loop's as it
// is now: it was a copy taken at the start, and a verdict dropped after the
// settings changed rewrote the list by the old ones -- the families of a
// switch turned off came back direct until the next cycle.
func watchReset(ctx context.Context, cfg func() Config, a *api, st *state) {
	t := time.NewTicker(requestPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c := cfg()
			takeReset(c, a, st)
			takeForget(c, a, st)
			// the user's lists and presets reach the core within a second;
			// a reload left pending -- by a reset, say, which removed its
			// request all the same -- is not left for the next cycle
			listMu.Lock()
			syncUserFiles(a)
			syncRoutes(a)
			retryReloads(a)
			listMu.Unlock()
		}
	}
}

// listRules: the rules a list file holds now, comments and blank lines left
// out. A missing file holds none.
func listRules(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// replaceList writes a rule-provider file atomically and has the core reload
// it; listMu held. A failed reload is remembered and retried, see
// reloadPending.
func replaceList(a *api, path, provider, body string) error {
	if err := paths.ReplaceFile(path, []byte(body)); err != nil {
		return fmt.Errorf("list %s not written: %w", path, err)
	}
	if err := a.reloadProvider(provider); err != nil {
		reloadPending[provider] = true
		return fmt.Errorf("provider %s not reloaded, will retry: %w", provider, err)
	}
	delete(reloadPending, provider)
	return nil
}

func skipped(cfg Config, dom string) bool {
	for _, s := range cfg.SkipSuffix {
		if dom == s || strings.HasSuffix(dom, "."+s) {
			return true
		}
	}
	return false
}

func concat(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

// first-seen order is kept: the queue is prioritised
func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// reportsMax: the probe journal is kept to this size, the one before it in
// .1 -- a week or two of reports. It grew by a megabyte a day with no bound.
var reportsMax int64 = 8 << 20

// reportsMu: the workers append concurrently, and a rotation must not rename
// the file from under another's append
var reportsMu sync.Mutex

func appendJSONL(path string, rep probe.Report) {
	if path == "" {
		return
	}
	b, err := json.Marshal(rep)
	if err != nil {
		return
	}
	reportsMu.Lock()
	defer reportsMu.Unlock()
	// before opening: Windows will not rename an open file
	_ = logfile.RotateIfOver(path, reportsMax)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

func preview(d []string) string {
	s := append([]string{}, d...)
	sort.Strings(s)
	if len(s) > 5 {
		return strings.Join(s[:5], ", ") + ", ..."
	}
	return strings.Join(s, ", ")
}

func ms(r probe.PathResult) string {
	if !r.TLSOk {
		return "-"
	}
	return fmt.Sprintf("%dms", (r.TCPTime + r.TLSTime).Milliseconds())
}

// msVal: the best measurement if present, otherwise the last one
func msVal(best int64, last probe.PathResult) string {
	if best > 0 {
		return fmt.Sprintf("%dms", best)
	}
	return ms(last)
}

// directFailed: the direct side of a probe did not get through -- no TCP, or
// a TLS handshake that was attempted and failed.
func directFailed(rep probe.Report) bool {
	d := rep.Direct
	return !d.TCPOk || (d.TLSTried && !d.TLSOk) || d.HTTPFailed()
}

// directDownOn: the direct side failed on this port at a stage the tunnel
// side got past. The same failure on both paths is the server's -- no TLS on
// 443 for a speedtest server that works on 20000, a push protocol that is
// not HTTP -- and says nothing about the direct path; counting it sent
// speedtest servers back into the tunnel once already. Nor does a tunnel
// that failed EARLIER: direct reset at TLS while the tunnel never got a TCP
// connection shows nothing about the server either -- only the stages were
// compared, and such a CLEAN name came out INCONCLUSIVE, sent back to the
// tunnel.
func directDownOn(rep probe.Report) bool {
	d := rep.Direct
	if !directFailed(rep) {
		return false
	}
	// never dialled: the direct resolver gave nothing, and direct traffic
	// would have nothing to go to whatever the tunnel shows
	if d.Err == "" && !d.TCPOk {
		return true
	}
	return reached(rep.Tunnel) > failedAt(d)
}

// probe stages in the order a check goes through them
var stageRank = map[string]int{"tcp": 1, "tls": 2, "http_write": 3, "http_read": 4, "body": 5}

// stageDone: past every stage
const stageDone = 6

// failedAt: the stage a failed side stopped at; an unknown one counts as the
// first, so any tunnel that got anywhere is past it.
func failedAt(r probe.PathResult) int {
	if n, ok := stageRank[r.ErrStage]; ok && r.Err != "" {
		return n
	}
	if r.TCPOk && r.TLSTried && !r.TLSOk {
		return stageRank["tls"]
	}
	return stageRank["tcp"]
}

// reached: the stage a side stopped at, stageDone past all of them; 0 for
// a side that shows no progress at all.
func reached(r probe.PathResult) int {
	if r.Err != "" {
		if n, ok := stageRank[r.ErrStage]; ok {
			return n
		}
		return 0
	}
	if !r.TCPOk || (r.TLSTried && !r.TLSOk) {
		return 0
	}
	return stageDone
}

// failTerm: how long a verdict other than CLEAN holds before it is checked
// again. FailTTL doubles with each check in a row that found nothing new, up
// to the cap: names blocked for good -- ad networks, sites on the registry --
// were probed every hour, and made two thirds of all probes. A false
// "blocked" only costs a detour, so noticing an unblock later is the cheap
// side. A name reverted N times waits at least N*FailTTL.
func failTerm(cfg Config, streak, reverts int) time.Duration {
	limit := max(cfg.MaxBackoff, cfg.FailTTL)
	d := cfg.FailTTL
	for i := 0; i < streak && d < limit; i++ {
		d *= 2
	}
	return min(max(d, time.Duration(reverts)*cfg.FailTTL), limit)
}

// sameFinding: whether a check found what the one before it did. The blocked
// verdicts count as one: which of them a name gets depends on which of its
// ports reported first.
func sameFinding(a, b probe.Verdict) bool {
	return a == b || (isBlocked(a) && isBlocked(b))
}

// verdictRank: how bad a port's verdict is for the name as a whole; the
// worst port's verdict is the name's. INCONCLUSIVE means "could not
// measure" -- e.g. the host has no QUIC on either path -- and is below a
// definite verdict, or the name would stay in the tunnel over a protocol it
// does not have. The order used to be the ports' order: a SLOWER first held
// on to its place against a BLOCKED_TLS after it, and a CLEAN kept once
// before (see SlowOnce) sent the name direct with one of its ports blocked.
var verdictRank = map[probe.Verdict]int{
	probe.Inconcl:     0,
	probe.Clean:       1,
	probe.CleanSplit:  2,
	probe.Slower:      3,
	probe.BlockedQUIC: 4,
	probe.ContentDiff: 5,
	probe.BlockedTCP:  6,
	probe.BlockedTLS:  6,
	probe.BlockedDPI:  6,
	probe.MITM:        7,
}

// worse: whether a is worse than b; of two alike the first stays
func worse(a, b probe.Verdict) bool { return verdictRank[a] > verdictRank[b] }

// worstPort: the name's verdict, its worst port's. A name going direct with
// its hello cut has its QUIC on 443 refused by the core (see awgconf): the
// browser falls back to TCP at once, and what QUIC showed does not count.
func worstPort(eps []endpoint, reps []probe.Report) probe.Report {
	split := false
	for i, r := range reps {
		if !eps[i].udp && eps[i].port == 443 && r.Verdict == probe.CleanSplit {
			split = true
		}
	}
	var rep probe.Report
	for i, r := range reps {
		if split && eps[i].udp && eps[i].port == 443 {
			continue
		}
		if rep.Domain == "" || worse(r.Verdict, rep.Verdict) {
			rep = r
		}
	}
	return rep
}

// splitNoQUIC: a name going direct with its hello cut whose QUIC on 443,
// seen and probed, was not clean -- plain, or through the decoy when it is
// on. Its QUIC is refused (see awgconf): the browser takes TCP at once
// rather than waiting on a QUIC that goes nowhere.
func splitNoQUIC(eps []endpoint, reps []probe.Report) bool {
	split, bad := false, false
	for i, r := range reps {
		if eps[i].port != 443 {
			continue
		}
		if !eps[i].udp && r.Verdict == probe.CleanSplit {
			split = true
		}
		if eps[i].udp && r.Verdict != probe.Clean && r.Verdict != probe.CleanSplit {
			bad = true
		}
	}
	return split && bad
}

// splitNoTCP: the mirror of splitNoQUIC -- a name whose QUIC on 443 goes
// direct, plain or through the decoy, while its TCP on 443 is blocked even
// with the hello cut, every other port going direct. The browser speaks
// QUIC to it: rr14---sn-n8v7kn7d.googlevideo.com moved 508 KB direct over
// QUIC through the decoy on 08.10, and was called BLOCKED_DPI by its TCP --
// held in the tunnel, where the service refused it the address its page
// came from. It goes direct now, its TCP on 443 refused so the browser does
// not wait on it; only with the decoy on, which its QUIC needs.
func splitNoTCP(cfg Config, eps []endpoint, reps []probe.Report) bool {
	if !cfg.Split || !cfg.QUICFake {
		return false
	}
	quicOK, tcpCut := false, false
	for i, r := range reps {
		switch {
		case eps[i].udp && eps[i].port == 443:
			quicOK = goesDirect(r.Verdict)
		case !eps[i].udp && eps[i].port == 443:
			tcpCut = r.Verdict == probe.BlockedDPI
		case !goesDirect(r.Verdict):
			return false
		}
	}
	return quicOK && tcpCut
}

// quicReport: the report of the QUIC port on 443
func quicReport(eps []endpoint, reps []probe.Report) probe.Report {
	for i, r := range reps {
		if eps[i].udp && eps[i].port == 443 {
			return r
		}
	}
	return probe.Report{}
}

// goesDirect: a verdict that sends the name direct, with its hello cut or not
func goesDirect(v probe.Verdict) bool { return v == probe.Clean || v == probe.CleanSplit }

func isBlocked(v probe.Verdict) bool {
	return v == probe.BlockedTCP || v == probe.BlockedTLS || v == probe.BlockedDPI || v == probe.BlockedQUIC
}

// directReachedV6: the direct side of a probe got through to an IPv6 node --
// the network has IPv6 after all, see learnV6.
func directReachedV6(rep probe.Report) bool {
	ip := net.ParseIP(rep.TestedIP)
	return ip != nil && ip.To4() == nil && !rep.DirectNoV6 &&
		rep.Verdict != probe.Inconcl && !directFailed(rep)
}

// withTCP adds plain TCP on every port seen only as QUIC. A mihomo rule
// covers the name on every protocol, and a browser falls back from QUIC to
// TCP whenever it likes: a name seen only over QUIC (a remembered Alt-Svc
// does that) used to go direct on TCP that nobody had checked.
func withTCP(eps []endpoint) []endpoint {
	has := map[endpoint]bool{}
	for _, e := range eps {
		has[e] = true
	}
	out := append([]endpoint(nil), eps...)
	for _, e := range eps {
		if tcp := (endpoint{port: e.port}); e.udp && !has[tcp] {
			has[tcp] = true
			out = append(out, tcp)
		}
	}
	return out
}

// plainTCP keeps the endpoints an address can be probed on without a name.
func plainTCP(eps []endpoint) []endpoint {
	var out []endpoint
	for _, e := range eps {
		if !e.udp && e.port != 443 {
			out = append(out, e)
		}
	}
	return out
}

// directResolvers: the detector's resolvers for the direct path -- the
// program's DNS cache while it answers the core (see dnscache), else the
// direct list the core asks itself. The node probed must be the one the
// traffic goes to, and the cache keeps a node for days past what a server
// names now.
func directResolvers(cfg Config) []probe.Resolver {
	if cfg.DNSCache && dnscache.Serving() != "" {
		return []probe.Resolver{probe.LocalResolver()}
	}
	return cfg.DirectDNS
}

func (cfg Config) network(id string) {
	if cfg.OnNetwork != nil {
		cfg.OnNetwork(id)
	}
}
