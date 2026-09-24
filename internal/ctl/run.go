// Controller: takes candidates from live mihomo traffic, runs probes,
// keeps a verdict memory with TTLs, bound to the network.
// By default it applies NOTHING -- it only logs what it would do.
package ctl

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"dpiswitch/internal/probe"
)

type Config struct {
	DirectAddr string
	TunnelAddr string
	APIAddr    string
	CfgPath    string
	ProxyName  string
	Provider   string
	ListPath   string
	// the same verdicts as addresses, see verifiedIPs
	IPProvider    string
	IPListPath    string
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
	Families     bool             // extend verdicts to the whole domain, see family.go
	DirectDNS    []probe.Resolver // empty -- the prober's built-in DoH
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
}

func cycle(cfg Config, a *api, st *state, netID string, w *watcher) {
	conns, err := a.connections()
	if err != nil {
		log.Printf("cannot read connections: %v", err)
		return
	}

	ports := w.drain()

	// everything the core has talked to, whatever route it took: a name
	// still in use keeps its verdict worth re-checking. From the watcher's
	// every-second look, not this snapshot alone -- the snapshot misses the
	// short connections most names live on, and a name missed that way
	// looked abandoned: its expired verdict was never re-checked
	live := w.drainLive()
	for _, c := range conns {
		if d := c.domain(); d != "" {
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
	// Names a verdict must not exist for: skipped ones, and ones the user's
	// own lists route (force-tunnel, presets). Filtering new candidates was
	// not enough -- a verdict made before stayed, was re-checked while the
	// name was in use, and a pinned host's CLEAN made its siblings a family.
	// The lists as files, plus what connections showed: a preset's address
	// ranges pin names no file spells out.
	lists := loadPinned(cfg.PinnedLists)
	seenPinned := map[string]bool{}
	for _, d := range w.drainPinned() {
		seenPinned[d] = true
	}
	leaveAlone := func(dom string) bool {
		return seenPinned[dom] || lists.has(dom) || skipped(cfg, dom)
	}
	if n := st.drop(netID, leaveAlone); n > 0 {
		log.Printf("dropped %d verdicts for names that are skipped or pinned by a list", n)
	}

	// order matters: suspicious first, then expired,
	// and only then new candidates -- rolling back is more urgent than expanding
	queue := dedupe(concat(
		suspectDirect(cfg, st, netID, conns),
		st.quicOnly(netID, cfg.Idle),
		st.expired(netID, cfg.Idle),
		pickCandidates(cfg, st, netID, ports),
	))
	queue = slices.DeleteFunc(queue, leaveAlone)
	if len(queue) == 0 {
		// verdicts expire with no probe running: the list follows anyway
		if cfg.Apply {
			syncList(cfg, a, st, netID, false)
		}
		return
	}
	total := len(queue)
	if len(queue) > cfg.PerCycle {
		queue = queue[:cfg.PerCycle]
		log.Printf("%d domains queued, taking %d this cycle", total, cfg.PerCycle)
	}

	direct := probe.Dialer{Addr: cfg.DirectAddr, Timeout: cfg.Timeout, DNS: cfg.DirectDNS, Established: a.established}
	tunnel := probe.Dialer{Addr: cfg.TunnelAddr, Timeout: cfg.Timeout, Established: a.established}

	var (
		wg      sync.WaitGroup
		sem     = make(chan struct{}, cfg.Workers)
		mu      sync.Mutex
		changed bool
	)
	for _, dom := range queue {
		wg.Add(1)
		go func(dom string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// mihomo rules are per domain, so a decision applies
			// to all ports at once. Hence every port seen must be checked,
			// and the worst verdict wins.
			// the ports seen this minute plus the ones remembered: a re-check
			// by TTL often runs while the name is idle, and must still probe
			// the ports it is really used on
			var stored []string
			if prev, ok := st.get(netID, dom); ok {
				stored = prev.Endpoints
			}
			eps := mergeEndpoints(ports[dom], stored)
			if _, addr := probe.AddrKey(dom); addr {
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
			// the direct path failed on a TCP port -- see entry.DirectDown
			directDown := false
			var downOn probe.Report
			for _, ep := range eps {
				r := probe.CheckProto(direct, tunnel, dom, ep.port, cfg.Attempts, ep.udp)
				appendJSONL(cfg.JSONLPath, r)
				if r.Aborted {
					// leave memory alone: the domain stays queued
					// and is re-checked once the core is back
					return
				}
				// QUIC failing direct is left out: most hosts have no QUIC at
				// all, and fail on both paths for that reason alone
				if !ep.udp && directDownOn(r) && !directDown {
					directDown, downOn = true, r
				}
				// INCONCLUSIVE means "could not measure" -- e.g. the host
				// does not answer QUIC on either path. Such a result
				// must not override a definite verdict, otherwise the domain
				// gets stuck in the tunnel over a protocol it does not have.
				switch {
				case rep.Domain == "":
					rep = r
				case rep.Verdict == probe.Inconcl && r.Verdict != probe.Inconcl:
					rep = r
				case r.Verdict == probe.Inconcl:
				case rep.Verdict == probe.Clean && r.Verdict != probe.Clean:
					rep = r
				}
			}
			// A port whose direct side failed while the tunnel failed too is
			// INCONCLUSIVE, and that must not override a definite verdict --
			// but CLEAN is a promise that the name works direct on every port
			// it uses, and on this one it does not. Clean on 443 plus dead
			// direct on 5228 used to come out CLEAN.
			if rep.Verdict == probe.Clean && directDown {
				rep = downOn
				rep.Verdict = probe.Inconcl
				rep.Reason = fmt.Sprintf("direct path fails on %s/%d: %s",
					downOn.Proto, downOn.Port, downOn.Reason)
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
			expiredClean := had && prev.Verdict == probe.Clean && time.Now().After(prev.ExpiresAt)
			// Keeping a verdict is for the tunnel side failing. When the
			// DIRECT path itself failed, a CLEAN is not kept either: whatever
			// this means about blocking, the host does not work direct now.
			// On any TCP port it uses, not only the one the report came from --
			// and not over QUIC, which most hosts simply do not have.
			dropClean := had && prev.Verdict == probe.Clean && (expiredClean || directDown)
			if had && rep.Verdict == probe.Inconcl && prev.Verdict != probe.Inconcl && !dropClean {
				kept := *prev
				kept.ExpiresAt = time.Now().Add(cfg.FailTTL)
				kept.Endpoints = endpointStrings(eps)
				st.put(netID, dom, &kept)
				log.Printf("  %s inconclusive (%s), keeping %s, retry in %s",
					dom, rep.Reason, prev.Verdict, cfg.FailTTL)
				return
			}

			e := &entry{
				Verdict:    rep.Verdict,
				Reason:     rep.Reason,
				DecidedAt:  time.Now(),
				TestedIP:   rep.TestedIP,
				Endpoints:  endpointStrings(eps),
				DirectDown: rep.Verdict == probe.Inconcl && directDown,
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
			if rep.Verdict == probe.Clean {
				e.ExpiresAt = time.Now().Add(cfg.TTL)
			} else {
				e.ExpiresAt = time.Now().Add(cfg.FailTTL)
			}
			if had {
				e.Reverts = prev.Reverts
				// the domain lost its direct path -- the more often this happens,
				// the longer it waits before being re-checked
				if dropClean && rep.Verdict == probe.Inconcl {
					// not a revert: no blocking was shown, the direct path just
					// could not be confirmed. Retry at the normal pace.
					log.Printf("  %s inconclusive (%s), CLEAN not confirmed -- "+
						"through the tunnel until the next check in %s", dom, rep.Reason, cfg.FailTTL)
				} else if prev.Verdict == probe.Clean && rep.Verdict != probe.Clean {
					e.Reverts++
					// from the blocked re-check up: the direct term (a week)
					// hit the cap on the very first revert, so it never grew
					backoff := time.Duration(e.Reverts) * cfg.FailTTL
					if backoff > cfg.MaxBackoff {
						backoff = cfg.MaxBackoff
					}
					e.ExpiresAt = time.Now().Add(backoff)
					log.Printf("REVERT %s: %s (%s), reverts total %d", dom, rep.Verdict, rep.Reason, e.Reverts)
				}
			}

			st.put(netID, dom, e)

			mu.Lock()
			if !had || prev.Verdict != rep.Verdict {
				changed = true
				if rep.Verdict == probe.Clean {
					// log the BEST measurements -- the very ones the decision
					// is based on. The last pass may have been slow by chance,
					// and showing it would be misleading
					log.Printf("CLEAN %s (node %s, direct %s vs tunnel %s)",
						dom, rep.TestedIP, msVal(rep.DirectMs, rep.Direct), msVal(rep.TunnelMs, rep.Tunnel))
				} else if !had {
					log.Printf("  %s %s: %s", rep.Verdict, dom, rep.Reason)
				}
			}
			mu.Unlock()
		}(dom)
	}
	wg.Wait()

	if err := st.save(); err != nil {
		log.Printf("state not saved: %v", err)
	}
	switch {
	case cfg.Apply:
		// not only when a verdict changed: a CLEAN expiring changes the list
		// too, and one re-confirmed after it dropped out must come back
		syncList(cfg, a, st, netID, false)
	case changed:
		applyList(cfg, a, st, netID) // observe mode: only logs
	}
}

// candidates: what the watcher accumulated and we have not decided yet.
// protocol and route filters were already applied while collecting.
func pickCandidates(cfg Config, st *state, netID string, seen map[string][]endpoint) []string {
	var out []string
	for dom := range seen {
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
		dom := c.domain()
		if dom == "" || !c.viaDirect() || c.Download > 0 {
			continue
		}
		e, had := st.get(netID, dom)
		switch {
		case had && e.Verdict == probe.Clean:
		case !had && fams[familyOf(dom)]:
			// sent direct by a family, never checked on its own
		case had && e.Verdict == probe.Inconcl && fams[familyOf(dom)]:
			// a family keeps sending it direct while its own check never
			// concluded. Without this it would never be picked again: the
			// entry exists, so it is not "unchecked", and it is not CLEAN
			// either -- and it would sit direct and broken forever.
		default:
			continue
		}
		if ts, err := time.Parse(time.RFC3339, c.Start); err == nil && time.Since(ts) > 10*time.Second {
			out = append(out, dom)
		}
	}
	return dedupe(out)
}

// write verdicts to the rule-provider and have the core reload it
func applyList(cfg Config, a *api, st *state, netID string) {
	syncList(cfg, a, st, netID, true)
}

// syncList brings the rule-provider files in line with memory. Unless forced
// it writes only when the rules differ from what is on disk: it runs every
// cycle, because verdicts change the list without any verdict changing --
// a CLEAN expires, or comes back after a re-check that found it the same.
func syncList(cfg Config, a *api, st *state, netID string, force bool) {
	doms, fams := directRules(cfg, st, netID)
	if !cfg.Apply {
		log.Printf("observe mode: %d domains would go DIRECT (%s)", len(doms), preview(doms))
		return
	}
	var ips []string
	if cfg.IPListPath != "" {
		ips = st.verifiedIPs(netID)
	}
	if !force && slices.Equal(listRules(cfg.ListPath), doms) &&
		(cfg.IPListPath == "" || slices.Equal(listRules(cfg.IPListPath), ips)) {
		return
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
	// the tested addresses of the same CLEAN names, for connections that
	// arrive with no name at all -- see verifiedIPs
	if cfg.IPListPath != "" {
		var ib strings.Builder
		ib.WriteString("# generated by the controller, do not edit\n")
		ib.WriteString("# the node each CLEAN name was probed on; matched only by\n")
		ib.WriteString("# connections to a bare address (the rule carries no-resolve)\n")
		for _, ip := range ips {
			ib.WriteString(ip + "\n")
		}
		if err := replaceList(a, cfg.IPListPath, cfg.IPProvider, ib.String()); err != nil {
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

func clearList(cfg Config, a *api) {
	b := "# auto-switch disabled -- everything goes through the tunnel\n"
	if err := replaceList(a, cfg.ListPath, cfg.Provider, b); err != nil {
		log.Print(err)
		return
	}
	if cfg.IPListPath != "" {
		if err := replaceList(a, cfg.IPListPath, cfg.IPProvider, b); err != nil {
			log.Print(err)
			return
		}
	}
	log.Println("auto-switch disabled: direct path removed from all domains")
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

// replaceList writes a rule-provider file atomically and has the core reload it.
func replaceList(a *api, path, provider, body string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0644); err != nil {
		return fmt.Errorf("list %s not written: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("list %s not replaced: %w", path, err)
	}
	if err := a.reloadProvider(provider); err != nil {
		return fmt.Errorf("provider %s not reloaded: %w", provider, err)
	}
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

func appendJSONL(path string, rep probe.Report) {
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	b, _ := json.Marshal(rep)
	fmt.Fprintln(f, string(b))
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

// directDownOn: the direct side failed on this port, and not the way the
// tunnel side failed too. The same failure on both paths is the server's --
// no TLS on 443 for a speedtest server that works on 20000, a push protocol
// that is not HTTP -- and says nothing about the direct path; counting it
// sent speedtest servers back into the tunnel once already.
func directDownOn(rep probe.Report) bool {
	d, t := rep.Direct, rep.Tunnel
	return directFailed(rep) && !(t.Err != "" && t.ErrStage == d.ErrStage)
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
