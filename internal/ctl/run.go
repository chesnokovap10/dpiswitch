// Controller: takes candidates from live mihomo traffic, runs probes,
// keeps a verdict memory with TTLs, bound to the network.
// By default it applies NOTHING -- it only logs what it would do.
package ctl

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
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
}

func cycle(cfg Config, a *api, st *state, netID string, w *watcher) {
	conns, err := a.connections()
	if err != nil {
		log.Printf("cannot read connections: %v", err)
		return
	}

	ports := w.drain()

	// everything the core is talking to right now, whatever route it takes:
	// a name still in use keeps its verdict worth re-checking
	var live []string
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

	// order matters: suspicious first, then expired,
	// and only then new candidates -- rolling back is more urgent than expanding
	queue := dedupe(concat(
		suspectDirect(cfg, st, netID, conns),
		st.expired(netID, cfg.Idle),
		pickCandidates(cfg, st, netID, ports),
	))
	if len(queue) == 0 {
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
			} else if len(eps) == 0 {
				eps = []endpoint{{port: 443}}
			}
			var rep probe.Report
			for _, ep := range eps {
				r := probe.CheckProto(direct, tunnel, dom, ep.port, cfg.Attempts, ep.udp)
				appendJSONL(cfg.JSONLPath, r)
				if r.Aborted {
					// leave memory alone: the domain stays queued
					// and is re-checked once the core is back
					return
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
			dropClean := had && prev.Verdict == probe.Clean && (expiredClean || directFailed(rep))
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
				Verdict:   rep.Verdict,
				Reason:    rep.Reason,
				DecidedAt: time.Now(),
				TestedIP:  rep.TestedIP,
				// a name being probed is a name in use right now
				LastSeen:  time.Now(),
				Endpoints: endpointStrings(eps),
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
					backoff := time.Duration(e.Reverts) * cfg.TTL
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
	if changed {
		applyList(cfg, a, st, netID)
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
	doms, fams := directRules(cfg, st, netID)
	if !cfg.Apply {
		log.Printf("observe mode: %d domains would go DIRECT (%s)", len(doms), preview(doms))
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
		for _, ip := range st.verifiedIPs(netID) {
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
	return !d.TCPOk || (d.TLSTried && !d.TLSOk)
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
