package ctl

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"dpiswitch/internal/probe"
)

// GET /connections returns a snapshot of OPEN connections. A typical web
// request lives for seconds, so polling once per cycle misses almost
// everything: in one session 353 domains went through the core, yet only 31
// showed up in polls. So we look often and accumulate names, while probing
// still happens once per cycle.
type watcher struct {
	mu   sync.Mutex
	seen map[string]map[endpoint]bool
	// order: the names in seen as they first turned up -- the order they
	// are probed in, see drain and requeue
	order []string
	// bare destination addresses of connections that carry no name -- see
	// state.touchIPs
	bare map[string]bool
	// every name seen, whatever route it took -- see state.touch
	live map[string]bool
	// names routed by a list the detector does not write -- see pinned()
	pinned map[string]bool
	// nameless TCP connections that went to the tunnel, by address, and in
	// how many cycles each was seen -- see addrCandidates
	addrPorts  map[string]map[endpoint]bool
	addrCycles map[string]int
	// fresh: the names first seen since the fast lane last looked, see
	// takeFresh
	fresh []string
}

func newWatcher(ctx context.Context, cfg Config, a *api) *watcher {
	w := &watcher{seen: map[string]map[endpoint]bool{}, bare: map[string]bool{},
		live: map[string]bool{}, pinned: map[string]bool{},
		addrPorts: map[string]map[endpoint]bool{}, addrCycles: map[string]int{}}
	go w.loop(ctx, cfg, a)
	return w
}

func (w *watcher) loop(ctx context.Context, cfg Config, a *api) {
	t := time.NewTimer(cfg.WatchInterval)
	defer t.Stop()
	var failed int
	slowed := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		next := cfg.WatchInterval
		conns, err := a.connections()
		if err != nil {
			// the core may have restarted -- don't log on every iteration
			if failed++; failed%30 == 1 {
				log.Printf("watcher: cannot read connections: %v", err)
			}
		} else {
			failed = 0
			w.observe(cfg, conns)
			next = watchStep(cfg.WatchInterval, len(conns))
			// said once each way; coming back takes a clear drop, so a count
			// hovering at the first step does not fill the log
			switch n := len(conns); {
			case !slowed && next > cfg.WatchInterval:
				slowed = true
				log.Printf("watcher: %d connections open, looking every %s", n, next)
			case slowed && n < watchPerStep*3/4:
				slowed = false
				log.Printf("watcher: %d connections open, looking every %s again", n, next)
			}
		}
		t.Reset(next)
	}
}

// watchPerStep, watchMaxStep: see watchStep
const (
	watchPerStep = 400
	watchMaxStep = 5
)

// watchStep: how long to wait before the next look, by how many connections
// the last one returned. Each look is the core's whole connection table,
// serialised by the core and parsed here: 44 connections are 33 KB, a
// torrent client's thousand are 730 KB and 3.7 ms to parse -- every second,
// in both processes. Such a load is mostly peers no probe is for, and a web
// name missed once is caught when it is requested again. Every 400
// connections add a step, up to five.
func watchStep(base time.Duration, conns int) time.Duration {
	return base * time.Duration(min(1+conns/watchPerStep, watchMaxStep))
}

// observe takes in one look at the core's connections.
func (w *watcher) observe(cfg Config, conns []connection) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, c := range conns {
		// the prober's own connections are neither a use of the name nor a
		// candidate: see fromProbe
		if c.fromProbe() {
			continue
		}
		dom := c.domain()
		if dom != "" {
			w.live[dom] = true
		}
		// a nameless connection from an application
		if dom == "" && c.Metadata.DestinationIP != "" {
			w.bare[c.Metadata.DestinationIP] = true
			if addrProbeable(c, cfg.ProxyName) {
				ip := c.Metadata.DestinationIP
				if w.addrPorts[ip] == nil {
					w.addrPorts[ip] = map[endpoint]bool{}
				}
				w.addrPorts[ip][endpoint{port: c.port()}] = true
			}
		}
		// the route is pinned by a list the detector does not write: a
		// verdict would change nothing, probing is a waste -- and a CLEAN
		// made here would count towards a family
		if dom != "" && c.pinned() {
			w.pinned[dom] = true
			continue
		}
		// besides tunnelled ones, take those sent direct by our list:
		// this way hosts admitted by a family without their own verdict
		// get checked. And in observe only, everything: it all goes direct.
		// Already decided ones are filtered by the state
		// And what no rule but the last took and that went direct: with no
		// first tunnel loaded, everything -- the ClientHello cut is checked
		// then (see Config.alone).
		// The cut's own names too: their ports were not seen from the day
		// of their verdict on, and a check made while one is open on QUIC
		// did not know of it.
		if dom == "" || !c.probeable() ||
			!(c.viaTunnel(cfg.ProxyName) || c.byProvider(cfg.Provider) || c.byProvider(ObserveProvider) ||
				cfg.SplitProvider != "" && c.byProvider(cfg.SplitProvider) ||
				c.byProvider(ObserveSplitProvider) || c.inherited() ||
				c.Rule == "Match" && c.viaDirect()) {
			continue
		}
		if w.seen[dom] == nil {
			w.seen[dom] = map[endpoint]bool{}
			w.order = append(w.order, dom)
			if len(w.fresh) < maxBacklog {
				w.fresh = append(w.fresh, dom)
			}
		}
		w.seen[dom][endpoint{udp: c.isUDP(), port: c.port()}] = true
	}
}

// take what has been accumulated and reset: decided domains will not come
// back because the state filters them out
// endpoint: one probe target of a domain. The protocol matters --
// QUIC may be blocked separately from TCP on the same port 443.
type endpoint struct {
	udp  bool
	port int
}

func (e endpoint) String() string {
	if e.udp {
		return fmt.Sprintf("quic/%d", e.port)
	}
	return fmt.Sprintf("tcp/%d", e.port)
}

// parseEndpoint reads back what String wrote.
func parseEndpoint(s string) (endpoint, bool) {
	proto, port, ok := strings.Cut(s, "/")
	n, err := strconv.Atoi(port)
	if !ok || err != nil || n <= 0 || n > 65535 {
		return endpoint{}, false
	}
	switch proto {
	case "tcp":
		return endpoint{port: n}, true
	case "quic":
		return endpoint{udp: true, port: n}, true
	}
	return endpoint{}, false
}

// maxEndpoints caps what one name remembers: every port costs a probe.
const maxEndpoints = 8

// mergeEndpoints: the ports seen now plus the ones remembered, most recent
// first, without duplicates -- and how many more there were than the cap
// let in. A name on more ports than that cannot be called clean: see cycle.
func mergeEndpoints(now []endpoint, stored []string) (out []endpoint, dropped int) {
	seen, in := map[endpoint]bool{}, map[endpoint]bool{}
	add := func(e endpoint) {
		if seen[e] {
			return
		}
		seen[e] = true
		switch {
		case len(out) < maxEndpoints:
			out = append(out, e)
			in[e] = true
		case !e.udp && in[endpoint{udp: true, port: e.port}]:
			// the TCP of a QUIC port taken: withTCP puts it back, it is
			// probed. Counted as left out, a name on eight ports whose
			// QUIC had brought its TCP as a ninth was remembered with
			// nine, and never came out of INCONCLUSIVE again
		default:
			dropped++
		}
	}
	for _, e := range now {
		add(e)
	}
	for _, s := range stored {
		if e, ok := parseEndpoint(s); ok {
			add(e)
		}
	}
	return out, dropped
}

func endpointStrings(eps []endpoint) []string {
	out := make([]string, len(eps))
	for i, e := range eps {
		out[i] = e.String()
	}
	return out
}

// takeFresh: the names first seen since the last call, with the ports seen
// so far. They stay in seen: the cycle takes whichever the fast lane had no
// room for, and the one it is probing is left to it (see claim).
func (w *watcher) takeFresh() (doms []string, ports map[string][]endpoint) {
	w.mu.Lock()
	defer w.mu.Unlock()
	doms, w.fresh = w.fresh, nil
	ports = make(map[string][]endpoint, len(doms))
	for _, d := range doms {
		for e := range w.seen[d] {
			ports[d] = append(ports[d], e)
		}
	}
	return doms, ports
}

// drainBare: the bare addresses accumulated since the last call.
func (w *watcher) drainBare() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := keys(w.bare)
	w.bare = map[string]bool{}
	return out
}

// drainLive: the names accumulated since the last call.
func (w *watcher) drainLive() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := keys(w.live)
	w.live = map[string]bool{}
	return out
}

// drainPinned: the pinned names accumulated since the last call.
func (w *watcher) drainPinned() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := keys(w.pinned)
	w.pinned = map[string]bool{}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// minAddrCycles: an address must turn up in this many cycles before it is
// probed. A P2P client left out of the exclusions would otherwise flood the
// queue with thousands of one-off peer addresses.
const minAddrCycles = 2

// addrProbeable: a nameless connection whose address can be judged without a
// name. Plain TCP only, and not 443: a bare address on 443 is TLS the sniffer
// could not read a name from, and blocking here works on that name -- a
// probe without it would test something other than the real traffic. UDP
// (STUN and the like) cannot be judged without knowing its protocol.
func addrProbeable(c connection, tunnelProxy string) bool {
	return !c.fromProbe() && !c.pinned() &&
		strings.EqualFold(c.Metadata.Network, "tcp") &&
		c.port() > 0 && c.port() != 443 &&
		(c.viaTunnel(tunnelProxy) || c.byProvider(ObserveProvider) || c.byProvider(ObserveSplitProvider))
}

// drain hands over what has been seen since the last call, with the order
// to take it in: names as they first turned up -- those given back by
// requeue first -- then the addresses that turned up often enough. A map
// alone used to be handed over, and a cycle with more candidates than it
// takes picked them in no order at all.
func (w *watcher) drain() (map[string][]endpoint, []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[string][]endpoint, len(w.seen))
	order := append([]string(nil), w.order...)
	for d, eps := range w.seen {
		for e := range eps {
			out[d] = append(out[d], e)
		}
		sort.Slice(out[d], func(i, j int) bool {
			if out[d][i].port != out[d][j].port {
				return out[d][i].port < out[d][j].port
			}
			return !out[d][i].udp
		})
	}
	// addresses: count the cycles, hand over the ones seen often enough
	var addrs []string
	for ip, eps := range w.addrPorts {
		w.addrCycles[ip]++
		if w.addrCycles[ip] < minAddrCycles {
			continue
		}
		key := probe.AddrPrefix + ip
		if _, given := out[key]; !given {
			addrs = append(addrs, key)
		}
		for e := range eps {
			out[key] = append(out[key], e)
		}
	}
	sort.Strings(addrs)
	order = append(order, addrs...)
	w.addrPorts = map[string]map[endpoint]bool{}
	if len(w.addrCycles) > 10000 {
		w.addrCycles = map[string]int{} // bounded: a flood must not grow memory
	}
	w.seen = map[string]map[endpoint]bool{}
	w.order = nil
	return out, order
}

// idle: a tick that runs no cycle -- the probes paused, no network. Only a
// cycle drained what the watcher gathers, and it went on gathering every
// second: with the tunnel down for a day, or no first tunnel and the cut
// off -- paused for good -- every name and every bare address seen stayed,
// a torrent client's peers among them, for as long as the service ran. The
// names and addresses in use are handed over, to be marked as a cycle marks
// them; the candidates wait for the probes within maxBacklog, the oldest
// going past it; the rest is dropped.
func (w *watcher) idle() (live, bare []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	live, bare = keys(w.live), keys(w.bare)
	w.live, w.bare, w.pinned = map[string]bool{}, map[string]bool{}, map[string]bool{}
	w.addrPorts = map[string]map[endpoint]bool{}
	if n := len(w.order) - maxBacklog; n > 0 {
		for _, d := range w.order[:n] {
			delete(w.seen, d)
		}
		w.order = append([]string(nil), w.order[n:]...)
	}
	return live, bare
}

// maxBacklog bounds the candidates kept between cycles: past it the oldest
// go -- a flood of one-off names must not grow memory without end.
const maxBacklog = 1000

// requeue gives back the candidates a cycle had no room for, with the ports
// they were seen on. drain handed over everything seen and forgot it, and a
// cycle takes 20: the rest were dropped -- and a name requested once, as
// many are, was never probed. On 24.09 the queue overflowed 21 times, up
// to 181 names, 1,650 queued for 420 probed. They now go first next time,
// in the order they came. It says how many the bound dropped.
func (w *watcher) requeue(doms []string, ports map[string][]endpoint) int {
	if len(doms) == 0 {
		return 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	back := make(map[string]bool, len(doms))
	for _, d := range doms {
		back[d] = true
		if w.seen[d] == nil {
			w.seen[d] = map[endpoint]bool{}
		}
		for _, e := range ports[d] {
			w.seen[d][e] = true
		}
	}
	// a name seen again meanwhile keeps one place: the earlier one
	order := append([]string(nil), doms...)
	for _, d := range w.order {
		if !back[d] {
			order = append(order, d)
		}
	}
	dropped := 0
	if n := len(order) - maxBacklog; n > 0 {
		for _, d := range order[:n] {
			delete(w.seen, d)
		}
		order, dropped = order[n:], n
	}
	w.order = order
	return dropped
}
