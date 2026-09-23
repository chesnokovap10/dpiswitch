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
)

// GET /connections returns a snapshot of OPEN connections. A typical web
// request lives for seconds, so polling once per cycle misses almost
// everything: in one session 353 domains went through the core, yet only 31
// showed up in polls. So we look often and accumulate names, while probing
// still happens once per cycle.
type watcher struct {
	mu   sync.Mutex
	seen map[string]map[endpoint]bool
	// bare destination addresses of connections that carry no name -- see
	// state.touchIPs
	bare map[string]bool
}

func newWatcher(ctx context.Context, cfg Config, a *api) *watcher {
	w := &watcher{seen: map[string]map[endpoint]bool{}, bare: map[string]bool{}}
	go w.loop(ctx, cfg, a)
	return w
}

func (w *watcher) loop(ctx context.Context, cfg Config, a *api) {
	t := time.NewTicker(cfg.WatchInterval)
	defer t.Stop()
	var failed int
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		conns, err := a.connections()
		if err != nil {
			// the core may have restarted -- don't log on every iteration
			if failed++; failed%30 == 1 {
				log.Printf("watcher: cannot read connections: %v", err)
			}
			continue
		}
		failed = 0
		w.mu.Lock()
		for _, c := range conns {
			dom := c.domain()
			// a nameless connection from an application (not from the probe,
			// which dials from loopback through its own listeners)
			if dom == "" && c.Metadata.SourceIP != "127.0.0.1" && c.Metadata.DestinationIP != "" {
				w.bare[c.Metadata.DestinationIP] = true
			}
			// besides tunnelled ones, take those sent direct by our list:
			// this way hosts admitted by a family without their own verdict
			// get checked. Already decided ones are filtered by the state
			if dom == "" || !c.probeable() ||
				!(c.viaTunnel(cfg.ProxyName) || c.byProvider(cfg.Provider)) {
				continue
			}
			// the route is pinned to the second tunnel (preset or custom list):
			// a verdict would change nothing, probing is a waste. Without awg2
			// such connections go through awg and would otherwise land here
			if c.Rule == "RuleSet" && (strings.HasPrefix(c.RulePayload, "preset-") ||
				c.RulePayload == "awg2-hosts") {
				continue
			}
			if w.seen[dom] == nil {
				w.seen[dom] = map[endpoint]bool{}
			}
			w.seen[dom][endpoint{udp: c.isUDP(), port: c.port()}] = true
		}
		w.mu.Unlock()
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
// first, without duplicates.
func mergeEndpoints(now []endpoint, stored []string) []endpoint {
	seen := map[endpoint]bool{}
	var out []endpoint
	add := func(e endpoint) {
		if !seen[e] && len(out) < maxEndpoints {
			seen[e] = true
			out = append(out, e)
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
	return out
}

func endpointStrings(eps []endpoint) []string {
	out := make([]string, len(eps))
	for i, e := range eps {
		out[i] = e.String()
	}
	return out
}

// drainBare: the bare addresses accumulated since the last call.
func (w *watcher) drainBare() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]string, 0, len(w.bare))
	for ip := range w.bare {
		out = append(out, ip)
	}
	w.bare = map[string]bool{}
	return out
}

func (w *watcher) drain() map[string][]endpoint {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[string][]endpoint, len(w.seen))
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
	w.seen = map[string]map[endpoint]bool{}
	return out
}
