package ctl

import (
	"encoding/json"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"dpiswitch/internal/probe"
)

type entry struct {
	Verdict   probe.Verdict `json:"verdict"`
	Reason    string        `json:"reason,omitempty"`
	DecidedAt time.Time     `json:"decided_at"`
	ExpiresAt time.Time     `json:"expires_at"`
	TestedIP  string        `json:"tested_ip,omitempty"`
	// LastSeen: when this name last showed up in the core's connections,
	// whatever route it took. A verdict is only worth re-checking while
	// someone still goes there -- CDN node names live for hours and then
	// vanish, and re-probing them forever costs a slice of every cycle.
	LastSeen time.Time `json:"last_seen,omitempty"`
	// Endpoints: every port the name was seen on ("tcp/20000", "quic/443").
	// A re-check made when the name is not in the connections that minute
	// used to probe 443 alone -- and speedtest servers, which work on 20000
	// and have nothing on 443, could never be confirmed clean again.
	Endpoints []string `json:"endpoints,omitempty"`
	Reverts   int      `json:"reverts"` // how many times the domain has been reverted
	// DirectDown: an INCONCLUSIVE whose direct side failed on some TCP port,
	// and not the way the tunnel side did (see directDownOn) -- no proof of
	// blocking, but the host does not work direct. A family must not sweep
	// it direct.
	DirectDown bool `json:"direct_down,omitempty"`
}

// state is split per network: the key is the ISP (AS...), see asn.go;
// while the ISP is unknown -- the gateway, see networkID()
type state struct {
	mu       sync.Mutex
	path     string
	Networks map[string]map[string]*entry `json:"networks"`
	// gateway -> ISP behind it
	Attach map[string]attachment `json:"attach,omitempty"`
	// the network the controller currently works in: the UI reads it from here
	// instead of computing it -- it cannot without access to the direct path
	Current string `json:"current,omitempty"`
}

func loadState(path string) *state {
	s := &state{path: path, Networks: map[string]map[string]*entry{}}
	b, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	_ = json.Unmarshal(b, s)
	if s.Networks == nil {
		s.Networks = map[string]map[string]*entry{}
	}
	return s
}

func (s *state) save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path) // atomic: both the controller and humans read this file
}

func (s *state) attached(gw string) (attachment, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Attach[gw]
	return a, ok
}

func (s *state) attach(gw, asn string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Attach == nil {
		s.Attach = map[string]attachment{}
	}
	s.Attach[gw] = attachment{Net: asn, Checked: time.Now()}
}

func (s *state) setCurrent(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Current = id
}

// mergeInto folds everything accumulated under gateways that turned out to
// be behind this ISP into the ISP's memory. Of two verdicts for a domain the
// newer wins. The old per-gateway records are removed: one ISP, one memory.
func (s *state) mergeInto(asn string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Networks[asn] == nil {
		s.Networks[asn] = map[string]*entry{}
	}
	dst := s.Networks[asn]
	n := 0
	for gw, a := range s.Attach {
		if a.Net != asn {
			continue
		}
		for dom, e := range s.Networks[gw] {
			if old, ok := dst[dom]; !ok || e.DecidedAt.After(old.DecidedAt) {
				dst[dom] = e
				n++
			}
		}
		delete(s.Networks, gw)
	}
	return n
}

func (s *state) net(id string) map[string]*entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Networks[id] == nil {
		s.Networks[id] = map[string]*entry{}
	}
	return s.Networks[id]
}

func (s *state) get(id, dom string) (*entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.Networks[id][dom]
	return e, ok
}

func (s *state) put(id, dom string, e *entry) {
	m := s.net(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	m[dom] = e
}

// domains currently allowed to go direct
func (s *state) verified(id string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	now := time.Now()
	for dom, e := range s.Networks[id] {
		if _, addr := probe.AddrKey(dom); addr {
			continue // goes to the address list, see verifiedIPs
		}
		if e.Verdict == probe.Clean && now.Before(e.ExpiresAt) {
			out = append(out, dom)
		}
	}
	sort.Strings(out)
	return out
}

// verifiedIPs: the node each CLEAN name was probed on, as /32 or /128.
//
// Some clients take a server list with addresses from their own service and
// connect to the bare IP: the speedtest client does, on port 20000, with a
// protocol that is neither TLS nor HTTP, so no name can be recovered and the
// name rules never match -- a verified server went through the tunnel at
// 126 Mbit/s instead of 700. Only the address the probe itself reached
// directly is listed, and the rule using it carries no-resolve, so a
// connection that has a name is still decided by the name.
func (s *state) verifiedIPs(id string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	seen := map[string]bool{}
	var out []string
	for _, e := range s.Networks[id] {
		if e.Verdict != probe.Clean || !now.Before(e.ExpiresAt) {
			continue
		}
		ip := net.ParseIP(e.TestedIP)
		if ip == nil {
			continue
		}
		cidr := ip.String() + "/128"
		if ip.To4() != nil {
			cidr = ip.String() + "/32"
		}
		if !seen[cidr] {
			seen[cidr] = true
			out = append(out, cidr)
		}
	}
	sort.Strings(out)
	return out
}

// touch marks names seen in the core's connections right now.
func (s *state) touch(id string, doms []string) {
	m := s.net(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, d := range doms {
		if e, ok := m[d]; ok {
			e.LastSeen = now
		}
	}
}

// touchIPs marks as seen the names whose probed node is one of these bare
// addresses. A client that takes a server list with addresses (the speedtest
// client, dialling IPs on port 20000) never produces a name, so without this
// its servers looked abandoned: an expired verdict was never re-checked and
// the server stayed in the tunnel for good.
func (s *state) touchIPs(id string, ips []string) int {
	if len(ips) == 0 {
		return 0
	}
	set := make(map[string]bool, len(ips))
	for _, ip := range ips {
		if p := net.ParseIP(ip); p != nil {
			set[p.String()] = true
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	n := 0
	for _, e := range s.Networks[id] {
		if p := net.ParseIP(e.TestedIP); p != nil && set[p.String()] {
			e.LastSeen = now
			n++
		}
	}
	return n
}

// forget drops names nothing has gone to for longer than idle. Without it
// memory only grows: two thirds of the names a busy day leaves behind are
// one-off CDN nodes that will never be requested again.
func (s *state) forget(id string, idle time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := time.Now().Add(-idle)
	n := 0
	for dom, e := range s.Networks[id] {
		if e.lastSeen().Before(cut) {
			delete(s.Networks[id], dom)
			n++
		}
	}
	return n
}

// quicOnly: CLEAN names still in use whose TCP was never probed on a port
// they were only seen on over QUIC. Verdicts made before withTCP existed go
// direct on TCP unchecked; they are re-checked now instead of when their
// term runs out, a week later.
func (s *state) quicOnly(id string, idle time.Duration) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	now := time.Now()
	for dom, e := range s.Networks[id] {
		if e.Verdict != probe.Clean || !now.Before(e.ExpiresAt) || !e.lastSeen().After(now.Add(-idle)) {
			continue
		}
		var eps []endpoint
		for _, x := range e.Endpoints {
			if ep, ok := parseEndpoint(x); ok {
				eps = append(eps, ep)
			}
		}
		if len(withTCP(eps)) > len(eps) {
			out = append(out, dom)
		}
	}
	sort.Strings(out)
	return out
}

// drop removes the verdicts of the names that match.
func (s *state) drop(id string, match func(dom string) bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for dom := range s.Networks[id] {
		if match(dom) {
			delete(s.Networks[id], dom)
			n++
		}
	}
	return n
}

// lastSeen falls back to the decision time for entries written before the
// field existed, so an old one is not mistaken for freshly used.
func (e *entry) lastSeen() time.Time {
	if e.LastSeen.IsZero() {
		return e.DecidedAt
	}
	return e.LastSeen
}

// candidates for re-checking: the verdict has expired AND the name is still
// in use. An expired verdict for a name nobody requests any more is left
// alone -- when traffic to it appears, the ordinary candidate picking takes
// it up the same minute.
func (s *state) expired(id string, idle time.Duration) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	now := time.Now()
	fresh := now.Add(-idle)
	for dom, e := range s.Networks[id] {
		if now.After(e.ExpiresAt) && e.lastSeen().After(fresh) {
			out = append(out, dom)
		}
	}
	sort.Strings(out)
	return out
}
