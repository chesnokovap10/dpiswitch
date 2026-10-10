package ctl

import (
	"dpiswitch/internal/paths"

	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
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
	// Streak: checks in a row that found this same verdict other than CLEAN,
	// or measured and could not overturn it. Each doubles the wait before
	// the next one, see failTerm.
	Streak int `json:"streak,omitempty"`
	// SlowOnce: a CLEAN measured slower once. It is kept and looked at again
	// after FailTTL; SLOWER a second time in a row reverts it.
	SlowOnce bool `json:"slow_once,omitempty"`
	// Alone: made with no first tunnel to measure against (see
	// probe.CheckAlone). A CLEAN made so sends nothing direct -- with no
	// tunnel everything goes direct anyway, and once there is one it is
	// checked first, against it.
	Alone bool `json:"alone,omitempty"`
	// NoQUIC: a CLEAN_SPLIT whose QUIC on 443 was blocked and the decoy did
	// not get it through (or was not tried): its QUIC is refused, see
	// splitNoQUIC
	NoQUIC bool `json:"no_quic,omitempty"`
	// NoTCP: a CLEAN_SPLIT that goes direct over QUIC alone -- its TCP on
	// 443 blocked even with the cut, refused; see splitNoTCP
	NoTCP bool `json:"no_tcp,omitempty"`
	// V6: the check looked for the name's IPv6 node too (see probeBatch). One
	// going direct without it was judged by its IPv4 node alone, see unseenV6
	V6 bool `json:"v6,omitempty"`
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
	// V6: what probes have shown of IPv6 on each network's direct path
	V6 map[string]*v6Memo `json:"v6,omitempty"`
	// Pending: names whose verdict was dropped from the UI, by network, and
	// when -- not checked yet, so a CDN family counts them as not passed
	// (see familyWays): dropping 38 blocked shards of a family in the
	// tunnel left 32 direct of 40, and the family went direct onto the
	// blocked ones (09.10)
	Pending map[string]map[string]time.Time `json:"pending,omitempty"`
	// Parked: verdicts set aside, by network, while a list or a skip holds
	// their name (see park). They were dropped: a preset switched on and
	// off again cost YouTube its 155 verdicts, and www.youtube.com went
	// through the tunnel for a minute and a half until checked anew (09.10)
	Parked map[string]map[string]*entry `json:"parked,omitempty"`
	// resets: how many times the verdicts were reset, see resetEpoch
	resets int
	// lookupFailed: when the ISP behind a gateway last could not be looked
	// up, see lookupBackoff; not kept across starts
	lookupFailed map[string]time.Time
	// ipFailed: when the public address behind a gateway last could not be
	// checked, see ipBackoff; not kept across starts
	ipFailed map[string]time.Time
}

type v6Memo struct {
	// Misses: names in a row whose IPv6 node the direct path did not reach
	Misses int `json:"misses,omitempty"`
	// NoneUntil: until then the direct path is taken to have no IPv6
	NoneUntil time.Time `json:"none_until,omitempty"`
}

const (
	v6Misses = 3              // misses in a row that make "no IPv6 here"
	v6Hold   = 24 * time.Hour // how long that holds before probes look again
)

func loadState(path string) *state {
	s := &state{path: path, Networks: map[string]map[string]*entry{}}
	b, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	if err := json.Unmarshal(b, s); err != nil {
		// an unreadable memory used to be dropped in silence, and the next
		// save wrote the empty one over the only copy of every verdict:
		// it is set aside for a person to look at
		bad := path + ".bad"
		_ = os.Remove(bad)
		if rerr := os.Rename(path, bad); rerr != nil {
			log.Printf("state %s unreadable (%v) and not set aside: %v", path, err, rerr)
		} else {
			log.Printf("state %s unreadable (%v): kept as %s, starting with an empty memory", path, err, bad)
		}
		s = &state{path: path}
	}
	if s.Networks == nil {
		s.Networks = map[string]map[string]*entry{}
	}
	// what a start offline filed under no network at all (see noNetwork)
	delete(s.Networks, noNetwork)
	delete(s.V6, noNetwork)
	if s.Current == noNetwork {
		s.Current = ""
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
	// atomic: both the controller and humans read this file -- the UI and
	// the tray every few seconds, which on Windows fails a plain rename
	return paths.ReplaceFile(s.path, b)
}

func (s *state) attached(gw string) (attachment, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Attach[gw]
	return a, ok
}

func (s *state) attach(gw, asn, ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Attach == nil {
		s.Attach = map[string]attachment{}
	}
	now := time.Now()
	s.Attach[gw] = attachment{Net: asn, Checked: now, IP: ip, IPChecked: now}
}

// staleIP: the public address behind gw was found changed; the next
// resolveNetwork looks at it again at once.
func (s *state) staleIP(gw string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.Attach[gw]; ok {
		a.IPChecked = time.Time{}
		s.Attach[gw] = a
	}
}

// sawIP: the public address behind gw was found the same again.
func (s *state) sawIP(gw string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.Attach[gw]; ok {
		a.IPChecked = time.Now()
		s.Attach[gw] = a
	}
}

func (s *state) current() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Current
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
		// what was set aside and dropped by hand under the gateway goes
		// with it: left there, nothing ever read or removed it again
		for dom, e := range s.Parked[gw] {
			if s.Parked[asn] == nil {
				s.Parked[asn] = map[string]*entry{}
			}
			if _, ok := s.Parked[asn][dom]; !ok {
				s.Parked[asn][dom] = e
			}
		}
		delete(s.Parked, gw)
		for dom, at := range s.Pending[gw] {
			if s.Pending[asn] == nil {
				s.Pending[asn] = map[string]time.Time{}
			}
			if at.After(s.Pending[asn][dom]) {
				s.Pending[asn][dom] = at
			}
		}
		delete(s.Pending, gw)
		// and what the probes showed of IPv6 there: the ISP's own stands
		if m, ok := s.V6[gw]; ok {
			if s.V6[asn] == nil {
				s.V6[asn] = m
			}
			delete(s.V6, gw)
		}
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

// get: a copy of the name's verdict as it stands. The one memory holds is
// written under mu -- touch marks it seen, new settings move its term --
// while a probe of the fast lane reads what it got here with no lock held.
func (s *state) get(id, dom string) (*entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.Networks[id][dom]
	if !ok || e == nil {
		return nil, false
	}
	c := *e
	return &c, true
}

func (s *state) put(id, dom string, e *entry) {
	m := s.net(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	m[dom] = e
	delete(s.Pending[id], dom)
}

// domains currently allowed to go direct
func (s *state) verified(id string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	now := time.Now()
	for dom, e := range s.Networks[id] {
		if _, addr := probe.AddrKey(dom); addr {
			continue // goes to the address list, see verifiedAddrs
		}
		if e.Verdict == probe.Clean && !e.Alone && now.Before(e.ExpiresAt) {
			out = append(out, dom)
		}
	}
	sort.Strings(out)
	return out
}

// madeAlone: the verdicts made with no tunnel, of names still in use -- to
// be checked again now that there is one
func (s *state) madeAlone(id string, idle time.Duration) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	fresh := time.Now().Add(-idle)
	for dom, e := range s.Networks[id] {
		if e.Alone && e.lastSeen().After(fresh) {
			out = append(out, dom)
		}
	}
	sort.Strings(out)
	return out
}

// verifiedSplit: the names that go direct with the ClientHello cut. A bare
// address has no name to cut.
func (s *state) verifiedSplit(id string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	now := time.Now()
	for dom, e := range s.Networks[id] {
		if _, addr := probe.AddrKey(dom); addr {
			continue
		}
		if e.Verdict == probe.CleanSplit && now.Before(e.ExpiresAt) {
			out = append(out, dom)
		}
	}
	sort.Strings(out)
	return out
}

// verifiedSplitNoTCP: of the cut's names, the ones whose TCP on 443 is
// refused, see entry.NoTCP
func (s *state) verifiedSplitNoTCP(id string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	now := time.Now()
	for dom, e := range s.Networks[id] {
		if _, addr := probe.AddrKey(dom); addr {
			continue
		}
		if e.Verdict == probe.CleanSplit && e.NoTCP && now.Before(e.ExpiresAt) {
			out = append(out, dom)
		}
	}
	sort.Strings(out)
	return out
}

// verifiedSplitNoQUIC: of the cut's names, the ones whose QUIC is refused,
// see entry.NoQUIC
func (s *state) verifiedSplitNoQUIC(id string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	now := time.Now()
	for dom, e := range s.Networks[id] {
		if _, addr := probe.AddrKey(dom); addr {
			continue
		}
		if e.Verdict == probe.CleanSplit && e.NoQUIC && now.Before(e.ExpiresAt) {
			out = append(out, dom)
		}
	}
	sort.Strings(out)
	return out
}

// verifiedAddrs: rules for connections that carry no name at all, one per
// node a CLEAN verdict was probed on, limited to what the probe really showed.
//
// Some clients take a server list with addresses from their own service and
// connect to the bare IP: the speedtest client does, on port 20000, with a
// protocol that is neither TLS nor HTTP, so no name can be recovered and the
// name rules never match -- a verified server went through the tunnel at
// 126 Mbit/s instead of 700.
//
// A bare /32 used to send everything nameless to that node direct: any port,
// UDP, and 443 too. But a name's 443 is probed as TLS with that name and its
// 80 as HTTP with that Host -- neither says anything about other traffic to
// the node, and a plain connect to one port says nothing about another (a
// Telegram DC reached on 80 would take MTProto on 443 along). So a rule holds
// the TCP ports probed by plain connect only, and fires only for a connection
// without a name: an HTTP one keeps its address beside the sniffed Host, and
// another name on a shared CDN node must not ride on this one's verdict.
func (s *state) verifiedAddrs(id string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	ports := map[string]map[int]bool{}
	for dom, e := range s.Networks[id] {
		if e.Verdict != probe.Clean || !now.Before(e.ExpiresAt) {
			continue
		}
		ip := net.ParseIP(e.TestedIP)
		if ip == nil {
			continue
		}
		_, bare := probe.AddrKey(dom)
		for _, x := range e.Endpoints {
			ep, ok := parseEndpoint(x)
			if !ok || ep.udp || (!bare && (ep.port == 443 || ep.port == 80)) {
				continue
			}
			if ports[ip.String()] == nil {
				ports[ip.String()] = map[int]bool{}
			}
			ports[ip.String()][ep.port] = true
		}
	}
	out := make([]string, 0, len(ports))
	for ip, ps := range ports {
		out = append(out, addrRule(net.ParseIP(ip), ps))
	}
	sort.Strings(out)
	return out
}

// onNode: the CLEAN verdicts an address rule for this node and TCP port
// comes from -- a bare address's own, and those of names probed there.
func (s *state) onNode(id, ip string, port int) []string {
	node := net.ParseIP(ip)
	if node == nil {
		return nil
	}
	want := endpoint{port: port}.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for dom, e := range s.Networks[id] {
		if e.Verdict != probe.Clean || !node.Equal(net.ParseIP(e.TestedIP)) {
			continue
		}
		for _, x := range e.Endpoints {
			if x == want {
				out = append(out, dom)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// cleanAddrs: bare addresses whose own CLEAN verdict holds -- they go direct
// by the address rules, the name list never shows them.
func (s *state) cleanAddrs(id string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	now := time.Now()
	for dom, e := range s.Networks[id] {
		if _, bare := probe.AddrKey(dom); bare && e.Verdict == probe.Clean && now.Before(e.ExpiresAt) {
			out = append(out, dom)
		}
	}
	sort.Strings(out)
	return out
}

// addrRule: TCP to these ports of this node, from a connection with no name.
func addrRule(ip net.IP, ports map[int]bool) string {
	list := make([]int, 0, len(ports))
	for p := range ports {
		list = append(list, p)
	}
	sort.Ints(list)
	ps := make([]string, len(list))
	for i, p := range list {
		ps[i] = strconv.Itoa(p)
	}
	kind, cidr := "IP-CIDR", ip.String()+"/32"
	if ip.To4() == nil {
		kind, cidr = "IP-CIDR6", ip.String()+"/128"
	}
	// DOMAIN-REGEX matches the sniffed name or the host: "." fails on an empty one
	return fmt.Sprintf("AND,((NETWORK,TCP),(DST-PORT,%s),(%s,%s,no-resolve),(NOT,((DOMAIN-REGEX,.))))",
		strings.Join(ps, "/"), kind, cidr)
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
	// a name held by a list is not touched: what was set aside ages from
	// its last use before
	for dom, e := range s.Parked[id] {
		if e.lastSeen().Before(cut) {
			delete(s.Parked[id], dom)
		}
	}
	// a name dropped by hand counts for pendingTerm, see familyWays
	for dom, at := range s.Pending[id] {
		if time.Since(at) >= pendingTerm {
			delete(s.Pending[id], dom)
		}
	}
	if len(s.Pending[id]) == 0 {
		delete(s.Pending, id)
	}
	return n
}

// staleNetwork: how long another network may go unused before its memory is
// dropped whole. forget goes by the network the machine is on, name by
// name; the others' names are never used there, and an ISP met once -- a
// hotel's, a phone's -- kept its verdicts for good. A month: a fortnight
// away does not cost the home network its memory.
const staleNetwork = 30 * 24 * time.Hour

// dropStale drops the networks other than current whose names were all last
// used before term, and says how many networks and names went.
func (s *state) dropStale(current string, term time.Duration) (nets, names int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := time.Now().Add(-term)
	for id, m := range s.Networks {
		if id == current {
			continue
		}
		used := false
		for _, e := range m {
			if e.lastSeen().After(cut) {
				used = true
				break
			}
		}
		if used {
			continue
		}
		nets, names = nets+1, names+len(m)
		delete(s.Networks, id)
		delete(s.V6, id)
		delete(s.Parked, id)
		delete(s.Pending, id)
	}
	return nets, names
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

// unseenV6: names going direct and still in use whose check never looked at
// their IPv6 node -- made before it did, or while the direct path had no
// IPv6. They are checked now, not when their term runs out a week later: the
// core dials either node, and one cut on IPv6 alone breaks whenever that
// node answers first.
func (s *state) unseenV6(id string, idle time.Duration) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	now := time.Now()
	for dom, e := range s.Networks[id] {
		if e.V6 || e.Alone || !goesDirect(e.Verdict) || !now.Before(e.ExpiresAt) || !e.lastSeen().After(now.Add(-idle)) {
			continue
		}
		if _, addr := probe.AddrKey(dom); !addr {
			out = append(out, dom)
		}
	}
	sort.Strings(out)
	return out
}

// directNoV6: whether this network's direct path is known to have no IPv6.
func (s *state) directNoV6(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.V6[id]
	return m != nil && time.Now().Before(m.NoneUntil)
}

// learnV6 takes what a cycle showed of IPv6 on the direct path: misses --
// names whose IPv6 node it did not reach, reached -- whether it reached one.
// On a network with no IPv6 every IPv6-only name was probed hourly only to
// fail direct again; after v6Misses of them in a row such nodes are not
// probed for v6Hold. It returns when that holds until, if it starts now.
//
// A host blocked by name on a network that does have IPv6 counts as a miss
// too -- judgeNode cannot tell the two apart. The cost is a detour: an
// IPv6-only name stays in the tunnel for the day.
func (s *state) learnV6(id string, misses int, reached bool) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.V6 == nil {
		s.V6 = map[string]*v6Memo{}
	}
	m := s.V6[id]
	if m == nil {
		m = &v6Memo{}
		s.V6[id] = m
	}
	switch {
	case reached:
		*m = v6Memo{}
		return time.Time{}, false
	case misses == 0 || time.Now().Before(m.NoneUntil):
		return time.Time{}, false
	}
	m.Misses += misses
	if m.Misses < v6Misses {
		return time.Time{}, false
	}
	m.Misses = 0
	m.NoneUntil = time.Now().Add(v6Hold)
	return m.NoneUntil, true
}

// resetVerdicts drops every verdict of one network: the one the verdicts
// page shows, the current one from the tray. It dropped those of every
// network, the ones kept for a network the machine is not on among them.
// What memory knows of the network itself -- which ISP is behind which
// gateway, IPv6 on the direct path -- is not a verdict and stays.
func (s *state) resetVerdicts(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.Networks[id])
	if s.Networks[id] != nil {
		s.Networks[id] = map[string]*entry{}
	}
	delete(s.Parked, id)
	// nor is a name dropped by hand before the reset still waiting for its
	// check: it counted against its CDN family for an hour after
	delete(s.Pending, id)
	s.resets++
	return n
}

// forgetVerdicts drops the verdicts of the names given, in one network:
// "name" alone, "+.name" the name and every name under it (a family),
// "@address" an address's own. It moves the epoch as a reset does: a cycle
// running would file a dropped name's verdict back.
func (s *state) forgetVerdicts(id string, keys []string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	now := time.Now()
	drop := func(dom string) {
		delete(s.Networks[id], dom)
		delete(s.Parked[id], dom)
		if s.Pending == nil {
			s.Pending = map[string]map[string]time.Time{}
		}
		if s.Pending[id] == nil {
			s.Pending[id] = map[string]time.Time{}
		}
		s.Pending[id][dom] = now
		n++
	}
	for _, k := range keys {
		if base, ok := strings.CutPrefix(k, "+."); ok {
			for dom := range s.Networks[id] {
				if dom == base || strings.HasSuffix(dom, "."+base) {
					drop(dom)
				}
			}
			for dom := range s.Parked[id] {
				if dom == base || strings.HasSuffix(dom, "."+base) {
					delete(s.Parked[id], dom)
				}
			}
			continue
		}
		delete(s.Parked[id], k)
		if _, ok := s.Networks[id][k]; ok {
			drop(k)
		}
	}
	s.resets++
	return n
}

// resetEpoch: changes with every reset. A cycle notes it before its probes,
// and files nothing if it changed meanwhile: probes started before a reset
// used to put their verdicts back into the memory it had just emptied.
func (s *state) resetEpoch() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resets
}

// park sets aside the verdicts of the names that match: out of the lists,
// the families and the re-checks, as dropped ones were, and back by unpark
// once nothing holds the name.
func (s *state) park(id string, match func(dom string) bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for dom, e := range s.Networks[id] {
		if match(dom) {
			if s.Parked == nil {
				s.Parked = map[string]map[string]*entry{}
			}
			if s.Parked[id] == nil {
				s.Parked[id] = map[string]*entry{}
			}
			s.Parked[id][dom] = e
			delete(s.Networks[id], dom)
			n++
		}
	}
	return n
}

// unpark puts back the verdicts set aside whose name nothing holds now. A
// verdict made meanwhile wins; one expired is re-checked as any other.
func (s *state) unpark(id string, held func(dom string) bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for dom, e := range s.Parked[id] {
		if held(dom) {
			continue
		}
		delete(s.Parked[id], dom)
		if _, ok := s.Networks[id][dom]; ok {
			continue
		}
		if s.Networks == nil {
			s.Networks = map[string]map[string]*entry{}
		}
		if s.Networks[id] == nil {
			s.Networks[id] = map[string]*entry{}
		}
		s.Networks[id][dom] = e
		n++
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
