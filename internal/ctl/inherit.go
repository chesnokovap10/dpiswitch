package ctl

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dpiswitch/internal/paths"
	"dpiswitch/internal/probe"
)

// Inheritance: a name with no verdict of its own goes the way its relatives
// go, not into the tunnel.
//
// A service hands out media links signed for the address its page came
// from, and serves them from hosts of their own -- a YouTube Music track
// from rrN---sn-....googlevideo.com, a new one for every track. The page,
// verified, went direct; each new media host, with no verdict yet, went
// through the tunnel, and the service saw another address: on 07.10 every
// videoplayback through it got a 31-byte SABR error, 403, and the player
// asked again every 10 s until the detector found the host clean -- 30 to
// 60 s of silence on every track. In observe only, where all goes one way,
// it never happened.
//
// The relatives are the same domain (its eTLD+1, as a family is) or the
// same network owning the node -- googlevideo.com and youtube.com share no
// domain, but both live in AS15169. A group lends its way only when it is
// clearly direct here: at least minInherit of its names go direct, and at
// least 3 of every 4 that went one way or the other. The way lent is the
// ClientHello cut: it carries a name blocked by its name as well as a clean
// one, the way observe only carries everything. A name with a verdict that
// does not go direct is held out (HoldProvider), so the rule only ever
// decides for a name with none: its own check follows as before, and a
// direct connection that brings nothing is checked at once (suspectDirect).
//
// A CDN host of a family going direct (cdnfam.go) blocked on both direct
// ways is refused (RefuseProvider), not sent through the tunnel: through
// the tunnel it gets the 403 above, and the player waits on it; refused, it
// takes another host in under a second (08.10). Nothing else is refused: a
// site the cut does not get through goes through the tunnel, however its
// domain goes.
//
// On only, with the cut and families switched on; the networks are learnt
// from RIPE, a few nodes a cycle (see asnBook).

const (
	HoldProvider      = "detector-hold"
	RefuseProvider    = "inherit-refuse"
	InheritProvider   = "inherit"
	InheritIPProvider = "inherit-ip"
)

const (
	minInherit = 3
	// at least inheritNum of every inheritDen names that went one way or the
	// other go direct
	inheritNum, inheritDen = 3, 4
)

// inherited: the connection went direct by inheritance, by the name's
// domain or by its address's network, or by its CDN family (cdnfam.go) --
// a way lent, not the name's own verdict. The network's rule is an AND,
// its payload in the core's own words: "((DomainRegex,.+) &&
// (RuleSet,inherit-ip))". The family's was left out at first, and a new
// CDN host of a family going direct was never taken for a check: blocked,
// it hung instead of being refused (09.10).
func (c connection) inherited() bool {
	return c.byProvider(InheritProvider) || c.byProvider(FamilyDirectProvider) ||
		c.Rule == "AND" && strings.Contains(c.RulePayload, "RuleSet,"+InheritIPProvider+")")
}

// inheritOn: whether the inheritance lists hold anything -- in On, with the
// cut and families switched on and a first tunnel to measure against
func inheritOn(cfg Config) bool {
	on := cfg.Apply
	if cfg.mode != nil {
		on = cfg.modeNow() == ModeOn
	}
	return on && !cfg.off() && cfg.cutNow().split && cfg.Families && !cfg.alone
}

// lean: which way a verdict points for its groups. A verdict going direct
// counts direct; one that does not, against -- an INCONCLUSIVE only when
// the direct path failed (as badForFamily); a CLEAN past its term, neither.
func lean(e *entry, now time.Time) (direct, against bool) {
	switch {
	case goesDirect(e.Verdict):
		return now.Before(e.ExpiresAt) && !e.Alone, false
	case e.Verdict == probe.Inconcl:
		return false, e.DirectDown
	}
	return false, true
}

// group: the count of one group's names, see lean
type group struct{ direct, against int }

func (g group) lends() bool {
	return g.direct >= minInherit && g.direct*inheritDen >= (g.direct+g.against)*inheritNum
}

// inheritance: what the three lists hold for this network -- the families
// and networks whose way a name with no verdict takes, the address ranges
// of those networks, the names held out -- plus the networks lending their
// way whose ranges are not known yet. fams are the plain families: direct
// already, above all of this.
type inheritance struct {
	families []string // "+.googlevideo.com"
	asns     []string // "AS15169", lending, ranges known or not
	ranges   []string
	hold     []string
	missing  []string // lending networks whose ranges the book lacks
}

// refusable: a verdict saying neither direct way gets through -- the cut
// tried and failed, or the connection itself cut. A BLOCKED_TLS with the
// cut on is one whose cut proved nothing (the tunnel silent); BLOCKED_QUIC
// leaves TCP; CONTENT_DIFF and INCONCLUSIVE say too little to refuse by.
func refusable(v probe.Verdict) bool {
	return v == probe.BlockedDPI || v == probe.BlockedTCP
}

func (s *state) inheritance(id string, book *asnBook, fams []family) inheritance {
	plain := map[string]bool{}
	for _, f := range fams {
		plain[f.Domain] = true
	}
	byFam := map[string]*group{}
	byASN := map[string]*group{}
	var hold []string
	now := time.Now()
	add := func(m map[string]*group, k string, d, a bool) {
		if k == "" || !d && !a {
			return
		}
		g := m[k]
		if g == nil {
			g = &group{}
			m[k] = g
		}
		if d {
			g.direct++
		} else {
			g.against++
		}
	}
	s.mu.Lock()
	for dom, e := range s.Networks[id] {
		if _, addr := probe.AddrKey(dom); addr {
			continue
		}
		d, a := lean(e, now)
		// A CLEAN or CLEAN_SPLIT that does not go direct is past its term:
		// held out like any other, it waits for its re-check in the tunnel
		// as before. An INCONCLUSIVE whose direct side worked and whose
		// tunnel did not answer is not: the check said nothing against the
		// direct way, and the name goes its relatives' way like one with no
		// verdict.
		if !d && !(e.Verdict == probe.Inconcl && probe.TunnelDown(e.Reason)) {
			hold = append(hold, dom)
		}
		add(byFam, familyOf(dom), d, a)
		add(byASN, book.asnOf(e.TestedIP), d, a)
	}
	s.mu.Unlock()
	var out inheritance
	for f, g := range byFam {
		if g.lends() && !plain[f] {
			out.families = append(out.families, "+."+f)
		}
	}
	for asn, g := range byASN {
		if !g.lends() {
			continue
		}
		out.asns = append(out.asns, asn)
		r, ok := book.ranges(asn)
		if !ok {
			out.missing = append(out.missing, asn)
		}
		out.ranges = append(out.ranges, r...)
	}
	sort.Strings(out.families)
	sort.Strings(out.asns)
	sort.Strings(out.missing)
	sort.Strings(hold)
	out.hold = hold
	// the ranges as the file holds them: sorted, once each
	out.ranges = dedupe(out.ranges)
	sort.Strings(out.ranges)
	return out
}

// writeInherit brings the three lists in line with memory, or empties them
// with inheritance off; listMu held. Unless forced it writes a list only
// when it differs from the file. The held names go first: a name newly
// blocked must be out before the rules that would lend it a way change; the
// refused ones before them, a name refused before it is held.
func writeInherit(cfg Config, a *api, st *state, netID string, fams []family, force bool) error {
	if cfg.InheritPath == "" {
		return nil
	}
	var in inheritance
	var ways []familyWay
	var famDirect, famTunnel, refuse []string
	was := map[string]bool{}
	on := inheritOn(cfg) && netID != "" && netID != noNetwork
	if on {
		in = st.inheritance(netID, cfg.book, fams)
		cfg.book.want(in.missing)
		for _, r := range listRules(cfg.FamilyDirectPath) {
			was[strings.TrimPrefix(r, "+.")] = true
		}
		ways = st.familyWays(netID, cfg.cdns, was)
		for _, w := range ways {
			if w.direct {
				famDirect = append(famDirect, w.f.rules()...)
				refuse = append(refuse, w.refuse...)
			} else if !w.undecided {
				famTunnel = append(famTunnel, w.f.rules()...)
			}
		}
		refuse = dedupe(refuse)
		sort.Strings(refuse)
	}
	lists := []struct {
		path, provider, what string
		rules                []string
	}{
		{cfg.FamilyTunnelPath, FamilyTunnelProvider, "CDN families going the tunnel's way here, page and CDN together", famTunnel},
		{cfg.RefusePath, RefuseProvider, "CDN hosts of a family going direct, blocked on both direct ways: refused", refuse},
		{cfg.HoldPath, HoldProvider, "names with a verdict that does not go direct: held out of inheritance", in.hold},
		{cfg.FamilyDirectPath, FamilyDirectProvider, "CDN families going direct here, page and CDN together", famDirect},
		{cfg.InheritPath, InheritProvider, "domains whose names go direct here: a name with no verdict goes their way", in.families},
		{cfg.InheritIPPath, InheritIPProvider, "address ranges of networks whose names go direct here: " + strings.Join(in.asns, ", "), in.ranges},
	}
	changed := false
	for _, l := range lists {
		if l.path == "" || !force && slices.Equal(listRules(l.path), l.rules) {
			continue
		}
		var b strings.Builder
		b.WriteString("# generated by the controller, do not edit\n")
		if on {
			fmt.Fprintf(&b, "# network %s, updated %s\n", netID, time.Now().Format(time.RFC3339))
			b.WriteString("# " + l.what + "\n")
		} else {
			b.WriteString("# inheritance off\n")
		}
		for _, r := range l.rules {
			b.WriteString(r + "\n")
		}
		if err := replaceList(a, l.path, l.provider, b.String()); err != nil {
			return err
		}
		if (l.provider == FamilyDirectProvider || l.provider == FamilyTunnelProvider) && on {
			for _, w := range ways {
				log.Printf("applied: CDN family %s", w)
			}
		}
		if l.provider == RefuseProvider && on {
			log.Printf("applied: %d CDN hosts blocked on both direct ways, their family direct, refused (%s)",
				len(refuse), preview(refuse))
		}
		changed = changed || l.provider != HoldProvider && l.provider != RefuseProvider
	}
	if on {
		for _, w := range ways {
			if w.direct != was[w.f.CDN] {
				if n := closeFamily(a, w); n > 0 {
					log.Printf("closed %d connections of CDN family %s going the old way", n, w.f.CDN)
				}
			}
		}
	}
	if changed && on {
		var by []string
		if len(in.families) > 0 {
			by = append(by, fmt.Sprintf("%d domains (%s)", len(in.families), preview(in.families)))
		}
		if len(in.asns) > 0 {
			by = append(by, fmt.Sprintf("%d networks (%s; %d ranges)", len(in.asns), strings.Join(in.asns, ", "), len(in.ranges)))
		}
		if len(by) == 0 {
			by = []string{"none lends its way yet"}
		}
		log.Printf("applied: a name with no verdict takes its relatives' way -- %s", strings.Join(by, ", "))
	}
	return nil
}

// asnBook: which network owns the nodes the detector probed, and the
// address ranges of the networks lending their way. From RIPE, as the ISP
// is: a node's network by its address, a network's ranges by what it
// announces. Kept in a file of its own: a network's ranges are a few
// hundred lines, the same for every network the machine is in.
type asnBook struct {
	mu   sync.Mutex
	path string
	// Nets: the announced prefix each looked-up node lies in, with its
	// network -- the next node in the same prefix needs no lookup
	Nets []asnNet `json:"nets"`
	// ASNs: the ranges of the networks wanted so far
	ASNs map[string]*asnRanges `json:"asns"`
	// what has not been looked up yet: nodes, and networks whose ranges
	// are wanted; and when a lookup last failed
	queue  []string
	wanted map[string]bool
	failed map[string]time.Time
	busy   atomic.Bool
	parsed map[string]netip.Prefix
}

type asnNet struct {
	Prefix string    `json:"prefix"`
	ASN    string    `json:"asn"`
	At     time.Time `json:"at"`
}

type asnRanges struct {
	Prefixes []string  `json:"prefixes"`
	At       time.Time `json:"at"`
	// the lookup failed: tried again after asnRetry, not asnRangesTerm
	Failed bool `json:"failed,omitempty"`
}

const (
	// a node's network is looked up again after this
	asnNetTerm = 30 * 24 * time.Hour
	// a network's ranges, after this -- an announcement changes now and then
	asnRangesTerm = 24 * time.Hour
	// a lookup that failed waits this long
	asnRetry = 10 * time.Minute
	// networks whose ranges are looked up per round
	asnPerRound = 20
	// nodes looked up per round, and at once: RIPE answers one in a
	// fraction of a second
	asnNodesPerRound = 1000
	asnWorkers       = 8
	asnRangeWorkers  = 4
	// a network announcing more than this is a cloud of unrelated tenants
	// rather than one service's: AS15169 announces ~1,400
	maxASNRanges = 5000
)

func loadASNBook(path string) *asnBook {
	b := &asnBook{path: path, ASNs: map[string]*asnRanges{}}
	if raw, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(raw, b); err != nil {
			log.Printf("network book %s unreadable, starting anew: %v", path, err)
			b.Nets, b.ASNs = nil, map[string]*asnRanges{}
		}
	}
	if b.ASNs == nil {
		b.ASNs = map[string]*asnRanges{}
	}
	return b
}

// asnOf: the network owning ip, if the book knows it; nil-safe
func (b *asnBook) asnOf(ip string) string {
	if b == nil || ip == "" {
		return ""
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	a = a.Unmap()
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	for _, n := range b.Nets {
		p, ok := b.prefix(n.Prefix)
		if ok && p.Contains(a) && now.Sub(n.At) < asnNetTerm {
			return n.ASN
		}
	}
	return ""
}

// prefix: n parsed, kept; b.mu held
func (b *asnBook) prefix(s string) (netip.Prefix, bool) {
	if p, ok := b.parsed[s]; ok {
		return p, true
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	if b.parsed == nil {
		b.parsed = map[string]netip.Prefix{}
	}
	b.parsed[s] = p
	return p, true
}

// ranges: a network's ranges as the inheritance list takes them, and
// whether they are known; nil-safe
func (b *asnBook) ranges(asn string) ([]string, bool) {
	if b == nil {
		return nil, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.ASNs[asn]
	if r == nil {
		return nil, false
	}
	if r.Failed {
		return nil, time.Since(r.At) < asnRetry
	}
	return r.Prefixes, time.Since(r.At) < asnRangesTerm
}

// want: networks whose ranges are to be looked up; nil-safe
func (b *asnBook) want(asns []string) {
	if b == nil || len(asns) == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.wanted == nil {
		b.wanted = map[string]bool{}
	}
	for _, a := range asns {
		b.wanted[a] = true
	}
}

// nodes: the probed nodes of this network's verdicts whose network the
// book does not know, for the next round
func (s *state) unownedNodes(id string, b *asnBook) []string {
	if b == nil {
		return nil
	}
	s.mu.Lock()
	var ips []string
	for dom, e := range s.Networks[id] {
		if _, addr := probe.AddrKey(dom); !addr && e.TestedIP != "" {
			ips = append(ips, e.TestedIP)
		}
	}
	s.mu.Unlock()
	ips = dedupe(ips)
	sort.Strings(ips)
	return slices.DeleteFunc(ips, func(ip string) bool { return b.asnOf(ip) != "" })
}

// the RIPE lookups, for the tests to script
var (
	ripeNetInfo  = ripeNetInfoGet
	ripePrefixes = ripePrefixesGet
)

func ripeNetInfoGet(cl *http.Client, ip string) (asn, prefix string, err error) {
	var r struct {
		Data struct {
			ASNs   []string `json:"asns"`
			Prefix string   `json:"prefix"`
		} `json:"data"`
	}
	if err := getJSON(cl, "https://stat.ripe.net/data/network-info/data.json?resource="+url.QueryEscape(ip), &r); err != nil {
		return "", "", err
	}
	if len(r.Data.ASNs) == 0 || r.Data.Prefix == "" {
		return "", "", fmt.Errorf("no network announces %s", ip)
	}
	return "AS" + r.Data.ASNs[0], r.Data.Prefix, nil
}

func ripePrefixesGet(cl *http.Client, asn string) ([]string, error) {
	var r struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	// seen by few peers: a leak or a test, not the network's own
	if err := getJSON(cl, "https://stat.ripe.net/data/announced-prefixes/data.json?min_peers_seeing=10&resource="+
		url.QueryEscape(asn), &r); err != nil {
		return nil, err
	}
	var out []string
	for _, p := range r.Data.Prefixes {
		if pp, err := netip.ParsePrefix(p.Prefix); err == nil {
			out = append(out, pp.Masked().String())
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s announces nothing", asn)
	}
	return out, nil
}

// round: one round of lookups -- the wanted networks' ranges first, then
// nodes -- in the background, one round at a time. done is called after a
// round that learnt anything, to rewrite the lists by it; a round it starts
// then takes the ranges those lists found wanting.
func (b *asnBook) round(directAddr string, nodes []string, done func()) {
	if b == nil || !b.busy.CompareAndSwap(false, true) {
		return
	}
	go func() {
		learnt := false
		// done runs once the round is over: it may start the next one --
		// the networks the nodes just showed lending want their ranges
		defer func() {
			b.busy.Store(false)
			if learnt {
				done()
			}
		}()
		cl := directClient(directAddr)
		b.mu.Lock()
		wanted := keys(b.wanted)
		b.mu.Unlock()
		sort.Strings(wanted)
		// the networks at once too, a few at a time: each answer is a few
		// hundred kilobytes
		var wg sync.WaitGroup
		sem := make(chan struct{}, asnRangeWorkers)
		for i, asn := range wanted {
			if i >= asnPerRound {
				break
			}
			if _, ok := b.ranges(asn); ok {
				b.mu.Lock()
				delete(b.wanted, asn)
				b.mu.Unlock()
				continue
			}
			sem <- struct{}{}
			wg.Add(1)
			go func(asn string) {
				defer func() { <-sem; wg.Done() }()
				p, err := ripePrefixes(cl, asn)
				b.mu.Lock()
				defer b.mu.Unlock()
				switch {
				case err != nil:
					log.Printf("network %s: ranges not learnt, trying again in %s: %v", asn, asnRetry, err)
					b.ASNs[asn] = &asnRanges{At: time.Now(), Failed: true}
				case len(p) > maxASNRanges:
					// kept for its term with no ranges: it lends nothing
					log.Printf("network %s announces %d ranges, more than %d: too wide to lend one service's way",
						asn, len(p), maxASNRanges)
					b.ASNs[asn] = &asnRanges{At: time.Now()}
					delete(b.wanted, asn)
				default:
					b.ASNs[asn] = &asnRanges{Prefixes: p, At: time.Now()}
					delete(b.wanted, asn)
					learnt = true
				}
			}(asn)
		}
		wg.Wait()
		// every node not known yet, asnWorkers at a time: memory made
		// before inheritance holds hundreds, and a few a cycle kept the
		// first minutes after an update on the old way
		sem = make(chan struct{}, asnWorkers)
		for i, ip := range nodes {
			if i >= asnNodesPerRound {
				break
			}
			sem <- struct{}{}
			// one in a prefix a lookup just learnt is not asked again
			if b.asnOf(ip) != "" || b.held(ip) {
				<-sem
				continue
			}
			wg.Add(1)
			go func(ip string) {
				defer func() { <-sem; wg.Done() }()
				asn, prefix, err := ripeNetInfo(cl, ip)
				b.mu.Lock()
				defer b.mu.Unlock()
				if err != nil {
					b.fail(ip)
				} else if p, perr := netip.ParsePrefix(prefix); perr == nil {
					b.Nets = append(b.Nets, asnNet{Prefix: p.Masked().String(), ASN: asn, At: time.Now()})
					learnt = true
				}
			}(ip)
		}
		wg.Wait()
		if !learnt {
			return
		}
		if err := b.save(); err != nil {
			log.Printf("network book not saved: %v", err)
		}
	}()
}

// held: a lookup of k failed a moment ago
func (b *asnBook) held(k string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	at, ok := b.failed[k]
	return ok && time.Since(at) < asnRetry
}

// fail notes a failed lookup; b.mu held
func (b *asnBook) fail(k string) {
	if b.failed == nil {
		b.failed = map[string]time.Time{}
	}
	b.failed[k] = time.Now()
}

func (b *asnBook) save() error {
	b.mu.Lock()
	// a node looked up long ago is looked up again: dropped here
	now := time.Now()
	b.Nets = slices.DeleteFunc(b.Nets, func(n asnNet) bool { return now.Sub(n.At) >= asnNetTerm })
	raw, err := json.Marshal(b)
	b.mu.Unlock()
	if err != nil {
		return err
	}
	return paths.ReplaceFile(b.path, raw)
}
