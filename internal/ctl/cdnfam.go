package ctl

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"

	"dpiswitch/internal/paths"
	"dpiswitch/internal/probe"
)

// CDN families: a page and the CDN serving its media go one way.
//
// A media URL is signed for the address its page came from (see
// inherit.go): a page direct and its CDN host through the tunnel, or the
// other way round, and the service refuses the host. Inheritance lends a
// CDN host the cut's way only where its domain is clearly direct, and the
// page goes by its own verdict, so on a network where the cut gets through
// to a third of googlevideo.com the two went apart.
//
// The link is the CDN's own certificate: googlevideo.com's names
// "*.c.youtube.com" -- a zone of youtube.com it serves -- but not
// youtube.com itself; youtube.com, the page, is a client. A page's
// certificate names whole domains ("*.google.com" names youtube.com and
// music.youtube.com themselves), so a domain named bare is never a client:
// that keeps google.com, many short-lived names of its own, from claiming
// YouTube. A CDN is a domain with at least cdnMinNames names checked here.
//
// A family goes the tunnel's way by default. It goes direct, the cut's
// way, when at least 3 of every 4 of its CDN names checked go direct
// (cdnMinChecked of them at least) and none of its pages is blocked; it
// keeps direct down to 1 in 2, so it does not swing on one verdict. Direct, its CDN hosts the cut does not get through are refused
// (RefuseProvider) -- through the tunnel the service would refuse them --
// and the player takes another host.

const (
	FamilyDirectProvider = "family-direct"
	FamilyTunnelProvider = "family-tunnel"
)

const (
	// a domain with this many names checked here is a CDN candidate: its
	// certificate is looked at
	cdnMinNames = 10
	// a family decides by this many of its CDN names checked; below it
	// stays in the tunnel
	cdnMinChecked = 10
	// direct at 3 in 4, kept direct down to 1 in 2. On 09.10 a family
	// direct at 10 of 31 on Beeline hung: the cut got through to a third of
	// the new hosts, the rest dropped silently until checked; through the
	// tunnel, page and all, it played.
	cdnEnterNum, cdnEnterDen = 3, 4
	cdnKeepNum, cdnKeepDen   = 1, 2
	cdnTerm                  = 7 * 24 * time.Hour
	cdnRetry                 = time.Hour
)

// cdnFamily: one CDN, the zones of its own and the pages it serves
type cdnFamily struct {
	CDN string `json:"cdn"` // "googlevideo.com"
	// Own: domains the certificate serves whole besides the CDN's --
	// "*.gvt1.com" -- known, left out of the family: nothing ties them to
	// a page
	Own []string `json:"own,omitempty"`
	// Bases: zones of other domains it serves -- "c.youtube.com"
	Bases []string `json:"bases,omitempty"`
	// Pages: the domains those zones belong to -- "youtube.com"
	Pages []string `json:"pages,omitempty"`
}

// clientZones: what a CDN's certificate says of its clients. A wildcard
// one label or more below a domain the certificate does not name bare is a
// zone the CDN serves for that domain's page; the page is that zone less
// its first label, never above the domain. A wildcard of a whole domain is
// the CDN's own.
func clientZones(cdn string, sans []string) cdnFamily {
	f := cdnFamily{CDN: cdn}
	bare := map[string]bool{}
	whole := map[string]bool{}
	for _, n := range sans {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		if strings.HasPrefix(n, "*.") {
			if base := n[2:]; familyOf(base) == base {
				whole[base] = true
			}
			continue
		}
		if fam := familyOf(n); fam != "" {
			bare[fam] = true
		}
	}
	for w := range whole {
		if w != cdn {
			f.Own = append(f.Own, w)
		}
	}
	pages := map[string]bool{}
	for _, n := range sans {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		if !strings.HasPrefix(n, "*.") {
			continue
		}
		base := n[2:]
		fam := familyOf(base)
		if fam == "" || fam == base || fam == cdn || whole[fam] || bare[fam] {
			continue
		}
		f.Bases = append(f.Bases, base)
		page := base[strings.Index(base, ".")+1:]
		if len(page) < len(fam) {
			page = fam
		}
		pages[page] = true
	}
	for p := range pages {
		f.Pages = append(f.Pages, p)
	}
	sort.Strings(f.Own)
	sort.Strings(f.Bases)
	sort.Strings(f.Pages)
	// a page under another page is that page's already
	f.Pages = slices.DeleteFunc(f.Pages, func(p string) bool {
		for _, q := range f.Pages {
			if q != p && strings.HasSuffix(p, "."+q) {
				return true
			}
		}
		return false
	})
	return f
}

// under: name is zone or below it
func under(name, zone string) bool {
	return name == zone || strings.HasSuffix(name, "."+zone)
}

// cdnOf: the name's part in the family -- one of its CDN's hosts, a page,
// or neither
func (f cdnFamily) cdnOf(name string) (cdn, page bool) {
	if under(name, f.CDN) {
		return true, false
	}
	for _, b := range f.Bases {
		if under(name, b) {
			return true, false
		}
	}
	for _, p := range f.Pages {
		if under(name, p) {
			return false, true
		}
	}
	return false, false
}

// rules: the family as a list takes it
func (f cdnFamily) rules() []string {
	out := []string{"+." + f.CDN}
	for _, z := range concat(f.Bases, f.Pages) {
		out = append(out, "+."+z)
	}
	return out
}

// pageBlocked: a verdict saying a page cannot go direct -- blocked, the cut
// tried or not; QUIC alone leaves TCP
func pageBlocked(v probe.Verdict) bool {
	return v == probe.BlockedDPI || v == probe.BlockedTCP || v == probe.BlockedTLS
}

// familyWay: what one family does on this network
type familyWay struct {
	f              cdnFamily
	direct         bool
	cdnDirect, cdn int    // CDN names going direct, of those leaning
	blockedPage    string // a page blocked here, if any
}

func (w familyWay) String() string {
	way := "tunnel"
	if w.direct {
		way = "direct"
	}
	s := fmt.Sprintf("%s (%s): %s, CDN %d of %d direct", w.f.CDN, strings.Join(w.f.Pages, ", "), way, w.cdnDirect, w.cdn)
	if w.blockedPage != "" {
		s += ", page " + w.blockedPage + " blocked"
	}
	return s
}

// familyWays: the families' ways by this network's verdicts. wasDirect:
// the CDNs whose family went direct so far (the list on disk).
func (s *state) familyWays(id string, book *cdnBook, wasDirect map[string]bool) []familyWay {
	fams := book.families()
	if len(fams) == 0 {
		return nil
	}
	ways := make([]familyWay, len(fams))
	for i, f := range fams {
		ways[i].f = f
	}
	now := time.Now()
	s.mu.Lock()
	for dom, e := range s.Networks[id] {
		if _, addr := probe.AddrKey(dom); addr {
			continue
		}
		for i := range ways {
			cdn, page := ways[i].f.cdnOf(dom)
			switch {
			case cdn:
				d, a := lean(e, now)
				if d || a {
					ways[i].cdn++
				}
				if d {
					ways[i].cdnDirect++
				}
			case page:
				if pageBlocked(e.Verdict) && now.Before(e.ExpiresAt) && ways[i].blockedPage == "" {
					ways[i].blockedPage = dom
				}
			}
		}
	}
	s.mu.Unlock()
	for i := range ways {
		w := &ways[i]
		num, den := cdnEnterNum, cdnEnterDen
		if wasDirect[w.f.CDN] {
			num, den = cdnKeepNum, cdnKeepDen
		}
		w.direct = w.blockedPage == "" && w.cdn >= cdnMinChecked && w.cdnDirect*den >= w.cdn*num
	}
	sort.Slice(ways, func(i, j int) bool { return ways[i].f.CDN < ways[j].f.CDN })
	return ways
}

// cdnCandidates: the domains with at least cdnMinNames names checked here
func (s *state) cdnCandidates(id string) []string {
	n := map[string]int{}
	s.mu.Lock()
	for dom := range s.Networks[id] {
		if f := familyOf(dom); f != "" {
			n[f]++
		}
	}
	s.mu.Unlock()
	var out []string
	for f, c := range n {
		if c >= cdnMinNames {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

// cdnHosts: a few of the domain's names checked here, to fetch its
// certificate from
func (s *state) cdnHosts(id, cdn string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for dom := range s.Networks[id] {
		if familyOf(dom) == cdn {
			out = append(out, dom)
		}
	}
	sort.Strings(out)
	if len(out) > 3 {
		out = out[:3]
	}
	return out
}

// cdnBook: the CDN candidates' certificates, as clientZones reads them --
// fetched through the tunnel, the same everywhere, kept in a file
type cdnBook struct {
	mu   sync.Mutex
	path string
	CDNs map[string]*cdnEntry `json:"cdns"`
	busy atomic.Bool
}

type cdnEntry struct {
	cdnFamily
	At     time.Time `json:"at"`
	Failed bool      `json:"failed,omitempty"`
}

func loadCDNBook(path string) *cdnBook {
	b := &cdnBook{path: path, CDNs: map[string]*cdnEntry{}}
	if raw, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(raw, b); err != nil {
			log.Printf("CDN book %s unreadable, starting anew: %v", path, err)
		}
	}
	if b.CDNs == nil {
		b.CDNs = map[string]*cdnEntry{}
	}
	return b
}

// families: the CDNs whose certificate names a page; nil-safe
func (b *cdnBook) families() []cdnFamily {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []cdnFamily
	pageSide := map[string]bool{}
	for _, e := range b.CDNs {
		if !e.Failed && len(e.Pages) > 0 {
			out = append(out, e.cdnFamily)
			for _, p := range e.Pages {
				pageSide[familyOf(p)] = true
			}
		}
	}
	// a domain another CDN serves zones of is a page's, whatever its own
	// certificate names: google.com's names a zone of android.com, and
	// googlevideo.com serves Drive's and Mail's
	return slices.DeleteFunc(out, func(f cdnFamily) bool { return pageSide[f.CDN] })
}

// stale: the candidates whose certificate is to be fetched (again)
func (b *cdnBook) stale(cands []string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for _, c := range cands {
		e := b.CDNs[c]
		switch {
		case e == nil:
		case e.Failed && time.Since(e.At) >= cdnRetry:
		case !e.Failed && time.Since(e.At) >= cdnTerm:
		default:
			continue
		}
		out = append(out, c)
	}
	return out
}

// fetchCert: the names the certificate of host's server holds, through the
// tunnel's listener -- the direct way may be blocked by that very name
var fetchCert = func(tunnelAddr, pass, host string) ([]string, error) {
	d, err := proxy.SOCKS5("tcp", tunnelAddr, &proxy.Auth{User: probe.SocksUser, Password: pass},
		&net.Dialer{Timeout: 8 * time.Second})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raw, err := d.(proxy.ContextDialer).DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	// only the names are read, nothing is sent past the handshake
	c := tls.Client(raw, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err := c.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return c.ConnectionState().PeerCertificates[0].DNSNames, nil
}

// round: the stale candidates' certificates, in the background, one round
// at a time; done after a round that learnt anything
func (b *cdnBook) round(tunnelAddr string, hosts map[string][]string, done func()) {
	if b == nil || len(hosts) == 0 || !b.busy.CompareAndSwap(false, true) {
		return
	}
	go func() {
		learnt := false
		defer func() {
			b.busy.Store(false)
			if learnt {
				done()
			}
		}()
		pass := socksPass()
		for cdn, list := range hosts {
			var sans []string
			var err error
			for _, h := range list {
				if sans, err = fetchCert(tunnelAddr, pass, h); err == nil {
					break
				}
			}
			e := &cdnEntry{At: time.Now()}
			if err != nil || len(sans) == 0 {
				e.Failed = true
				e.CDN = cdn
			} else {
				e.cdnFamily = clientZones(cdn, sans)
				if len(e.Pages) > 0 {
					log.Printf("CDN %s serves %s", cdn, strings.Join(e.Pages, ", "))
				}
			}
			b.mu.Lock()
			b.CDNs[cdn] = e
			b.mu.Unlock()
			learnt = learnt || !e.Failed
		}
		if learnt {
			if err := b.save(); err != nil {
				log.Printf("CDN book not saved: %v", err)
			}
		}
	}()
}

func (b *cdnBook) save() error {
	b.mu.Lock()
	raw, err := json.Marshal(b)
	b.mu.Unlock()
	if err != nil {
		return err
	}
	return paths.ReplaceFile(b.path, raw)
}
