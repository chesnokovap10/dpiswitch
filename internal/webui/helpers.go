package webui

import (
	"errors"
	"net/netip"
	"sync"
	"time"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/probe"
)

type netPrefix struct{ p netip.Prefix }

func parsePrefix(s string) *netPrefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return nil
	}
	return &netPrefix{p}
}

func (n *netPrefix) contains(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && n.p.Contains(a.Unmap())
}

type dnsResult struct {
	Server string
	Kind   string // DoH, DoT, DNS
	OK     bool
	Ms     int64
	IPs    []string
	Error  string
	// the address as written (Was) did not answer and its other DoH
	// spelling did: this one, which the box takes instead (see
	// probe.DoHPathAlternative)
	Fixed, Was string
	// plain DNS to some other server, answered by the tunnel's own: the
	// servers catch port 53 and hand it to their resolver (see caughtBy)
	Caught bool
}

// caughtBy marks the plain-DNS results the tunnel's server answered itself:
// whoami.akamai.net gives its address (the endpoint) though the box names
// another server. The tunnel's own resolver (10.8.1.0 and the like) is
// private and answers so by right -- not marked.
func caughtBy(endpoint string, res []dnsResult) {
	ep, err := netip.ParseAddr(endpoint)
	if err != nil {
		return
	}
	ep = ep.Unmap()
	for i, r := range res {
		if r.Kind != "DNS" || !r.OK {
			continue
		}
		rs, err := probe.ParseResolver(r.Server)
		if err != nil {
			continue
		}
		if a, err := netip.ParseAddr(rs.Host); err == nil {
			a = a.Unmap()
			if a == ep || a.IsPrivate() || a.IsLoopback() {
				continue
			}
		}
		for _, ip := range r.IPs {
			if a, err := netip.ParseAddr(ip); err == nil && a.Unmap() == ep {
				res[i].Caught = true
				break
			}
		}
	}
}

// dnsTest: what the DNS test shows, and the box's new text when an address
// was fixed -- the page puts it in the box, see data-fill in ui.js
type dnsTest struct {
	Results []dnsResult
	Field   string
	Fill    string
}

// testDNS checks resolvers over the same path the core will use: direct
// ones through the prober's listener that bypasses the tunnel, tunnel ones
// through awg. whoami.akamai.net answers with the address of the recursive
// server that asked it -- who actually resolves, not the domain's owner.
func testDNS(path string, servers []string) []dnsResult {
	cfg := ctl.Defaults()
	d := probe.Dialer{Addr: cfg.DirectAddr, Timeout: 6 * time.Second}
	switch path {
	case "tunnel":
		d.Addr = cfg.TunnelAddr
	case "tunnel2":
		d.Addr = cfg.Tunnel2Addr
	}
	out := make([]dnsResult, len(servers))
	var wg sync.WaitGroup
	for i, srv := range servers {
		wg.Add(1)
		go func(i int, srv string) {
			defer wg.Done()
			out[i] = pingDNS(d, srv)
		}(i, srv)
	}
	wg.Wait()
	return out
}

// pingEither: probe.PingEither; the tests put a script here
var pingEither = probe.PingEither

// pingDNS: one resolver asked, over d -- a DoH server that answers the other
// spelling of its address only is taken on that one (see probe.PingEither)
func pingDNS(d probe.Dialer, srv string) dnsResult {
	res := dnsResult{Server: srv, Kind: "DNS"}
	rs, err := probe.ParseResolver(srv)
	if err == nil {
		switch rs.Scheme {
		case "https":
			res.Kind = "DoH"
		case "tls":
			res.Kind = "DoT"
		}
		// the time of a query on a connection already up: the first
		// one's handshake is paid once, and showed a server two or
		// three times slower than it answers
		var rtt time.Duration
		var used string
		res.IPs, rtt, used, err = pingEither(d, srv, "whoami.akamai.net")
		res.Ms = rtt.Milliseconds()
		if err == nil && used != srv {
			res.Server, res.Fixed, res.Was = used, used, srv
		}
	}
	var re *probe.ResolverError
	switch {
	case errors.As(err, &re):
		// the server is named beside it: the reason alone, which the page
		// translates
		res.Error = re.Why
	case err != nil:
		res.Error = probe.Truncate(err.Error(), 120)
	default:
		res.OK = len(res.IPs) > 0
	}
	return res
}
