package webui

import (
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
}

// testDNS checks resolvers over the same path the core will use: direct
// ones through the prober's listener that bypasses the tunnel, tunnel ones
// through awg. whoami.akamai.net answers with the address of the recursive
// server that asked it -- who actually resolves, not the domain's owner.
func testDNS(path string, servers []string) []dnsResult {
	cfg := ctl.Defaults()
	d := probe.Dialer{Addr: cfg.DirectAddr, Timeout: 6 * time.Second}
	if path == "tunnel" {
		d.Addr = cfg.TunnelAddr
	}
	out := make([]dnsResult, len(servers))
	var wg sync.WaitGroup
	for i, srv := range servers {
		wg.Add(1)
		go func(i int, srv string) {
			defer wg.Done()
			res := dnsResult{Server: srv, Kind: "DNS"}
			rs, err := probe.ParseResolver(srv)
			if err == nil {
				switch {
				case len(srv) > 8 && srv[:8] == "https://":
					res.Kind = "DoH"
				case len(srv) > 6 && srv[:6] == "tls://":
					res.Kind = "DoT"
				}
				t := time.Now()
				res.IPs, err = rs.Lookup(d, "whoami.akamai.net")
				res.Ms = time.Since(t).Milliseconds()
			}
			if err != nil {
				res.Error = probe.Truncate(err.Error(), 120)
			} else {
				res.OK = len(res.IPs) > 0
			}
			out[i] = res
		}(i, srv)
	}
	wg.Wait()
	return out
}
