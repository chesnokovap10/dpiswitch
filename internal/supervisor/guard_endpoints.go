package supervisor

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"time"

	"dpiswitch/internal/awgconf"
	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/probe"
)

// guardSystemEndpoints follows the configured tunnel transport and direct UDP
// DNS servers. Some network filters attribute their packets to System instead
// of the core. Only these exact destinations may use that exception.
func guardSystemEndpoints() func() []netip.AddrPort {
	type entry struct {
		ips  []netip.Addr
		next time.Time
	}
	cache := map[string]entry{}
	resolve := func(host string) []netip.Addr {
		if ip, err := netip.ParseAddr(host); err == nil {
			return []netip.Addr{ip.Unmap()}
		}
		e := cache[host]
		if time.Now().After(e.next) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			cancel()
			// A transient lookup failure keeps the last resolution for this host.
			if err == nil && len(ips) > 0 {
				e.ips = ips
			}
			e.next = time.Now().Add(time.Minute)
			cache[host] = e
		}
		return e.ips
	}
	return func() []netip.AddrPort {
		var out []netip.AddrPort
		add := func(host string, port uint16) {
			for _, ip := range resolve(host) {
				out = append(out, netip.AddrPortFrom(ip.Unmap(), port))
			}
		}
		first, _ := awgconf.ParseFile(paths.SourceConf())
		if first != nil {
			if err := first.Usable(); err != nil {
				first = nil
			}
		}
		second, _ := awgconf.Second(first)
		for _, conf := range []*awgconf.Conf{first, second} {
			if conf == nil {
				continue
			}
			host, text, err := net.SplitHostPort(conf.Peer["Endpoint"])
			if err != nil {
				continue
			}
			port, err := strconv.ParseUint(text, 10, 16)
			if err != nil || port == 0 {
				continue
			}
			add(host, uint16(port))
		}
		// Tunnel DNS is carried inside the encrypted transport above. Only plain
		// UDP resolvers used directly need another physical UDP exception.
		for _, server := range ctl.LoadSettings(paths.Settings()).DirectDNS {
			r, err := probe.ParseResolver(server)
			if err == nil && r.Scheme == "udp" {
				add(r.Host, uint16(r.Port))
			}
		}
		return out
	}
}
