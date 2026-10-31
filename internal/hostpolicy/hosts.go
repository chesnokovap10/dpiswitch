// Package hostpolicy reads the system hosts pins without asking DNS.
package hostpolicy

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// Lookup fails closed on read errors. A missing/unreadable file must not be
// mistaken for permission to probe a domain at its public DNS address.
func Lookup(host string) ([]netip.Addr, error) {
	body, err := os.ReadFile(systemHostsPath())
	if err != nil {
		return nil, fmt.Errorf("read system hosts: %w", err)
	}
	return parse(body, host), nil
}

func parse(body []byte, host string) []netip.Addr {
	host = strings.TrimSuffix(host, ".")
	var ips []netip.Addr
	for _, line := range strings.Split(strings.TrimPrefix(string(body), "\ufeff"), "\n") {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip, err := netip.ParseAddr(fields[0])
		if err != nil || ip.Zone() != "" {
			continue
		}
		for _, name := range fields[1:] {
			if strings.EqualFold(strings.TrimSuffix(name, "."), host) {
				ips = append(ips, ip.Unmap())
				break
			}
		}
	}
	return ips
}
