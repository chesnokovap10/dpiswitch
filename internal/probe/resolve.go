package probe

import (
	"fmt"
	"strings"
)

// DoH resolution over a given path (direct or tunnel).
// The resolver is dialed by IP literal: plain UDP/53 may be blocked, and
// bootstrapping by name would be a chicken-and-egg problem.
var defaultResolvers = []Resolver{
	{Raw: "https://8.8.8.8/dns-query", Scheme: "https", Host: "8.8.8.8", Port: 443, Path: "/dns-query"},
	{Raw: "https://1.1.1.1/dns-query", Scheme: "https", Host: "1.1.1.1", Port: 443, Path: "/dns-query"},
}

func ResolveVia(d Dialer, host string) ([]string, error) {
	return resolveVia(d, host, typeA)
}

// ResolveViaV6: ResolveVia for AAAA, for a name with no A record
func ResolveViaV6(d Dialer, host string) ([]string, error) {
	return resolveVia(d, host, typeAAAA)
}

func resolveVia(d Dialer, host string, qtype uint16) ([]string, error) {
	var lastErr error
	for _, r := range defaultResolvers {
		ips, err := r.lookup(d, host, qtype)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("empty answer from all resolvers")
	}
	return nil, lastErr
}

func JoinIPs(s []string) string { return strings.Join(s, ",") }
