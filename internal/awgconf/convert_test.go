package awgconf

import (
	"fmt"
	"strings"
	"testing"
)

// The core's own default is DualStack, and an unknown ip-version value
// unmarshals back to it (constant/dns.go), so both states must be written
// out explicitly and spelled the way the core spells them.
func TestWriteProxyIPVersion(t *testing.T) {
	c := &Conf{
		Interface: Section{"Address": "10.8.1.3/32, fd7a:a1c3:8b42::3/128", "PrivateKey": "k"},
		Peer:      Section{"PublicKey": "p", "Endpoint": "198.51.100.7:51820"},
	}
	for _, tc := range []struct {
		ipv6   bool
		v6Dead bool
		want   string
	}{
		{true, false, "ip-version: ipv4-prefer"},
		{false, false, "ip-version: ipv4"},
		// the check found IPv6 dead through this tunnel
		{true, true, "ip-version: ipv4"},
	} {
		var sb strings.Builder
		c.writeProxy(func(f string, a ...any) {
			sb.WriteString(strings.TrimRight(fmt.Sprintf(f, a...), "\n") + "\n")
		}, "awg", nil, tc.ipv6, tc.v6Dead)
		got := sb.String()
		for _, line := range strings.Split(got, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ip-version:") && line != tc.want {
				t.Fatalf("ipv6=%v dead=%v: got %q, want %q", tc.ipv6, tc.v6Dead, line, tc.want)
			}
		}
		if !strings.Contains(got, tc.want) {
			t.Fatalf("ipv6=%v: %q not written at all:\n%s", tc.ipv6, tc.want, got)
		}
	}
}
