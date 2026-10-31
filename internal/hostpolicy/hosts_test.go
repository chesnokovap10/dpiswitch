package hostpolicy

import (
	"net/netip"
	"testing"
)

func TestPinsIncludeAliasesIPv6AndMappedIPv4(t *testing.T) {
	ips := parse([]byte("\ufeff192.0.2.1 other.example Protected.Example # note\r\n::ffff:192.0.2.2 protected.example.\n2001:db8::1 protected.example\nbad protected.example\n192.0.2.3 unprotected.example\n"), "PROTECTED.EXAMPLE.")
	if len(ips) != 3 || ips[0] != netip.MustParseAddr("192.0.2.1") || ips[1] != netip.MustParseAddr("192.0.2.2") || !ips[2].Is6() {
		t.Fatalf("pins: %v", ips)
	}
}
