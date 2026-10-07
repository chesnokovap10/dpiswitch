package supervisor

import (
	"net"
	"testing"
)

// An IPv6 uplink counts only for a tunnel whose server is an IPv6 address
func TestEndpointV6(t *testing.T) {
	for ep, want := range map[string]bool{
		"[2001:db8::1]:51820": true, "198.51.100.7:51820": false, "vpn.example.org:51820": false,
		"[::ffff:198.51.100.7]:51820": false, "nonsense": false,
	} {
		if got := endpointV6(ep); got != want {
			t.Errorf("%s: %v", ep, got)
		}
	}
}

func TestHasUplink6(t *testing.T) {
	global, ula := net.ParseIP("2a00:1e88::1"), net.ParseIP("fdfe:dcba:9876::1")
	wifi := adapter{index6: 11, name: "Wi-Fi", up: true, v6: []net.IP{global}}
	tun := adapter{index6: 34, name: "Meta", up: true, v6: []net.IP{global}}
	if !hasUplink6([]adapter{wifi}, map[uint32]bool{11: true}) {
		t.Error("Wi-Fi with an IPv6 default route and a global address")
	}
	if hasUplink6([]adapter{wifi}, map[uint32]bool{}) {
		t.Error("no IPv6 default route")
	}
	if hasUplink6([]adapter{tun}, map[uint32]bool{34: true}) {
		t.Error("the TUN taken for an uplink")
	}
	if isULA(global) || !isULA(ula) {
		t.Error("isULA")
	}
}
