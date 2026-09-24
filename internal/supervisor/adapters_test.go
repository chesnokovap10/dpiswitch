package supervisor

import (
	"net"
	"testing"
)

func v4(s ...string) []net.IP {
	var out []net.IP
	for _, a := range s {
		out = append(out, net.ParseIP(a).To4())
	}
	return out
}

var (
	wifi  = adapter{index: 7, name: "Wi-Fi", desc: "MediaTek Wi-Fi 6E", up: true, v4: v4("192.168.31.250")}
	meta  = adapter{index: 40, name: "Meta", desc: "Meta Tunnel", up: true, v4: v4("198.18.0.1")}
	wsl   = adapter{index: 30, name: "vEthernet (WSL)", desc: "Hyper-V Virtual Ethernet Adapter", up: true, v4: v4("172.24.16.1")}
	modem = adapter{index: 12, name: "Cellular", desc: "Mobile Broadband Adapter", up: true, v4: v4("10.120.4.9")}
	apipa = adapter{index: 9, name: "Ethernet", desc: "Realtek", up: true, v4: v4("169.254.10.3")}
	wg    = adapter{index: 50, name: "home", desc: "WireGuard Tunnel", up: true, v4: v4("10.8.1.3")}
	awgVP = adapter{index: 51, name: "AmneziaVPN", desc: "AmneziaWG Tunnel", up: true, v4: v4("10.8.1.4")}
)

// A network is an interface that leads out: a default route through it,
// not merely an address.
func TestHasUplink(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ads    []adapter
		routes []uint32
		want   bool
	}{
		{"Wi-Fi with its route", []adapter{wifi, meta}, []uint32{7, 40}, true},
		{"Wi-Fi off, WSL up", []adapter{wsl, meta}, []uint32{40}, false},
		{"the TUN's own route only", []adapter{meta}, []uint32{40}, false},
		{"a modem, route on-link", []adapter{modem}, []uint32{12}, true},
		{"no DHCP answer", []adapter{apipa}, []uint32{9}, false},
		{"Wi-Fi down", []adapter{{index: 7, name: "Wi-Fi", v4: v4("192.168.31.250")}}, []uint32{7}, false},
	} {
		routes := map[uint32]bool{}
		for _, r := range tc.routes {
			routes[r] = true
		}
		if got := hasUplink(tc.ads, routes); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Another WireGuard-type client is told by its adapter, not by any
// point-to-point interface: a modem or our own TUN is no reason to leave
// a dead tunnel alone.
func TestForeignWG(t *testing.T) {
	for _, tc := range []struct {
		name string
		ads  []adapter
		want bool
	}{
		{"WireGuard up", []adapter{wifi, meta, wg}, true},
		{"AmneziaWG up", []adapter{wifi, awgVP}, true},
		{"a modem, our TUN", []adapter{modem, meta}, false},
		{"WireGuard down", []adapter{wifi, {name: "home", desc: "WireGuard Tunnel"}}, false},
	} {
		if got, _ := foreignWG(tc.ads); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The tables themselves are read on this machine.
func TestAdaptersRead(t *testing.T) {
	ads, err := adapters()
	if err != nil || len(ads) == 0 {
		t.Fatalf("adapters: %d, %v", len(ads), err)
	}
	if _, err := defaultRoutes4(); err != nil {
		t.Fatalf("routes: %v", err)
	}
}
