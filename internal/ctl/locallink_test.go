package ctl

import (
	"net"
	"strings"
	"testing"
)

// The local link as this machine has it: no loopback, no TUN, no
// link-local address -- each "index=address/bits".
func TestLocalLinkHere(t *testing.T) {
	for _, f := range strings.Fields(localLink()) {
		for _, bad := range []string{"=127.", "=198.18.", "=198.19.", "=169.254.", "=fe80:", "=fdfe:dcba:9876:", "=2001:2:"} {
			if strings.Contains(f, bad) {
				t.Errorf("%s in the local link", f)
			}
		}
	}
}

// An IPv6 network's router is its name when there is no IPv4 gateway: the
// link-local next hop of the lowest metric, the same whatever order the
// table gives; a next hop that is no router's -- the core's ULA -- none.
func TestPickGateway6(t *testing.T) {
	r := func(hop string, index uint32, metric int) route6 { return route6{net.ParseIP(hop), index, metric} }
	if gw, ifc := pickGateway6([]route6{r("fdfe:dcba:9876::2", 40, 1)}); gw != "" {
		t.Errorf("the core's own next hop taken: %s on %d", gw, ifc)
	}
	rows := []route6{r("fe80::2", 12, 50), r("fdfe:dcba:9876::2", 40, 1), r("fe80::1", 7, 25), r("fe80::3", 9, 25)}
	for i := range 3 {
		if gw, ifc := pickGateway6(rows); gw != "fe80::1" || ifc != 7 {
			t.Fatalf("order %d: %s on %d, want fe80::1 on 7", i, gw, ifc)
		}
		rows = append(rows[1:], rows[0])
	}
}

// The gateway as this machine has it, and the network named by it when the
// IPv4 one is not there to: a router's link-local address, read off the
// table. Says what it found, not whether there is IPv6 here.
func TestGateway6Here(t *testing.T) {
	gw, ifc, ok := gateway6FromTable()
	if !ok {
		t.Fatal("the IPv6 routing table not read")
	}
	if gw == "" {
		t.Skip("no IPv6 default route here")
	}
	if ip := net.ParseIP(gw); ip == nil || !ip.IsLinkLocalUnicast() {
		t.Errorf("gateway %q is no router's link-local address", gw)
	}
	mac, read := macFromTable6(gw, ifc)
	t.Logf("IPv6 gateway %s on interface %d, MAC %q (table read %v)", gw, ifc, mac, read)
}

// An IPv6 address stands for its network: a /128 one -- a temporary
// address, made anew every day -- by its /64.
func TestPrefix64(t *testing.T) {
	for in, want := range map[string]string{
		"2a00:1e88:13ca:cd00:adb8:b4b2:bee7:cee1/128": "2a00:1e88:13ca:cd00::/64",
		"2a00:1e88:13ca:cd00::470/128":                "2a00:1e88:13ca:cd00::/64",
		"2a00:1e88:13ca:cd00:1:2:3:4/64":              "2a00:1e88:13ca:cd00::/64",
		"2a00:1e88:13ca:cd00:1:2:3:4/56":              "2a00:1e88:13ca:cd00::/56",
	} {
		ip, n, _ := net.ParseCIDR(in)
		n.IP = ip
		if got := prefix64(n).String(); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
	for _, f := range strings.Fields(localLink()) {
		if strings.Contains(f, ":") && strings.HasSuffix(f, "/128") {
			t.Errorf("%s: an IPv6 address in the local link, not its network", f)
		}
	}
}
