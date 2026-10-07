package udpguard

import (
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/tailscale/wf"
)

func testExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

// The plan puts the same four rules in each family's own layer, the block
// last and the lowest, so that put in one by one the block never stands
// alone, and every rule is for UDP and nothing else.
func TestPlanShape(t *testing.T) {
	p, err := buildPlan(testExe(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.rules) != 8 {
		t.Fatalf("%d rules, want 8: four for each family", len(p.rules))
	}
	if p.sublayer.Provider != providerKey || p.provider.ID != providerKey || p.sublayer.ID != sublayerKey {
		t.Error("the sublayer is not the provider's, or the keys are not ours")
	}
	if p.sublayer.Weight != 0xffff {
		t.Errorf("sublayer weight %#x: another sublayer's permit could stand over the block", p.sublayer.Weight)
	}

	ids, names := map[wf.RuleID]bool{}, map[string]bool{}
	layers := map[wf.LayerID]int{}
	for i, r := range p.rules {
		if ids[r.ID] || names[r.Name] || r.ID.IsZero() {
			t.Errorf("rule %d: key or name taken again: %s", i, r.Name)
		}
		ids[r.ID], names[r.Name] = true, true
		layers[r.Layer]++
		if r.Sublayer != sublayerKey || r.Provider != providerKey {
			t.Errorf("%s: not in our sublayer", r.Name)
		}
		if len(r.Conditions) == 0 || r.Conditions[0].Field != wf.FieldIPProtocol || r.Conditions[0].Value != wf.IPProtoUDP {
			t.Errorf("%s: not for UDP first", r.Name)
		}
		isBlock := r.Action == wf.ActionBlock
		if isBlock != (i >= 6) {
			t.Errorf("%s: at %d, a block is last and only the last two", r.Name, i)
		}
		for _, c := range r.Conditions {
			if c.Op != wf.MatchTypeEqual {
				t.Errorf("%s: %v: only equality is used", r.Name, c)
			}
		}
	}
	if layers[wf.LayerALEAuthConnectV4] != 4 || layers[wf.LayerALEAuthConnectV6] != 4 {
		t.Errorf("rules by layer: %v", layers)
	}

	// the order they are looked at in: every permit stands over every block,
	// the core over the local network over DHCP
	weights := map[string]uint64{}
	var lowestPermit, highestBlock uint64 = ^uint64(0), 0
	for _, r := range p.rules {
		what := strings.TrimSuffix(strings.TrimPrefix(r.Name, "DPI Switch UDP guard: "), " (IPv4)")
		what = strings.TrimSuffix(what, " (IPv6)")
		if w, seen := weights[what]; seen && w != r.Weight {
			t.Errorf("%s: the two families weigh it differently", what)
		}
		weights[what] = r.Weight
		if r.Action == wf.ActionBlock {
			highestBlock = max(highestBlock, r.Weight)
		} else {
			lowestPermit = min(lowestPermit, r.Weight)
		}
	}
	if lowestPermit <= highestBlock {
		t.Errorf("a permit weighs %d, a block %d: the block is looked at first", lowestPermit, highestBlock)
	}
	if !(weights["the core's UDP"] > weights["UDP to the local network"] &&
		weights["UDP to the local network"] > weights["UDP to a DHCP server"]) {
		t.Errorf("weights: %v", weights)
	}
}

// The block names the adapters by their type, one condition each -- on one
// field the engine takes them as alternatives -- and the rest of the rules
// name neither an adapter nor a type: a rule that did would not hold for a
// packet leaving by another one.
func TestBlockIsByUplinkType(t *testing.T) {
	p, err := buildPlan(testExe(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range p.rules {
		var types []uint32
		for _, c := range r.Conditions {
			if c.Field == wf.FieldInterfaceType {
				types = append(types, c.Value.(uint32))
			}
		}
		if r.Action != wf.ActionBlock {
			if len(types) != 0 {
				t.Errorf("%s: names an adapter type", r.Name)
			}
			continue
		}
		want := map[uint32]bool{6: true, 71: true, 243: true, 244: true}
		if len(types) != len(want) {
			t.Errorf("%s: types %v", r.Name, types)
		}
		for _, ty := range types {
			if !want[ty] {
				t.Errorf("%s: type %d is not an uplink's", r.Name, ty)
			}
		}
		// the TUN's own type is none of them, or its traffic would be blocked
		for _, ty := range types {
			if ty == 53 {
				t.Errorf("%s: blocks Wintun's type", r.Name)
			}
		}
	}
}

// The local network is where a packet goes no further: private, link-local
// and multicast addresses, loopback -- and no public address, in either
// family, however near it looks.
func TestLocalCoversTheLocalNetworkOnly(t *testing.T) {
	covered := func(list []netip.Prefix, ip string) bool {
		a := netip.MustParseAddr(ip)
		for _, p := range list {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "10.255.255.254", "172.16.0.1", "172.31.255.255",
		"192.168.0.1", "192.168.31.1", "169.254.10.10", "224.0.0.251", "239.255.255.250", "255.255.255.255"} {
		if !covered(local4, ip) {
			t.Errorf("%s is the local network's and is blocked", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "192.0.2.1", "198.18.0.1", "172.15.255.255", "172.32.0.1",
		"192.167.1.1", "192.169.1.1", "11.0.0.1", "9.255.255.255", "100.64.0.1", "223.255.255.255", "84.252.75.74"} {
		if covered(local4, ip) {
			t.Errorf("%s is public and is let through", ip)
		}
	}
	for _, ip := range []string{"::1", "fe80::1", "febf::1", "fd00::1", "fc00::1", "fdfe:dcba:9876::1", "ff02::fb", "ff05::1:3"} {
		if !covered(local6, ip) {
			t.Errorf("%s is the local network's and is blocked", ip)
		}
	}
	for _, ip := range []string{"2001:db8::1", "2a00:1450:4001::1", "2606:4700:4700::1111", "2001:2::1", "fec0::1", "::ffff:8.8.8.8"} {
		if covered(local6, ip) {
			t.Errorf("%s is public and is let through", ip)
		}
	}
}

// Each family's rules carry its own addresses and port: a v4 prefix in a v6
// layer is an engine error, and DHCP's port is 67 for one and 547 for the other.
func TestFamiliesAreKeptApart(t *testing.T) {
	p, err := buildPlan(testExe(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range p.rules {
		v4 := r.Layer == wf.LayerALEAuthConnectV4
		for _, c := range r.Conditions {
			switch c.Field {
			case wf.FieldIPRemoteAddress:
				if pfx := c.Value.(netip.Prefix); pfx.Addr().Is4() != v4 {
					t.Errorf("%s: %v is of the other family", r.Name, pfx)
				}
			case wf.FieldIPRemotePort:
				if want := map[bool]uint16{true: 67, false: 547}[v4]; c.Value.(uint16) != want {
					t.Errorf("%s: port %v, want %d", r.Name, c.Value, want)
				}
			}
		}
	}
}

// A core that is not there has no application ID, and nothing is put in
// with the core unnamed: every packet of its own would be blocked.
func TestPlanNeedsTheCore(t *testing.T) {
	if _, err := buildPlan(`C:\no\such\dir\mihomo.exe`); err == nil {
		t.Fatal("a plan for a core that does not exist")
	}
}
