package udpguard

import (
	"fmt"
	"net/netip"

	"github.com/tailscale/wf"
)

// What is blocked, and what is let through.
//
// A program that binds its UDP socket to the physical adapter's own address
// -- a browser gathering WebRTC candidates, a messenger's calls, a game, a
// torrent client -- leaves by that adapter whatever the routes say: the TUN's
// default route is not asked. Windows takes the source address for the
// adapter to leave by. The packet goes around the tunnel with the real
// address in it.
//
// The filters sit in the ALE connect layer, where an outgoing UDP flow is
// authorised on its first packet, and have the same four rules for IPv4 and
// IPv6, in one sublayer of ours. The highest weight is evaluated first and a
// permit ends it:
//
//	permit  UDP of the core -- its tunnels' packets, its direct sites, the
//	        detector's probes: all of it leaves by the adapter
//	permit  UDP to the local network: private, link-local and multicast
//	        addresses, loopback -- the router, a TV cast to, a printer, the
//	        network's discovery
//	permit  UDP to a DHCP server's port: the lease is asked of an address
//	        the lease itself gives
//	block   UDP out of a cable, Wi-Fi or mobile broadband adapter
//
// Nothing is said of the TUN adapter, and nothing needs to be: it is none of
// those types (Windows reports Wintun's as 53, "propVirtual"), so what the
// routes send into it is not touched.

// the types of the adapters a packet leaves the machine by (ipifcons.h); a
// virtual switch's adapter is Ethernet too, as the bridged one of a virtual
// machine, and a VPN's -- PPP, tunnel or its own kind -- is none of them
const (
	ifEthernet = 6   // IF_TYPE_ETHERNET_CSMACD
	ifWiFi     = 71  // IF_TYPE_IEEE80211
	ifMobile   = 243 // IF_TYPE_WWANPP
	ifMobile2  = 244 // IF_TYPE_WWANPP2
)

var uplinkTypes = []uint32{ifEthernet, ifWiFi, ifMobile, ifMobile2}

// the addresses UDP to which is not guarded: where a packet to them goes no
// further than the local network. A device there with an address of another
// kind is cut off; the setting's text says so.
var (
	local4 = prefixes("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32")
	local6 = prefixes("::1/128", "fe80::/10", "fc00::/7", "ff00::/8")
)

func prefixes(list ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(list))
	for i, s := range list {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// the weights, in the order the rules are looked at; the sublayer's is the
// highest there is, so that no other sublayer's permit stands over the block
const (
	weightCore  uint64 = 0x400
	weightLocal uint64 = 0x300
	weightDHCP  uint64 = 0x200
	weightBlock uint64 = 0x100

	sublayerWeight uint16 = 0xffff
)

// the keys of what is put in: ours alone, so that a look at the filters
// (netsh wfp show filters) names them, and nothing else's is taken for them
var (
	providerKey = wf.ProviderID{Data1: 0x0f512656, Data2: 0xf12c, Data3: 0x4954,
		Data4: [8]byte{0xac, 0xe6, 0x8d, 0x96, 0x3f, 0x98, 0x37, 0xbb}}
	sublayerKey = wf.SublayerID{Data1: 0x432bb7b5, Data2: 0x3e5d, Data3: 0x4e8d,
		Data4: [8]byte{0x85, 0xb0, 0x04, 0x58, 0xd3, 0xf2, 0x59, 0x98}}
	// the rules' keys count up from this one
	ruleKey0 = wf.RuleID{Data1: 0xe854ada6, Data2: 0x4c92, Data3: 0x41a3,
		Data4: [8]byte{0x9a, 0xfe, 0xdc, 0xcb, 0x62, 0x2e, 0xd5, 0x09}}
)

func ruleKey(i int) wf.RuleID {
	k := ruleKey0
	k.Data1 += uint32(i)
	return k
}

// plan: everything one installation puts into the filtering engine
type plan struct {
	provider wf.Provider
	sublayer wf.Sublayer
	rules    []*wf.Rule
	// core: the program let through, as it was given
	core string
}

// family: what differs between the two layers
type family struct {
	name  string
	layer wf.LayerID
	local []netip.Prefix
	dhcp  uint16 // the DHCP server's port: 67, and 547 for DHCPv6
}

var families = []family{
	{"IPv4", wf.LayerALEAuthConnectV4, local4, 67},
	{"IPv6", wf.LayerALEAuthConnectV6, local6, 547},
}

// buildPlan: the filters for a core at the path given. The permits come
// first and the blocks last: put in one by one, the block is the last to
// take effect, and never stands alone.
func buildPlan(core string) (plan, error) {
	app, err := wf.AppID(core)
	if err != nil {
		return plan{}, fmt.Errorf("the core's application ID: %w", err)
	}
	p := plan{
		core: core,
		provider: wf.Provider{ID: providerKey, Name: "DPI Switch",
			Description: "DPI Switch: UDP that would leave around the tunnel"},
		sublayer: wf.Sublayer{ID: sublayerKey, Name: "DPI Switch UDP guard", Provider: providerKey,
			Description: "Blocks UDP out of the physical adapters, but the core's own", Weight: sublayerWeight},
	}
	var blocks []*wf.Rule
	for _, f := range families {
		p.rules = append(p.rules,
			f.rule("the core's UDP", weightCore, wf.ActionPermit,
				&wf.Match{Field: wf.FieldALEAppID, Op: wf.MatchTypeEqual, Value: app}),
			f.rule("UDP to the local network", weightLocal, wf.ActionPermit, f.localMatches()...),
			f.rule("UDP to a DHCP server", weightDHCP, wf.ActionPermit,
				&wf.Match{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: f.dhcp}),
		)
		blocks = append(blocks, f.rule("UDP out of a physical adapter", weightBlock, wf.ActionBlock, uplinkMatches()...))
	}
	p.rules = append(p.rules, blocks...)
	for i, r := range p.rules {
		r.ID, r.Sublayer, r.Provider = ruleKey(i), sublayerKey, providerKey
	}
	return p, nil
}

// rule: one filter of the family's layer, for UDP and what else is given
func (f family) rule(what string, weight uint64, action wf.Action, conds ...*wf.Match) *wf.Rule {
	return &wf.Rule{
		Name:   fmt.Sprintf("DPI Switch UDP guard: %s (%s)", what, f.name),
		Layer:  f.layer,
		Weight: weight,
		Action: action,
		Conditions: append([]*wf.Match{
			{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoUDP},
		}, conds...),
	}
}

// localMatches: the destination is any of the family's local prefixes --
// conditions on one field are alternatives in the engine
func (f family) localMatches() []*wf.Match {
	out := make([]*wf.Match, len(f.local))
	for i, p := range f.local {
		out[i] = &wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: p}
	}
	return out
}

// uplinkMatches: the adapter is any of the types a packet leaves by
func uplinkMatches() []*wf.Match {
	out := make([]*wf.Match, len(uplinkTypes))
	for i, t := range uplinkTypes {
		out[i] = &wf.Match{Field: wf.FieldInterfaceType, Op: wf.MatchTypeEqual, Value: t}
	}
	return out
}
