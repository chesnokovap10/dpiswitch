package supervisor

import (
	"net"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// adapter: what the network checks need to know of one interface.
type adapter struct {
	index uint32 // the IPv4 interface index routes refer to
	name  string // "Wi-Fi", "Meta"
	desc  string // the driver's description: "WireGuard Tunnel", "Meta Tunnel"
	up    bool
	v4    []net.IP
}

func adapters() ([]adapter, error) {
	size := uint32(16 << 10)
	for i := 0; i < 4; i++ {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER,
			0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil, err
		}
		var out []adapter
		for a := first; a != nil; a = a.Next {
			ad := adapter{
				index: a.IfIndex,
				name:  windows.UTF16PtrToString(a.FriendlyName),
				desc:  windows.UTF16PtrToString(a.Description),
				up:    a.OperStatus == windows.IfOperStatusUp,
			}
			for u := a.FirstUnicastAddress; u != nil; u = u.Next {
				if v4 := u.Address.IP().To4(); v4 != nil {
					ad.v4 = append(ad.v4, v4)
				}
			}
			out = append(out, ad)
		}
		runtime.KeepAlive(buf)
		return out, nil
	}
	return nil, windows.ERROR_BUFFER_OVERFLOW
}

// defaultRoutes4: the interfaces an IPv4 default route leaves by.
func defaultRoutes4() (map[uint32]bool, error) {
	var t *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &t); err != nil {
		return nil, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(t))
	out := map[uint32]bool{}
	for _, r := range t.Rows() {
		if r.DestinationPrefix.PrefixLength == 0 {
			out[r.InterfaceIndex] = true
		}
	}
	return out, nil
}

// ours: the core's own TUN adapter
func (a adapter) ours() bool {
	if strings.EqualFold(a.name, "Meta") {
		return true
	}
	for _, ip := range a.v4 {
		if tunRange.Contains(ip) {
			return true
		}
	}
	return false
}

// usable: an IPv4 address a network gave -- not a link-local one that
// means DHCP did not answer, nor loopback
func (a adapter) usable() bool {
	for _, ip := range a.v4 {
		if !(ip[0] == 169 && ip[1] == 254) && !ip.IsLoopback() && !tunRange.Contains(ip) {
			return true
		}
	}
	return false
}

// hasUplink: whether some interface leads out -- up, with an address a
// network gave it, and an IPv4 default route through it. An address alone
// used to be enough, and a WSL, Hyper-V or VirtualBox adapter -- up, with an
// address, going nowhere -- counted as a network: with Wi-Fi off the core
// was started into the void and restarted every minute and a half. A
// default route, not a gateway address: a mobile modem's route is on-link
// and names no gateway.
func hasUplink(ads []adapter, routes map[uint32]bool) bool {
	for _, a := range ads {
		if a.up && !a.ours() && routes[a.index] && a.usable() {
			return true
		}
	}
	return false
}

// wgKinds: words in the description of an adapter another WireGuard-type
// client brings up -- WireGuard itself, AmneziaWG and AmneziaVPN. Not the
// bare "wintun" of the driver they share: sing-box, Clash and other VPNs
// bring up Wintun adapters too, and with any of them up a dead tunnel was
// never restarted.
var wgKinds = []string{"wireguard", "amnezia"}

// foreignWG: an adapter of another WireGuard-type client that is up.
func foreignWG(ads []adapter) (bool, string) {
	for _, a := range ads {
		if !a.up || a.ours() {
			continue
		}
		d := strings.ToLower(a.desc)
		for _, k := range wgKinds {
			if strings.Contains(d, k) {
				return true, a.name
			}
		}
	}
	return false, ""
}
