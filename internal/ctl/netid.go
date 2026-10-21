package ctl

import (
	"context"
	"dpiswitch/internal/winexec"
	"sync"
	"sync/atomic"
	"time"

	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// noNetwork: the network id while there is none -- no gateway, no address.
// Nothing is filed under it: it is no network, and a start offline used to
// file verdicts there and apply them at a later start on whatever network
// that was.
const noNetwork = "unknown"

// fake-ip range from the mihomo config: 198.18.0.1/16
var _, fakeIPRange, _ = net.ParseCIDR("198.18.0.0/15")

// the core's own IPv6: its adapter's address (fdfe:dcba:9876::1/126) and the
// fake-ip range (2001:2::/48) -- see awgconf
var (
	_, tunRange6, _  = net.ParseCIDR("fdfe:dcba:9876::/48")
	_, fakeRange6, _ = net.ParseCIDR("2001:2::/48")
)

func ownV6(ip net.IP) bool { return tunRange6.Contains(ip) || fakeRange6.Contains(ip) }

// prefix64: an IPv6 address's network, no narrower than a /64. Windows
// gives a temporary address and a DHCPv6 one as /128 (17.10), and the
// temporary one is made anew every day: by its address the network would
// change with it.
func prefix64(n *net.IPNet) *net.IPNet {
	ones, bits := n.Mask.Size()
	if ones > 64 {
		ones = 64
	}
	m := net.CIDRMask(ones, bits)
	return &net.IPNet{IP: n.IP.Mask(m), Mask: m}
}

var (
	netIDMu   sync.Mutex
	netIDVal  string
	netIDWhen time.Time
)

// networkID is cached: it queries route and arp, i.e. spawns processes,
// while the tray status refreshes every few seconds. Five seconds: with half
// a minute a new Wi-Fi was taken for the old one that long (09.10, the UI
// slow to see a network change).
var netIDCache = 5 * time.Second

func networkID() string {
	netIDMu.Lock()
	defer netIDMu.Unlock()
	if netIDVal != "" && time.Since(netIDWhen) < netIDCache {
		return netIDVal
	}
	netIDVal = computeNetworkID()
	netIDWhen = time.Now()
	return netIDVal
}

func computeNetworkID() string {
	// The network identity is the gateway and its MAC, nothing else.
	//
	// It used to include the addresses of ALL interfaces, and any extra
	// adapter (Bluetooth with APIPA, another VPN's virtual adapter) counted
	// as a network change: accumulated verdicts were wiped at once.
	// Seen in practice -- 192 domains lost.
	//
	// Read from Windows' own tables. It was read off route.exe and arp.exe,
	// 60 ms and two processes a look (10.10) -- and a look is made at every
	// tick, and four for every name the fast lane probes: a page opening
	// with thirty new names started over a hundred processes. The programs
	// are asked only when the tables cannot be read.
	gw, ifIndex, ok := gatewayFromTable()
	if !ok {
		gw = defaultGateway()
	}
	if gw != "" {
		parts := []string{"gw=" + gw}
		mac, read := "", false
		if ok {
			mac, read = macFromTable(gw, ifIndex)
		}
		if !read {
			mac = arpMAC(gw)
		}
		if mac != "" {
			// tells apart different networks with the same 192.168.1.x
			parts = append(parts, "mac="+mac)
		}
		sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
		return hex.EncodeToString(sum[:])[:16]
	}

	// No IPv4 gateway: a network with IPv6 alone (a mobile one, NAT64) has
	// its router's link-local address and MAC to tell it by, as the IPv4
	// gateway does. It was taken for no network at all, and the detector
	// stood while the tunnel ran over IPv6 (the review of 17.10). A network
	// with both is told by its IPv4 gateway as before: memory filed under
	// that stays its own.
	if gw6, ifIndex, ok := gateway6FromTable(); ok && gw6 != "" {
		parts := []string{"gw6=" + gw6}
		if mac, _ := macFromTable6(gw6, ifIndex); mac != "" {
			parts = append(parts, "mac="+mac)
		}
		sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
		return hex.EncodeToString(sum[:])[:16]
	}

	// no gateway -- fall back to subnets, but only real ones:
	// APIPA means DHCP did not answer and the address is random
	nets := localNets()
	if len(nets) == 0 {
		return noNetwork
	}
	sort.Strings(nets)
	sum := sha256.Sum256([]byte(strings.Join(nets, "|")))
	return hex.EncodeToString(sum[:])[:16]
}

// parse by numeric fields, not headers: route output is localized
// fields: network, mask, gateway, interface, metric
var zeroRoute = regexp.MustCompile(`^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s+\S+\s+(\d+)`)

// defaultGateway: the gateway of the PHYSICAL network.
//
// There are two default routes: via the network card and via our TUN
// (198.18.0.2). The order of lines in route output is not guaranteed: after
// a Wi-Fi reconnect the TUN line came first, and our own tunnel was taken
// for a new network -- with an empty verdict memory. So TUN is dropped and
// the lowest metric among the rest wins.
func defaultGateway() string {
	out, err := winexec.Output(winexec.System32("route.exe"), "print", "-4", "0.0.0.0")
	if err != nil {
		return ""
	}
	return pickGateway(string(out))
}

func pickGateway(out string) string {
	best, bestMetric := "", -1
	for _, line := range strings.Split(out, "\n") {
		m := zeroRoute.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ip := net.ParseIP(m[1])
		if ip == nil || fakeIPRange.Contains(ip) {
			continue
		}
		metric, _ := strconv.Atoi(m[2])
		if bestMetric < 0 || metric < bestMetric {
			best, bestMetric = m[1], metric
		}
	}
	return best
}

// gatewayFromTable: defaultGateway off the routing table itself -- the IPv4
// default routes with a gateway, the TUN's left out, the lowest metric as
// route.exe shows it (the route's plus the interface's) -- and the interface
// it leaves by. ok false when the table cannot be read.
func gatewayFromTable() (gw string, ifIndex uint32, ok bool) {
	var t *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &t); err != nil {
		return "", 0, false
	}
	defer windows.FreeMibTable(unsafe.Pointer(t))
	best := -1
	for _, r := range t.Rows() {
		if r.DestinationPrefix.PrefixLength != 0 || r.NextHop.Family != windows.AF_INET {
			continue
		}
		a := (*windows.RawSockaddrInet4)(unsafe.Pointer(&r.NextHop)).Addr
		ip := net.IPv4(a[0], a[1], a[2], a[3])
		// no gateway: an on-link route, a mobile modem's -- route.exe says
		// "On-link" there, and it was never taken
		if ip.IsUnspecified() || fakeIPRange.Contains(ip) {
			continue
		}
		metric := int(r.Metric)
		ifc := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceIndex: r.InterfaceIndex}
		if windows.GetIpInterfaceEntry(&ifc) == nil {
			metric += int(ifc.Metric)
		}
		// two of one metric: the same one at every look, whatever order the
		// table gives them in -- the network's name hangs on it
		g := ip.String()
		if best < 0 || metric < best || metric == best &&
			(r.InterfaceIndex < ifIndex || r.InterfaceIndex == ifIndex && g < gw) {
			best, gw, ifIndex = metric, g, r.InterfaceIndex
		}
	}
	return gw, ifIndex, true
}

// gateway6FromTable: the IPv6 default route's gateway -- a router's
// link-local address, as routers advertise themselves -- with its zone, the
// lowest metric's, and the interface it leaves by. A next hop that is no
// link-local one is none a router gave: the core's own adapter routes by
// its ULA. ok false when the table cannot be read.
func gateway6FromTable() (gw string, ifIndex uint32, ok bool) {
	var t *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET6, &t); err != nil {
		return "", 0, false
	}
	defer windows.FreeMibTable(unsafe.Pointer(t))
	var rows []route6
	for _, r := range t.Rows() {
		if r.DestinationPrefix.PrefixLength != 0 || r.NextHop.Family != windows.AF_INET6 {
			continue
		}
		a := (*windows.RawSockaddrInet6)(unsafe.Pointer(&r.NextHop)).Addr
		metric := int(r.Metric)
		ifc := windows.MibIpInterfaceRow{Family: windows.AF_INET6, InterfaceIndex: r.InterfaceIndex}
		if windows.GetIpInterfaceEntry(&ifc) == nil {
			metric += int(ifc.Metric)
		}
		rows = append(rows, route6{net.IP(a[:]), r.InterfaceIndex, metric})
	}
	gw, ifIndex = pickGateway6(rows)
	return gw, ifIndex, true
}

// route6: an IPv6 default route as pickGateway6 weighs it
type route6 struct {
	hop    net.IP
	index  uint32
	metric int
}

// pickGateway6: the router's link-local next hop of the lowest metric, the
// same one at every look whatever order the table gives -- the network's
// name hangs on it
func pickGateway6(rows []route6) (gw string, ifIndex uint32) {
	best := -1
	for _, r := range rows {
		if !r.hop.IsLinkLocalUnicast() {
			continue
		}
		g := r.hop.String()
		if best < 0 || r.metric < best || r.metric == best &&
			(r.index < ifIndex || r.index == ifIndex && g < gw) {
			best, gw, ifIndex = r.metric, g, r.index
		}
	}
	return gw, ifIndex
}

// hasDirectV6: whether the direct path has IPv6 -- an adapter with a global
// IPv6 address and an IPv6 default route out by it. The core's own adapter
// has neither kind of address a network gave: its is a local one.
func hasDirectV6() bool {
	var t *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET6, &t); err != nil {
		return false
	}
	routed := map[int]bool{}
	for _, r := range t.Rows() {
		if r.DestinationPrefix.PrefixLength == 0 {
			routed[int(r.InterfaceIndex)] = true
		}
	}
	windows.FreeMibTable(unsafe.Pointer(t))
	ifaces, err := interfaces()
	if err != nil {
		return false
	}
	for _, ifc := range ifaces {
		if !ifc.up || !routed[int(ifc.index6)] && !routed[int(ifc.index)] {
			continue
		}
		for _, n := range ifc.nets {
			if n.IP.To4() == nil && n.IP.IsGlobalUnicast() && n.IP[0]&0xfe != 0xfc {
				return true
			}
		}
	}
	return false
}

// ifNet: an interface as the checks here read it
type ifNet struct {
	index, index6 uint32 // its IPv4 index (the IPv6 one with no IPv4), its IPv6 one
	up, loopback  bool
	nets          []*net.IPNet // its unicast addresses with their prefixes
}

// interfaces: the interfaces and their addresses, in one read of Windows'
// adapter table. net.Interfaces and an Addrs for each read the whole table
// once each: 4.7 ms a look on this machine (21.10), and localLink looks
// every two seconds -- one read is 1 ms. What it gives is what those give:
// the same index, up and loopback, and the addresses with their prefixes.
func interfaces() ([]ifNet, error) {
	size := uint32(16 << 10)
	for range 4 {
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
		var out []ifNet
		for a := first; a != nil; a = a.Next {
			f := ifNet{index: a.IfIndex, index6: a.Ipv6IfIndex, up: a.OperStatus == windows.IfOperStatusUp,
				loopback: a.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK}
			if f.index == 0 {
				f.index = f.index6
			}
			for u := a.FirstUnicastAddress; u != nil; u = u.Next {
				ip := u.Address.IP()
				if ip == nil {
					continue
				}
				bits := 8 * net.IPv6len
				if v4 := ip.To4(); v4 != nil {
					ip, bits = v4, 8*net.IPv4len
				}
				f.nets = append(f.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(int(u.OnLinkPrefixLength), bits)})
			}
			out = append(out, f)
		}
		runtime.KeepAlive(buf)
		return out, nil
	}
	return nil, windows.ERROR_BUFFER_OVERFLOW
}

var pGetIpNetTable2 = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetIpNetTable2")

// MIB_IPNET_TABLE2: the count, then the rows from offset 8; MIB_IPNET_ROW2
// is 88 bytes -- the address (SOCKADDR_INET) at 0, the interface's index at
// 28, the physical address at 40 and its length at 72
const (
	ipNetRows    = 8
	ipNetRowSize = 88
)

// macFromTable: arpMAC off the neighbour table itself -- the address ip has
// on the interface, written as arp.exe writes it; on another interface if
// not on that one. read false when the table cannot be read.
func macFromTable(ip string, ifIndex uint32) (mac string, read bool) {
	want := net.ParseIP(ip).To4()
	if want == nil || pGetIpNetTable2.Find() != nil {
		return "", false
	}
	var table unsafe.Pointer
	if r, _, _ := pGetIpNetTable2.Call(uintptr(windows.AF_INET), uintptr(unsafe.Pointer(&table))); r != 0 || table == nil {
		return "", false
	}
	defer windows.FreeMibTable(table)
	n := int(*(*uint32)(table))
	other := ""
	for i := 0; i < n; i++ {
		row := unsafe.Add(table, ipNetRows+i*ipNetRowSize)
		sa := (*windows.RawSockaddrInet4)(row)
		if sa.Family != windows.AF_INET || !want.Equal(net.IP(sa.Addr[:])) || *(*uint32)(unsafe.Add(row, 72)) != 6 {
			continue
		}
		hw := (*[6]byte)(unsafe.Add(row, 40))
		if *hw == ([6]byte{}) {
			continue // not answered yet
		}
		s := fmt.Sprintf("%02x-%02x-%02x-%02x-%02x-%02x", hw[0], hw[1], hw[2], hw[3], hw[4], hw[5])
		if *(*uint32)(unsafe.Add(row, 28)) == ifIndex {
			return s, true
		}
		if other == "" {
			other = s
		}
	}
	return other, true
}

// macFromTable6: macFromTable for an IPv6 neighbour -- the router's
// link-local address on the interface given, which is the only one it is
// known by there
func macFromTable6(ip string, ifIndex uint32) (mac string, read bool) {
	want := net.ParseIP(ip)
	if want == nil || want.To4() != nil || pGetIpNetTable2.Find() != nil {
		return "", false
	}
	var table unsafe.Pointer
	if r, _, _ := pGetIpNetTable2.Call(uintptr(windows.AF_INET6), uintptr(unsafe.Pointer(&table))); r != 0 || table == nil {
		return "", false
	}
	defer windows.FreeMibTable(table)
	n := int(*(*uint32)(table))
	for i := 0; i < n; i++ {
		row := unsafe.Add(table, ipNetRows+i*ipNetRowSize)
		sa := (*windows.RawSockaddrInet6)(row)
		if sa.Family != windows.AF_INET6 || !want.Equal(net.IP(sa.Addr[:])) ||
			*(*uint32)(unsafe.Add(row, 28)) != ifIndex || *(*uint32)(unsafe.Add(row, 72)) != 6 {
			continue
		}
		hw := (*[6]byte)(unsafe.Add(row, 40))
		if *hw == ([6]byte{}) {
			continue
		}
		return fmt.Sprintf("%02x-%02x-%02x-%02x-%02x-%02x", hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]), true
	}
	return "", true
}

var macRe = regexp.MustCompile(`([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}`)

func arpMAC(ip string) string {
	out, err := winexec.Output(winexec.System32("arp.exe"), "-a", ip)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, ip) {
			if m := macRe.FindString(line); m != "" {
				return strings.ToLower(m)
			}
		}
	}
	return ""
}

func localNets() []string {
	var out []string
	ifaces, err := interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifaces {
		if !ifc.up || ifc.loopback {
			continue
		}
		for _, n := range ifc.nets {
			if n.IP.IsLinkLocalUnicast() {
				continue
			}
			// skip mihomo's own TUN: otherwise the id depends on whether the
			// tunnel is up, and memory splits in two for one physical network
			if fakeIPRange.Contains(n.IP) || ownV6(n.IP) {
				continue
			}
			// an IPv6 network by its prefix: the address in it changes as
			// Windows makes a new temporary one
			if n.IP.To4() == nil {
				n = prefix64(n)
			}
			out = append(out, "net="+n.String())
		}
	}
	return out
}

// localLink: the adapters up and their addresses -- IPv4 ones, and IPv6 ones
// by their prefixes -- as one string -- what
// this machine sees of its network without asking anyone. It is no network's
// identity (the ISP is, see resolveNetwork): it changes when the adapter
// does, another Wi-Fi is joined, DHCP hands out another address, and then
// the network is looked for at once. A switch of Wi-Fi or adapter was seen
// only when the gateway's cache ran out and a tick came, the public address
// only when its recheck was due (09.10: a minute). No process is started:
// it is asked every two seconds.
func localLink() string {
	ifaces, err := interfaces()
	if err != nil {
		return ""
	}
	var out []string
	for _, ifc := range ifaces {
		if !ifc.up || ifc.loopback {
			continue
		}
		for _, n := range ifc.nets {
			// link-local ones say nothing of the network: Bluetooth's and
			// Wi-Fi Direct's adapters hold 169.254.x and come and go
			if fakeIPRange.Contains(n.IP) || ownV6(n.IP) || n.IP.IsLinkLocalUnicast() {
				continue
			}
			// IPv6 by its prefix: a new temporary address is no new network,
			// and on a network with IPv6 alone the prefix is all there is
			if n.IP.To4() == nil {
				n = prefix64(n)
			}
			out = append(out, strconv.Itoa(int(ifc.index))+"="+n.String())
		}
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

// the local link, and how often it is looked at; the tests script both
var (
	localLinkFn = localLink
	localPoll   = 2 * time.Second
)

// netForce: when the local link last changed, unix nanoseconds; zero once
// the network was found after it. Until then, for two minutes at most, a
// look asks the gateway and the public address anew, whatever their caches
// and backoffs say: with RIPE out of reach for good the backoffs hold again,
// and the cycles are not held up by lookups at every tick
var netForce atomic.Int64

const netForceFor = 2 * time.Minute

func netForced() bool {
	at := netForce.Load()
	return at != 0 && time.Since(time.Unix(0, at)) < netForceFor
}

// watchLocal wakes the main loop when the local link changes.
func watchLocal(ctx context.Context) {
	last := localLinkFn()
	t := time.NewTicker(localPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cur := localLinkFn()
		if cur == last {
			continue
		}
		last = cur
		netIDMu.Lock()
		netIDWhen = time.Time{}
		netIDMu.Unlock()
		netForce.Store(time.Now().UnixNano())
		select {
		case netWake <- struct{}{}:
		default:
		}
	}
}

// attachmentNow: the network the machine is attached to right now, not the
// cached networkID; the tests put a script in its place.
var attachmentNow = computeNetworkID

// netPoll: how often a cycle looks whether the network changed under it
var netPoll = 5 * time.Second

// netGuard watches the network through one cycle. The main loop looks for a
// new network only between cycles, and a cycle -- a few ports, a few
// attempts, an 8-second timeout each -- runs for minutes: after a switch
// from Wi-Fi A to B its probes went out through B, and their verdicts were
// filed under A, to be trusted there on the way back.
type netGuard struct {
	start string
	flag  atomic.Bool
	stop  chan struct{}
}

func guardNetwork() *netGuard {
	g := &netGuard{start: attachmentNow(), stop: make(chan struct{})}
	go func() {
		t := time.NewTicker(netPoll)
		defer t.Stop()
		for {
			select {
			case <-g.stop:
				return
			case <-t.C:
				if attachmentNow() != g.start {
					g.flag.Store(true)
					return
				}
			}
		}
	}()
	return g
}

// moved: the network was seen to change since the cycle began.
func (g *netGuard) moved() bool { return g.flag.Load() }

// done stops the watch and says whether the network stayed the same all
// through: the last look is made now, after the last probe finished.
func (g *netGuard) done() bool {
	close(g.stop)
	return !g.flag.Load() && attachmentNow() == g.start
}
