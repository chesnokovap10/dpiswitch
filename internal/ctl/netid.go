package ctl

import (
	"context"
	"dpiswitch/internal/winexec"
	"sync"
	"sync/atomic"
	"time"

	"crypto/sha256"
	"encoding/hex"
	"net"
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
	if gw := defaultGateway(); gw != "" {
		parts := []string{"gw=" + gw}
		if mac := arpMAC(gw); mac != "" {
			// tells apart different networks with the same 192.168.1.x
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
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok || n.IP.To4() == nil {
				continue
			}
			// skip mihomo's own TUN: otherwise the id depends on whether the
			// tunnel is up, and memory splits in two for one physical network
			if fakeIPRange.Contains(n.IP) {
				continue
			}
			out = append(out, "net="+n.String())
		}
	}
	return out
}

// localLink: the adapters up and their IPv4 addresses, as one string -- what
// this machine sees of its network without asking anyone. It is no network's
// identity (the ISP is, see resolveNetwork): it changes when the adapter
// does, another Wi-Fi is joined, DHCP hands out another address, and then
// the network is looked for at once. A switch of Wi-Fi or adapter was seen
// only when the gateway's cache ran out and a tick came, the public address
// only when its recheck was due (09.10: a minute). No process is started:
// it is asked every two seconds.
func localLink() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var out []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			// link-local ones say nothing of the network: Bluetooth's and
			// Wi-Fi Direct's adapters hold 169.254.x and come and go
			if !ok || n.IP.To4() == nil || fakeIPRange.Contains(n.IP) || n.IP.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, strconv.Itoa(ifc.Index)+"="+n.String())
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
