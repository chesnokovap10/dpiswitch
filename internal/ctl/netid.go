package ctl

import (
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
// while the tray status refreshes every few seconds. A network change is
// not lost within half a minute -- the controller cycle is longer.
func networkID() string {
	netIDMu.Lock()
	defer netIDMu.Unlock()
	if netIDVal != "" && time.Since(netIDWhen) < 30*time.Second {
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
