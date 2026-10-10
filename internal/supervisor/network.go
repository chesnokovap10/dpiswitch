package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"dpiswitch/internal/awgconf"
	"dpiswitch/internal/paths"
)

// --- physical network presence ---

// fake-ip and the TUN address itself: the core's interface does not count
// as a network, otherwise the check would always pass
var tunRange = mustCIDR("198.18.0.0/15")

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// physicalNetwork: whether there is at least one working interface besides
// our TUN. After a reboot Wi-Fi comes up later than the service, and starting
// the core into the void is pointless -- it would only burn retries.
//
// IPv4, unless a tunnel's server is an IPv6 address: the question is
// whether the tunnels can come up. On a network with IPv6 alone a server
// reached over IPv4 cannot be, and "no network, waiting" is the right
// answer there -- counting a global IPv6 address instead would restart the
// core every minute and a half for a tunnel that has no way through. A
// server given by its IPv6 address can, and an IPv6 uplink counts then:
// with IPv6 alone the core never started.
//
// An interface counts only with a default route out through it: see
// hasUplink.
func physicalNetwork() bool {
	ads, err := adapters()
	if err == nil {
		var routes map[uint32]bool
		if routes, err = defaultRoutes4(); err == nil {
			if hasUplink(ads, routes) {
				return true
			}
			if endpointsV6() {
				if routes6, err := defaultRoutes6(); err == nil {
					return hasUplink6(ads, routes6)
				}
			}
			return false
		}
	}
	// the tables not read: an address, as before, rather than no core
	return anyAddress4()
}

// endpointsV6: whether a tunnel's server is given by an IPv6 address -- of
// the tunnels the config is built with: a second one switched off or left
// out (see awgconf.Second) brings nothing up
var endpointsV6 = func() bool {
	first, err := awgconf.ParseFile(paths.SourceConf())
	if err != nil {
		first = nil
	}
	if first != nil && endpointV6(first.Peer["Endpoint"]) {
		return true
	}
	c2, _ := awgconf.Second(first)
	return c2 != nil && endpointV6(c2.Peer["Endpoint"])
}

// endpointV6: an Endpoint whose host is an IPv6 address
func endpointV6(ep string) bool {
	host, _, err := net.SplitHostPort(ep)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() == nil
}

// anyAddress4: an IPv4 address besides the TUN's and link-local ones.
func anyAddress4() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := n.IP.To4()
			if ip == nil || tunRange.Contains(ip) {
				continue
			}
			// 169.254.x.x -- no DHCP lease: not connected yet
			if ip[0] == 169 && ip[1] == 254 {
				continue
			}
			return true
		}
	}
	return false
}

// --- network change notifications ---

var (
	iphlpapi              = windows.NewLazySystemDLL("iphlpapi.dll")
	pNotifyAddrChange     = iphlpapi.NewProc("NotifyAddrChange")
	pCancelIPChangeNotify = iphlpapi.NewProc("CancelIPChangeNotify")
)

// ctxPollMs: how often a wait for an address change looks at the context
var ctxPollMs uint32 = 60000

// abandoned: requests whose cancellation did not complete. The kernel may
// still write into their OVERLAPPED and signal their event, so both are kept
// for the life of the process.
var (
	abandonedMu sync.Mutex
	abandoned   []*windows.Overlapped
)

// watchNetworkChanges signals when interface addresses change: Wi-Fi
// connected, network switched, cable unplugged. No reason to wait for the
// regular poll in such moments -- check right away.
func watchNetworkChanges(ctx context.Context, notify func()) {
	for ctx.Err() == nil {
		fired, err := waitAddrChange(ctx)
		if err != nil {
			time.Sleep(10 * time.Second)
			continue
		}
		if fired {
			notify()
		}
	}
}

// waitAddrChange issues one request and waits until it completes or ctx ends.
//
// The kernel writes the request's status into its OVERLAPPED when it
// completes, however late that is, so the OVERLAPPED must outlive it. It used
// to be dropped after a minute's wait with the request still pending, and a
// new request issued: the GC reused the memory, and at the next address
// change every request left behind -- one per quiet minute -- zeroed bytes
// 0-3 and 8-15 of whatever lived there by then. Verdicts were saved with such
// holes in addresses, names and times.
func waitAddrChange(ctx context.Context) (bool, error) {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return false, err
	}
	ov := &windows.Overlapped{HEvent: ev}
	var handle windows.Handle // not to be closed, says the documentation
	r, _, _ := pNotifyAddrChange.Call(
		uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(ov)))
	// ERROR_IO_PENDING is the normal path: the notification comes later
	if r != uintptr(syscall.ERROR_IO_PENDING) && r != 0 {
		windows.CloseHandle(ev)
		return false, syscall.Errno(r)
	}
	for {
		// the same request is waited for across the polls: only the
		// context is looked at between them
		res, err := windows.WaitForSingleObject(ev, ctxPollMs)
		if res == windows.WAIT_OBJECT_0 {
			// completed: the kernel is done with ov
			runtime.KeepAlive(ov)
			windows.CloseHandle(ev)
			return ctx.Err() == nil, nil
		}
		if err != nil || ctx.Err() != nil {
			cancelAddrChange(ov)
			return false, err
		}
	}
}

// cancelAddrChange lets a pending request go only once the cancellation has
// landed in its OVERLAPPED; if it does not, the request is kept forever.
func cancelAddrChange(ov *windows.Overlapped) {
	pCancelIPChangeNotify.Call(uintptr(unsafe.Pointer(ov)))
	if res, _ := windows.WaitForSingleObject(ov.HEvent, 5000); res == windows.WAIT_OBJECT_0 {
		windows.CloseHandle(ov.HEvent)
		return
	}
	abandonedMu.Lock()
	abandoned = append(abandoned, ov)
	abandonedMu.Unlock()
}

// --- tunnel liveness check ---

type healthChecker struct {
	apiAddr string
	secret  string
	client  *http.Client
}

func newHealthChecker(apiAddr, secret string) *healthChecker {
	return &healthChecker{
		apiAddr: apiAddr, secret: secret,
		client: &http.Client{Timeout: 12 * time.Second},
	}
}

// check measures one proxy against one URL through the core's own API, so the
// path tested is the path traffic takes.
func (h *healthChecker) check(proxy, target string, timeoutMs int) (bool, string) {
	u := fmt.Sprintf("http://%s/proxies/%s/delay?timeout=%d&url=%s",
		h.apiAddr, url.PathEscape(proxy), timeoutMs,
		url.QueryEscape(target))
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return false, err.Error()
	}
	if h.secret != "" {
		req.Header.Set("Authorization", "Bearer "+h.secret)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		// the core itself is unreachable -- a separate problem, but cured the same way
		return false, "core API not responding: " + trim(err.Error())
	}
	defer resp.Body.Close()

	var body struct {
		Delay   int    `json:"delay"`
		Message string `json:"message"`
	}
	json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusOK || body.Delay == 0 {
		msg := body.Message
		if msg == "" {
			msg = resp.Status
		}
		return false, trim(msg)
	}
	return true, fmt.Sprintf("%d ms", body.Delay)
}

func trim(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 90 {
		return s[:90] + "…"
	}
	return s
}

// NetworkUp: whether a physical network exists. The UI uses it to tell
// "the tunnel is broken" from "there is no network at all".
func NetworkUp() bool { return physicalNetwork() }

// foreignTunnel: whether SOMEONE ELSE's WireGuard-type tunnel is up.
//
// If another WireGuard client with the same key runs in parallel, the server
// keeps stealing the session: our tunnel drops, we restart the core, the
// session is stolen again -- round and round. A restart does not help here,
// it hurts, so in this situation we leave the core alone.
//
// Such a client is told by its adapter's description (see foreignWG). Any
// point-to-point adapter used to count -- a mobile modem's, another kind of
// VPN's -- and with one up the tunnel's death never restarted the core.
func foreignTunnel() (bool, string) {
	ads, err := adapters()
	if err != nil {
		return false, ""
	}
	return foreignWG(ads)
}
