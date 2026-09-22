package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
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
func physicalNetwork() bool {
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
	iphlpapi          = windows.NewLazySystemDLL("iphlpapi.dll")
	pNotifyAddrChange = iphlpapi.NewProc("NotifyAddrChange")
)

// watchNetworkChanges signals when interface addresses change: Wi-Fi
// connected, network switched, cable unplugged. No reason to wait for the
// regular poll in such moments -- check right away.
func watchNetworkChanges(ctx context.Context, notify func()) {
	for {
		if ctx.Err() != nil {
			return
		}
		var handle windows.Handle
		var ov windows.Overlapped
		ev, err := windows.CreateEvent(nil, 1, 0, nil)
		if err != nil {
			time.Sleep(10 * time.Second)
			continue
		}
		ov.HEvent = ev

		r, _, _ := pNotifyAddrChange.Call(
			uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(&ov)))
		// ERROR_IO_PENDING is the normal path: the notification comes later
		if r != uintptr(syscall.ERROR_IO_PENDING) && r != 0 {
			windows.CloseHandle(ev)
			time.Sleep(10 * time.Second)
			continue
		}

		// wait for the event, but no longer than a minute -- otherwise a
		// context cancel would not wake us until the next address change
		res, _ := windows.WaitForSingleObject(ev, 60000)
		windows.CloseHandle(ev)
		if ctx.Err() != nil {
			return
		}
		if res == windows.WAIT_OBJECT_0 {
			notify()
		}
	}
}

// --- tunnel liveness check ---

type healthChecker struct {
	apiAddr string
	secret  string
	proxy   string
	client  *http.Client
}

func newHealthChecker(apiAddr, secret, proxy string) *healthChecker {
	return &healthChecker{
		apiAddr: apiAddr, secret: secret, proxy: proxy,
		client: &http.Client{Timeout: 12 * time.Second},
	}
}

// alive asks the core for a delay measured through the tunnel itself. This is
// an honest end-to-end check: TUN being up with a dead peer looks fine from
// the outside while traffic goes nowhere.
func (h *healthChecker) alive() (bool, string) {
	u := fmt.Sprintf("http://%s/proxies/%s/delay?timeout=5000&url=%s",
		h.apiAddr, url.PathEscape(h.proxy),
		url.QueryEscape("http://cp.cloudflare.com/generate_204"))
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

// TunnelAlive: a check from outside the service -- used by the tray,
// which has no access to the supervisor's state.
func TunnelAlive(apiAddr, secret, proxy string) (bool, string) {
	return newHealthChecker(apiAddr, secret, proxy).alive()
}

// foreignTunnel: whether SOMEONE ELSE's tunnel adapter is up.
//
// If another WireGuard client with the same key runs in parallel, the server
// keeps stealing the session: our tunnel drops, we restart the core, the
// session is stolen again -- round and round. A restart does not help here,
// it hurts, so in this situation we leave the core alone.
func foreignTunnel() (bool, string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false, ""
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := ifc.Name
		if name == "Meta" || strings.EqualFold(name, "Meta") {
			continue // our own
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok || n.IP.To4() == nil || tunRange.Contains(n.IP.To4()) {
				continue
			}
			// tunnel interfaces have no broadcast and no gateway:
			// a point-to-point sign, like WireGuard
			if ifc.Flags&net.FlagPointToPoint != 0 ||
				(ifc.Flags&net.FlagBroadcast == 0 && ifc.Flags&net.FlagMulticast == 0) {
				return true, name
			}
		}
	}
	return false, ""
}
