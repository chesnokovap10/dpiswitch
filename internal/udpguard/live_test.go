package udpguard

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

// The check against the real engine: the real filters, and datagrams sent
// out of the real adapter. The Windows Filtering Platform takes filters from
// an administrator alone, so it runs only when asked, from an elevated
// process (tools\udpguard-live.ps1 does all of it):
//
//	go test -c -o udpguard.test.exe ./internal/udpguard
//	set DPISWITCH_LIVE_WFP=1
//	udpguard.test.exe -test.run TestLive -test.v        (elevated)
//
// The filters are of a dynamic session, in this process: they go when it
// does, and the test lifts them itself before. Nothing but a datagram of one
// byte to addresses nothing answers is sent.
//
// A block gives the sender no error: the send goes through as if the packet
// were on its way, and the packet is dropped. What tells them apart is the
// engine's record of the packets it dropped, which a session of its own, kept
// open all through, reads here -- the record is the engine's, not the
// session's.

// uplink: the addresses of the adapter a program would bind to to leave
// around the tunnel
type uplink struct {
	name   string
	luid   uint64
	v4, v6 netip.Addr
}

// findUplink: the first adapter of a cable or Wi-Fi type that is up, has a
// gateway and an address a network gave it
func findUplink(t *testing.T) uplink {
	t.Helper()
	size := uint32(32 << 10)
	for try := 0; try < 4; try++ {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER|windows.GAA_FLAG_INCLUDE_GATEWAYS,
			0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for a := first; a != nil; a = a.Next {
			if a.OperStatus != windows.IfOperStatusUp || a.FirstGatewayAddress == nil ||
				(a.IfType != ifEthernet && a.IfType != ifWiFi) {
				continue
			}
			u := uplink{name: windows.UTF16PtrToString(a.FriendlyName), luid: a.Luid}
			for ua := a.FirstUnicastAddress; ua != nil; ua = ua.Next {
				ip, ok := netip.AddrFromSlice(ua.Address.IP())
				if !ok {
					continue
				}
				ip = ip.Unmap()
				switch {
				case ip.Is4() && !u.v4.IsValid() && !ip.IsLinkLocalUnicast():
					u.v4 = ip
				case ip.Is6() && !u.v6.IsValid() && ip.IsGlobalUnicast():
					u.v6 = ip
				}
			}
			if u.v4.IsValid() {
				runtime.KeepAlive(buf)
				return u
			}
		}
		runtime.KeepAlive(buf)
		break
	}
	t.Skip("no cable or Wi-Fi adapter with a gateway and an IPv4 address")
	return uplink{}
}

// flow: a datagram sent, as the engine will have it recorded
type flow struct{ local, remote netip.AddrPort }

// send: one byte, from src (any address when invalid) to dst:port, on a
// socket connected to it; an interface name for a link-local destination's scope
func send(src, dst netip.Addr, port int, zone string) (flow, error) {
	network := "udp4"
	if dst.Is6() {
		network = "udp6"
	}
	var laddr *net.UDPAddr
	if src.IsValid() {
		laddr = &net.UDPAddr{IP: src.AsSlice()}
	}
	c, err := net.DialUDP(network, laddr, &net.UDPAddr{IP: dst.AsSlice(), Port: port, Zone: zone})
	if err != nil {
		return flow{}, err
	}
	defer c.Close()
	f := flow{local: c.LocalAddr().(*net.UDPAddr).AddrPort(), remote: netip.AddrPortFrom(dst, uint16(port))}
	_, err = c.Write([]byte{0})
	return f, err
}

// sendUnconnected: the same on a socket that is not connected, as a program
// sending to many addresses does
func sendUnconnected(src, dst netip.Addr, port int) (flow, error) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: src.AsSlice()})
	if err != nil {
		return flow{}, err
	}
	defer c.Close()
	f := flow{local: c.LocalAddr().(*net.UDPAddr).AddrPort(), remote: netip.AddrPortFrom(dst, uint16(port))}
	_, err = c.WriteToUDP([]byte{0}, &net.UDPAddr{IP: dst.AsSlice(), Port: port})
	return f, err
}

type liveProbe struct {
	name string
	send func() (flow, error)
	// guarded: whether the guard, with the core another program, drops it
	guarded bool
}

// liveCore: the core the service really runs, so that the tunnel's own
// packets go on while the guard of this check is in -- else cmd.exe, a
// program that is none of the test's
func liveCore() string {
	for _, p := range []string{
		filepath.Join(os.Getenv("ProgramFiles"), "DPI Switch", "core", "mihomo.exe"),
		filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"),
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func gateLive(t *testing.T) {
	t.Helper()
	if os.Getenv("DPISWITCH_LIVE_WFP") != "1" {
		t.Skip("puts real filters into the engine: set DPISWITCH_LIVE_WFP=1, and run elevated")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("the engine takes filters from an administrator: run elevated")
	}
}

func TestLive(t *testing.T) {
	gateLive(t)
	up := findUplink(t)
	t.Logf("adapter %q: IPv4 %v, IPv6 %v", up.name, up.v4, up.v6)
	core := liveCore()
	if core == "" {
		t.Skip("no program to stand in for the core")
	}
	t.Logf("the core let through: %s", core)

	a := netip.MustParseAddr
	probes := []liveProbe{
		{"IPv4 bound to the adapter -> a public address", func() (flow, error) { return send(up.v4, a("192.0.2.1"), 9, "") }, true},
		{"IPv4 bound, not connected -> a public address", func() (flow, error) { return sendUnconnected(up.v4, a("192.0.2.2"), 9) }, true},
		{"IPv4 bound to the adapter -> a public DNS port", func() (flow, error) { return send(up.v4, a("192.0.2.1"), 53, "") }, true},
		{"IPv4 bound to the adapter -> a private address", func() (flow, error) { return send(up.v4, a("10.255.255.1"), 9, "") }, false},
		{"IPv4 bound to the adapter -> a multicast group", func() (flow, error) { return send(up.v4, a("239.255.77.77"), 9, "") }, false},
		{"IPv4 bound to the adapter -> a public address, DHCP's port", func() (flow, error) { return send(up.v4, a("192.0.2.1"), 67, "") }, true},
	}
	if meta, err := net.InterfaceByName("Meta"); err == nil && meta.Flags&net.FlagUp != 0 {
		probes = append(probes, liveProbe{"IPv4 unbound -> a public address, into the TUN",
			func() (flow, error) { return send(netip.Addr{}, a("192.0.2.1"), 9, "") }, false})
	} else {
		t.Log("no TUN adapter up: the unbound probe is left out")
	}
	if up.v6.IsValid() {
		probes = append(probes,
			liveProbe{"IPv6 bound to the adapter -> a public address", func() (flow, error) { return send(up.v6, a("2001:db8::1"), 9, "") }, true},
			liveProbe{"IPv6 bound to the adapter -> a unique local address", func() (flow, error) { return send(up.v6, a("fd00::1"), 9, "") }, false},
			liveProbe{"IPv6 bound to the adapter -> a link-local multicast group", func() (flow, error) { return send(up.v6, a("ff02::77:77"), 9, up.name) }, false},
			liveProbe{"IPv6 bound to the adapter -> a public address, DHCPv6's port", func() (flow, error) { return send(up.v6, a("2001:db8::1"), 547, "") }, true},
		)
	} else {
		t.Log("no global IPv6 address on the adapter: IPv6 is left out")
	}

	// the engine's record, read through a session of its own
	spec, err := wf.New(&wf.Options{Name: "udpguard live check: the record", Dynamic: true})
	if err != nil {
		t.Fatal(err)
	}
	defer spec.Close()

	// round: every probe sent, and then asked of the record, which wants
	// moments to have the drop in it -- a packet expected dropped is waited
	// for, one expected through is asked after a pause
	round := func(label string, wantDropped func(liveProbe) bool) {
		t.Helper()
		since := time.Now().Add(-time.Second)
		flows := make([]flow, len(probes))
		sent := make([]error, len(probes))
		for i, p := range probes {
			flows[i], sent[i] = p.send()
		}
		time.Sleep(400 * time.Millisecond)
		for i, p := range probes {
			if sent[i] != nil {
				t.Errorf("%s: %s: the send failed, and a block gives no error: %v", label, p.name, sent[i])
				continue
			}
			got := sessionSawDrop(spec, flows[i].local, flows[i].remote, since)
			for wait := 0; wantDropped(p) && !got && wait < 20; wait++ {
				time.Sleep(100 * time.Millisecond)
				got = sessionSawDrop(spec, flows[i].local, flows[i].remote, since)
			}
			t.Logf("%s: %-62s %s", label, p.name, map[bool]string{true: "DROPPED", false: "through"}[got])
			if got != wantDropped(p) {
				t.Errorf("%s: %s: dropped %v, want %v", label, p.name, got, wantDropped(p))
			}
		}
	}

	// 1: before -- none of them is dropped; one that is says another
	// program's filter is in the way, and the rest of this check with it.
	// But with the service's own guard in the engine: then it is that guard
	// the first round looks at -- what the machine is guarded by now, the
	// build installed -- and this check's guard goes in beside it, under
	// keys of its own: the engine refuses the same ones twice. A packet
	// either of them blocks is dropped, so the round after shows this
	// build's rules wherever they are the stricter.
	service := Present()
	if service {
		t.Log("the service's guard is in the engine: the first round is its own")
		round("service", func(p liveProbe) bool { return p.guarded })
	} else {
		round("before", func(liveProbe) bool { return false })
	}

	// 2: the guard in, the core another program
	guardSince := time.Now()
	g := New()
	if service {
		g.open = func(p plan) (engine, error) { return openWFP(besideKeys(p)) }
	}
	defer g.Lift()
	ch, err := g.Ensure(core)
	if err != nil || ch != Put {
		t.Fatalf("Ensure: %v, %v", ch, err)
	}
	t.Logf("the guard is in: %d filters", g.Rules())
	round("guard", func(p liveProbe) bool { return p.guarded })

	// the core the service really runs is let through: with the guard in, not
	// one of its packets is in the engine's record of drops. The whole point --
	// a permit that did not match it would cut the tunnel's own packets off.
	if strings.EqualFold(filepath.Base(core), "mihomo.exe") {
		own, all := 0, 0
		if evs, err := spec.DropEvents(); err == nil {
			for _, ev := range evs {
				if ev.IPProtocol != 17 || ev.Timestamp.Before(guardSince) {
					continue
				}
				all++
				if strings.HasSuffix(strings.ToLower(ev.AppID), `\core\mihomo.exe`) {
					own++
					t.Logf("the core's packet dropped: %v -> %v, %s", ev.LocalAddr, ev.RemoteAddr, ev.AppID)
				}
			}
		}
		if own > 0 {
			t.Errorf("%d packets of the core dropped with the guard in: its permit does not match it", own)
		}
		t.Logf("the core's packets dropped with the guard in: %d (of %d dropped since)", own, all)
	}

	// the guard looks at itself with the engine's own answer, and reads the
	// engine's record of what it dropped, as the service does to check it
	if ch, err := g.Ensure(core); err != nil || ch != Kept {
		t.Errorf("the second Ensure: %v, %v: the guard in place was not found", ch, err)
	}
	since := time.Now().Add(-time.Second)
	f, err := send(up.v4, a("192.0.2.1"), 9, "")
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for i := 0; i < 20 && !seen; i++ {
		time.Sleep(100 * time.Millisecond)
		seen = g.Dropped(f.local, f.remote, since)
	}
	if !seen {
		t.Error("Guard.Dropped does not see the packet the guard dropped")
	}
	if g.Dropped(netip.AddrPortFrom(up.v4, 1), f.remote, since) {
		t.Error("Guard.Dropped sees a packet nobody sent")
	}

	if service {
		// the rest is of a machine with no other guard: nothing dropped with
		// the core this program, nothing with the guard lifted
		g.Lift()
		t.Log("the service's guard stays in: the rounds with no guard are left out")
		return
	}

	// 3: with this very program the core, nothing of it is dropped
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if ch, err := g.Ensure(self); err != nil || ch != Replaced {
		t.Fatalf("Ensure for another core: %v, %v", ch, err)
	}
	round("core is us", func(liveProbe) bool { return false })

	// 4: lifted, nothing is dropped
	if !g.Lift() {
		t.Fatal("Lift found nothing to lift")
	}
	round("lifted", func(liveProbe) bool { return false })

	// 5: put in again after a lift
	if ch, err := g.Ensure(core); err != nil || ch != Put {
		t.Fatalf("Ensure after a lift: %v, %v", ch, err)
	}
	round("put again", func(p liveProbe) bool { return p.guarded })
}

// besideKeys: the plan under keys of its own, to stand in the engine beside
// the service's guard
func besideKeys(p plan) plan {
	p.provider.ID.Data1++
	p.sublayer.ID.Data1++
	p.sublayer.Provider = p.provider.ID
	for _, r := range p.rules {
		r.ID.Data1 += 0x1000
		r.Sublayer, r.Provider = p.sublayer.ID, p.provider.ID
	}
	return p
}

func describe(err error) string {
	if err == nil {
		return "sent"
	}
	return fmt.Sprintf("failed: %v", err)
}
