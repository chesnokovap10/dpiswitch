//go:build routing

package awgconf

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
)

// TestCoreAAAA asks the real core, on the config as the settings make it,
// what it answers a program asking for a name's IPv6 address -- with IPv6
// through the tunnel on in the settings, and off. On, the answer is a
// stand-in address the TUN adapter takes. Off, the adapter has no IPv6 at
// all: a real address answered then is one the program dials past the core,
// out of the physical adapter, wherever the network has IPv6 of its own.
//
// With IPv6 off the config has the core's DNS give no AAAA and names no
// stand-in range: the core answers AAAA with no address at all (10.10, core
// 8067c742), and the program takes IPv4. The adapter takes IPv6 all the
// same, and a connection made to an IPv6 address -- learnt past the core's
// DNS -- is refused by the rules, not let out past the tunnel. Both are the
// core's behaviour on that config -- this is what holds it to it.
//
//	go test -tags routing -run TestCoreAAAA -v ./internal/awgconf
func TestCoreAAAA(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the core")
	}
	core := coreBinary(t)
	const name = "www.google.com" // has both A and AAAA
	for _, v6 := range []bool{true, false} {
		t.Run(fmt.Sprintf("ipv6=%v", v6), func(t *testing.T) {
			setupRouting(t, ctl.ModeOn, "awg1")
			if _, err := ctl.UpdateSettings(paths.Settings(), func(s *ctl.Settings) error { s.IPv6 = v6; return nil }); err != nil {
				t.Fatal(err)
			}
			// keys the core takes; the endpoint is a TEST-NET address nothing
			// answers on -- the tunnel's state is not what is asked here
			key := func(b byte) string { return strings.Repeat("A", 42) + string(b) + "=" }
			conf := "[Interface]\nPrivateKey = " + key('E') + "\nAddress = 10.8.1.3/32\n[Peer]\nPublicKey = " + key('I') + "\nEndpoint = 198.51.100.7:51820\n"
			if err := os.WriteFile(paths.SourceConf(), []byte(conf), 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := ParseFile(paths.SourceConf())
			if err != nil {
				t.Fatal(err)
			}
			out, err := c.Render()
			if err != nil {
				t.Fatal(err)
			}
			api, dns := freePort(t), freePort(t)
			socks := freePort(t)
			ls := fmt.Sprintf("listeners:\n  - name: in\n    type: socks\n    listen: 127.0.0.1\n    port: %d\n", socks)
			_, log := startCore(t, core, coreSafe(t, out, ls, api, dns), api)

			a, rcA, err := askCore(dns, name, 1)
			if err != nil {
				t.Fatalf("A: %v", err)
			}
			aaaa, rc6, err := askCore(dns, name, 28)
			if err != nil {
				t.Fatalf("AAAA: %v", err)
			}
			t.Logf("IPv6 %v in the settings: A rcode %d %v; AAAA rcode %d %v", v6, rcA, a, rc6, aaaa)
			standIn4, standIn6 := mustNet("198.18.0.0/16"), mustNet("2001:2::/48")
			for _, ip := range a {
				if !standIn4.Contains(ip) {
					t.Errorf("A answered with %s, not a stand-in address", ip)
				}
			}
			for _, ip := range aaaa {
				switch {
				case v6 && !standIn6.Contains(ip):
					t.Errorf("IPv6 on: AAAA answered with %s, not a stand-in address", ip)
				case !v6:
					t.Errorf("IPv6 off: AAAA answered with %s -- the adapter has no IPv6, a program dials it past the core", ip)
				}
			}
			if v6 && len(aaaa) == 0 {
				t.Error("IPv6 on: no AAAA answer")
			}
			// and an address dialled as it is, through the rules: refused with
			// IPv6 off, the rules' to route with it on
			const literal = "2001:db8::1"
			dialV6(socks, literal, 80)
			refused := false
			for end := time.Now().Add(5 * time.Second); time.Now().Before(end) && !refused; time.Sleep(100 * time.Millisecond) {
				for _, l := range strings.Split(log.String(), "\n") {
					refused = refused || strings.Contains(l, literal) && strings.Contains(l, "using REJECT")
				}
				if v6 && strings.Contains(log.String(), literal) {
					break
				}
			}
			if refused == v6 {
				t.Errorf("IPv6 %v: a connection to an IPv6 address refused by the rules %v", v6, refused)
			}
		})
	}
}

func mustNet(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// askCore: the addresses the core's DNS listener answers a query of the type
// given with, and the answer's rcode
func askCore(port int, name string, qtype uint16) ([]net.IP, int, error) {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0)
	q = binary.BigEndian.AppendUint16(q, qtype)
	q = binary.BigEndian.AppendUint16(q, 1)
	var lastErr error
	// the listener comes up a moment after the controller
	for try := 0; try < 10; try++ {
		c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return nil, 0, err
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Write(q)
		m := make([]byte, 4096)
		n, err := c.Read(m)
		c.Close()
		if err != nil {
			lastErr = err
			time.Sleep(300 * time.Millisecond)
			continue
		}
		m = m[:n]
		if n < 12 {
			return nil, 0, fmt.Errorf("short answer")
		}
		var ips []net.IP
		off := len(q) // the question comes back as asked
		for i := 0; i < int(binary.BigEndian.Uint16(m[6:])); i++ {
			// a record's name: a pointer, or labels to a zero
			for off < len(m) {
				if m[off]&0xc0 == 0xc0 {
					off += 2
					break
				}
				if m[off] == 0 {
					off++
					break
				}
				off += 1 + int(m[off])
			}
			if off+10 > len(m) {
				break
			}
			typ, rdl := binary.BigEndian.Uint16(m[off:]), int(binary.BigEndian.Uint16(m[off+8:]))
			off += 10
			if off+rdl > len(m) {
				break
			}
			if typ == qtype && (rdl == 4 || rdl == 16) {
				ips = append(ips, net.IP(append([]byte(nil), m[off:off+rdl]...)))
			}
			off += rdl
		}
		return ips, int(m[3] & 0x0f), nil
	}
	return nil, 0, lastErr
}

// dialV6: a SOCKS5 CONNECT to an IPv6 address through the listener on
// socksPort. The outcome does not matter: the core's log says where it went.
func dialV6(socksPort int, addr string, port int) {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 2*time.Second)
	if err != nil {
		return
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte{5, 1, 0})
	io.ReadFull(c, make([]byte, 2))
	req := append([]byte{5, 1, 0, 4}, net.ParseIP(addr).To16()...)
	c.Write(append(req, byte(port>>8), byte(port)))
	io.ReadFull(c, make([]byte, 10))
}
