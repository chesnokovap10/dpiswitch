//go:build routing

package awgconf

import (
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
)

// TestCoreSpeed: the WireGuard outbound's own speed, both ways, through a
// peer on this machine (tools/wgpeer) -- no network in the way, so two cores
// compare on what they do themselves. Only with DPISWITCH_SPEED set:
//
//	DPISWITCH_SPEED=1 DPISWITCH_CORE=<core> go test -tags routing -run TestCoreSpeed -v ./internal/awgconf
func TestCoreSpeed(t *testing.T) {
	if os.Getenv("DPISWITCH_SPEED") == "" {
		t.Skip("DPISWITCH_SPEED not set")
	}
	core := coreBinary(t)
	peer := buildPeer(t)
	setupRouting(t, ctl.ModeOn, "awg1")
	cPriv, cPub := wgKeys(t)
	sPriv, sPub := wgKeys(t)
	port := startPeer(t, peer, sPriv, cPub)
	conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.8.1.3/32\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:%d\n", b64(cPriv), b64(sPub), port)
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
	socks, api := freePort(t), freePort(t)
	ls := fmt.Sprintf("listeners:\n  - name: in-awg\n    type: socks\n    listen: 127.0.0.1\n    port: %d\n    proxy: awg\n", socks)
	startCore(t, core, coreSafe(t, out, ls, api, freePort(t)), api)

	const size = 200 << 20
	for round := 1; round <= 3; round++ {
		up := speed(t, socks, 9, func(c net.Conn) (int64, error) {
			return io.CopyN(c, zeroReader{}, size)
		})
		down := speed(t, socks, 19, func(c net.Conn) (int64, error) {
			return io.CopyN(io.Discard, c, size)
		})
		t.Logf("round %d: up %.0f Mbit/s, down %.0f Mbit/s", round, up, down)
	}
}

// speed: Mbit/s of move over a connection to the peer's port, through the
// SOCKS listener on socksPort
func speed(t *testing.T, socksPort, port int, move func(net.Conn) (int64, error)) float64 {
	t.Helper()
	c, err := socksConnect(socksPort, [4]byte{203, 0, 113, 9}, port)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	n, err := move(c)
	if err != nil {
		t.Fatalf("after %d bytes: %v", n, err)
	}
	return float64(n) * 8 / 1e6 / time.Since(start).Seconds()
}

// socksConnect: a SOCKS5 CONNECT to ip:port, the connection kept open
func socksConnect(socksPort int, ip [4]byte, port int) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 2*time.Second)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err == nil {
		_, err = io.ReadFull(c, make([]byte, 2))
	}
	if err == nil {
		_, err = c.Write([]byte{5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)})
	}
	rep := make([]byte, 10)
	if err == nil {
		_, err = io.ReadFull(c, rep)
	}
	if err == nil && rep[1] != 0 {
		err = fmt.Errorf("socks reply %d", rep[1])
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	c.SetDeadline(time.Now().Add(2 * time.Minute))
	return c, nil
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
