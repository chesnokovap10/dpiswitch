package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// dialDNSQUIC keeps DoQ and DoH3 on the chosen path, including hostname
// resolution at the SOCKS listener rather than through Windows DNS.
func (r Resolver) dialDNSQUIC(ctx context.Context, d Dialer, tc *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	limited := d
	if end, ok := ctx.Deadline(); ok {
		limited.Timeout = max(time.Millisecond, time.Until(end))
	}
	pc, err := limited.DialUDP()
	if err != nil {
		return nil, err
	}
	var packets net.PacketConn = pc
	target := &net.UDPAddr{IP: net.ParseIP(r.Host), Port: r.Port}
	if target.IP == nil {
		if d.Direct {
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", r.Host)
			if err != nil || len(ips) == 0 {
				pc.Close()
				return nil, fmt.Errorf("DNS QUIC bootstrap: %v", err)
			}
			target.IP = net.IP(ips[0].AsSlice())
		} else {
			// Resolve at the chosen SOCKS listener, never via Windows.
			// This address identifies the connection locally; no packet
			// is sent to it. Every write uses the resolver's host name.
			target.IP = net.IPv4(192, 0, 2, 1)
			packets = &namedDNSQUICConn{udpConn: pc, host: r.Host, target: target}
		}
	}
	qt := &quic.Transport{Conn: packets}
	conn, err := qt.Dial(ctx, target, tc, cfg)
	if err != nil {
		qt.Close()
		pc.Close()
		return nil, err
	}
	go func() { <-conn.Context().Done(); qt.Close(); pc.Close() }()
	return conn, nil
}

// One SOCKS association serves one hostname. QUIC sees a stable remote
// address while the relay resolves and forwards the real destination.
type namedDNSQUICConn struct {
	*udpConn
	host   string
	target *net.UDPAddr
}

func (c *namedDNSQUICConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.writeToName(p, c.host, c.target.Port)
}
func (c *namedDNSQUICConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, _, err := c.udpConn.ReadFrom(p)
	return n, c.target, err
}
