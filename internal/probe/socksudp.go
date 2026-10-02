package probe

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// SOCKS5 UDP ASSOCIATE. Needed because under TUN a plain UDP socket of the
// prober would be pulled into the tunnel, and the "direct" QUIC probe would
// measure the tunnel. The control TCP connection must live for the whole
// association: once it closes, the relay drops our session.
type udpConn struct {
	ctrl  net.Conn // control TCP connection, kept open
	relay *net.UDPConn
	to    *net.UDPAddr // mihomo relay address
	once  sync.Once
}

func (d Dialer) DialUDP() (*udpConn, error) {
	c, err := net.DialTimeout("tcp", d.Addr, d.Timeout)
	if err != nil {
		return nil, fmt.Errorf("socks connect: %w", err)
	}
	_ = c.SetDeadline(time.Now().Add(d.Timeout))
	if err := d.greet(c); err != nil {
		c.Close()
		return nil, err
	}

	// the socket datagrams go from, made first, on the address the control
	// connection comes from: a listener with users takes UDP only from the
	// port an association names (DPI Switch's core, listener/socks/assoc.go)
	var local net.IP
	if a, ok := c.LocalAddr().(*net.TCPAddr); ok {
		local = a.IP
	}
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: local})
	if err != nil {
		c.Close()
		return nil, err
	}
	fail := func(err error) (*udpConn, error) {
		uc.Close()
		c.Close()
		return nil, err
	}

	// CMD=3 (UDP ASSOCIATE), naming the port; the relay answers with the
	// address to send datagrams to
	from := uc.LocalAddr().(*net.UDPAddr).Port
	req := []byte{5, 3, 0, 1, 0, 0, 0, 0, byte(from >> 8), byte(from)}
	if _, err := c.Write(req); err != nil {
		return fail(fmt.Errorf("socks udp associate: %w", err))
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return fail(fmt.Errorf("socks associate reply: %w", err))
	}
	if head[1] != 0 {
		return fail(fmt.Errorf("socks udp refused: %s", socksErr(head[1])))
	}

	var host string
	switch head[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return fail(err)
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return fail(err)
		}
		host = net.IP(b).String()
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return fail(err)
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(c, b); err != nil {
			return fail(err)
		}
		host = string(b)
	default:
		return fail(fmt.Errorf("socks bad atyp %d", head[3]))
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return fail(err)
	}
	port := int(pb[0])<<8 | int(pb[1])

	// the relay may call itself 0.0.0.0 -- then send to wherever
	// the TCP connection went
	if host == "0.0.0.0" || host == "::" {
		h, _, _ := net.SplitHostPort(d.Addr)
		host = h
	}
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return fail(err)
	}
	_ = c.SetDeadline(time.Time{})
	return &udpConn{ctrl: c, relay: uc, to: raddr}, nil
}

// below: a net.PacketConn implementation on top of the relay, so it can
// be handed to quic-go as a regular socket

func (u *udpConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("*net.UDPAddr required")
	}
	ip4 := ua.IP.To4()
	var hdr []byte
	if ip4 != nil {
		hdr = append([]byte{0, 0, 0, 1}, ip4...)
	} else {
		hdr = append([]byte{0, 0, 0, 4}, ua.IP.To16()...)
	}
	hdr = append(hdr, byte(ua.Port>>8), byte(ua.Port))
	if _, err := u.relay.WriteToUDP(append(hdr, p...), u.to); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (u *udpConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, len(p)+262) // headroom for the SOCKS header
	n, _, err := u.relay.ReadFromUDP(buf)
	if err != nil {
		return 0, nil, err
	}
	if n < 10 {
		return 0, nil, errors.New("datagram too short")
	}
	// RSV(2) FRAG(1) ATYP(1) ADDR PORT DATA
	var off int
	var ip net.IP
	switch buf[3] {
	case 1:
		if n < 10 {
			return 0, nil, errors.New("short ipv4 header")
		}
		ip = net.IP(buf[4:8])
		off = 8
	case 4:
		if n < 22 {
			return 0, nil, errors.New("short ipv6 header")
		}
		ip = net.IP(buf[4:20])
		off = 20
	case 3:
		l := int(buf[4])
		if n < 5+l+2 {
			return 0, nil, errors.New("short domain header")
		}
		off = 5 + l
	default:
		return 0, nil, fmt.Errorf("unknown atyp %d", buf[3])
	}
	port := int(buf[off])<<8 | int(buf[off+1])
	off += 2
	copied := copy(p, buf[off:n])
	return copied, &net.UDPAddr{IP: ip, Port: port}, nil
}

func (u *udpConn) Close() error {
	u.once.Do(func() {
		u.relay.Close()
		u.ctrl.Close() // closing the control connection tears down the association
	})
	return nil
}

// quic-go checks for these methods; without them it logs a buffer-size
// warning on every call
func (u *udpConn) SetReadBuffer(n int) error  { return u.relay.SetReadBuffer(n) }
func (u *udpConn) SetWriteBuffer(n int) error { return u.relay.SetWriteBuffer(n) }

func (u *udpConn) LocalAddr() net.Addr                { return u.relay.LocalAddr() }
func (u *udpConn) SetDeadline(t time.Time) error      { return u.relay.SetDeadline(t) }
func (u *udpConn) SetReadDeadline(t time.Time) error  { return u.relay.SetReadDeadline(t) }
func (u *udpConn) SetWriteDeadline(t time.Time) error { return u.relay.SetWriteDeadline(t) }
