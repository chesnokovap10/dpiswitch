package probe

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// Minimal SOCKS5 CONNECT. A raw net.Conn is required: we run TLS
// ourselves to see the certificate and the exact failure mode.
type Dialer struct {
	Addr    string // mihomo listener address
	Timeout time.Duration
	// resolvers for this path: the same the core uses. Empty -- built-in DoH
	DNS []Resolver
}

// Alive: whether the core's listener itself accepts connections (not the site behind it)
func (d Dialer) Alive() bool {
	c, err := net.DialTimeout("tcp", d.Addr, time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func (d Dialer) dial(host string, port int) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", d.Addr, d.Timeout)
	if err != nil {
		return nil, fmt.Errorf("socks connect: %w", err)
	}
	_ = c.SetDeadline(time.Now().Add(d.Timeout))

	// greeting: version 5, one method -- no authentication
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		c.Close()
		return nil, fmt.Errorf("socks greeting: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		c.Close()
		return nil, fmt.Errorf("socks greeting reply: %w", err)
	}
	if resp[0] != 5 || resp[1] != 0 {
		c.Close()
		return nil, fmt.Errorf("socks method rejected: %v", resp)
	}

	// CONNECT by host name: resolution is left to mihomo so the path
	// matches the one real traffic will take
	if len(host) > 255 {
		c.Close()
		return nil, errors.New("hostname too long for socks5")
	}
	// an IP literal is sent as an address (types 1 and 4), not as a name:
	// the core is not obliged to recognise "fd7a::" as IPv6 in the name field
	var req []byte
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append([]byte{5, 1, 0, 1}, v4...)
		} else {
			req = append([]byte{5, 1, 0, 4}, ip.To16()...)
		}
	} else {
		req = append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, fmt.Errorf("socks request: %w", err)
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		c.Close()
		return nil, fmt.Errorf("socks reply: %w", err)
	}
	if head[1] != 0 {
		c.Close()
		return nil, fmt.Errorf("socks refused: %s", socksErr(head[1]))
	}
	// drain BND.ADDR: we don't need it, but it must not stay in the stream
	var skip int
	switch head[3] {
	case 1:
		skip = 4
	case 4:
		skip = 16
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			c.Close()
			return nil, err
		}
		skip = int(l[0])
	default:
		c.Close()
		return nil, fmt.Errorf("socks bad atyp %d", head[3])
	}
	if _, err := io.ReadFull(c, make([]byte, skip+2)); err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

func socksErr(code byte) string {
	switch code {
	case 1:
		return "general failure"
	case 2:
		return "not allowed"
	case 3:
		return "network unreachable"
	case 4:
		return "host unreachable"
	case 5:
		return "connection refused"
	case 6:
		return "ttl expired"
	case 7:
		return "command not supported"
	case 8:
		return "address type not supported"
	}
	return "code " + strconv.Itoa(int(code))
}
