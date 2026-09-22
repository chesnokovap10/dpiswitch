package probe

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// SOCKS5 UDP ASSOCIATE. нужен, потому что под TUN обычный UDP-сокет
// пробника утянуло бы в туннель, и "прямая" проба QUIC меряла бы
// туннель. управляющее TCP-соединение обязано жить всё время
// ассоциации: закроется оно -- релей выбросит нашу сессию.
type udpConn struct {
	ctrl  net.Conn // управляющее TCP-соединение, держим открытым
	relay *net.UDPConn
	to    *net.UDPAddr // адрес релея mihomo
	once  sync.Once
}

func (d Dialer) DialUDP() (*udpConn, error) {
	c, err := net.DialTimeout("tcp", d.Addr, d.Timeout)
	if err != nil {
		return nil, fmt.Errorf("socks connect: %w", err)
	}
	_ = c.SetDeadline(time.Now().Add(d.Timeout))

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

	// CMD=3 (UDP ASSOCIATE). адрес источника не знаем, шлём нули --
	// релей вернёт адрес, на который нам слать датаграммы
	req := []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, fmt.Errorf("socks udp associate: %w", err)
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		c.Close()
		return nil, fmt.Errorf("socks associate reply: %w", err)
	}
	if head[1] != 0 {
		c.Close()
		return nil, fmt.Errorf("socks udp refused: %s", socksErr(head[1]))
	}

	var host string
	switch head[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			c.Close()
			return nil, err
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			c.Close()
			return nil, err
		}
		host = net.IP(b).String()
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			c.Close()
			return nil, err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(c, b); err != nil {
			c.Close()
			return nil, err
		}
		host = string(b)
	default:
		c.Close()
		return nil, fmt.Errorf("socks bad atyp %d", head[3])
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		c.Close()
		return nil, err
	}
	port := int(pb[0])<<8 | int(pb[1])

	// релей мог назвать себя 0.0.0.0 -- тогда шлём туда же,
	// куда подключались по TCP
	if host == "0.0.0.0" || host == "::" {
		h, _, _ := net.SplitHostPort(d.Addr)
		host = h
	}
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		c.Close()
		return nil, err
	}
	uc, err := net.ListenUDP("udp", nil)
	if err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return &udpConn{ctrl: c, relay: uc, to: raddr}, nil
}

// дальше -- реализация net.PacketConn поверх релея, чтобы её
// можно было отдать quic-go как обычный сокет

func (u *udpConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("нужен *net.UDPAddr")
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
	buf := make([]byte, len(p)+262) // запас под заголовок SOCKS
	n, _, err := u.relay.ReadFromUDP(buf)
	if err != nil {
		return 0, nil, err
	}
	if n < 10 {
		return 0, nil, errors.New("слишком короткая датаграмма")
	}
	// RSV(2) FRAG(1) ATYP(1) ADDR PORT DATA
	var off int
	var ip net.IP
	switch buf[3] {
	case 1:
		if n < 10 {
			return 0, nil, errors.New("короткий ipv4-заголовок")
		}
		ip = net.IP(buf[4:8])
		off = 8
	case 4:
		if n < 22 {
			return 0, nil, errors.New("короткий ipv6-заголовок")
		}
		ip = net.IP(buf[4:20])
		off = 20
	case 3:
		l := int(buf[4])
		if n < 5+l+2 {
			return 0, nil, errors.New("короткий доменный заголовок")
		}
		off = 5 + l
	default:
		return 0, nil, fmt.Errorf("неизвестный atyp %d", buf[3])
	}
	port := int(buf[off])<<8 | int(buf[off+1])
	off += 2
	copied := copy(p, buf[off:n])
	return copied, &net.UDPAddr{IP: ip, Port: port}, nil
}

func (u *udpConn) Close() error {
	u.once.Do(func() {
		u.relay.Close()
		u.ctrl.Close() // закрытие управляющего соединения рвёт ассоциацию
	})
	return nil
}

// quic-go проверяет наличие этих методов, иначе пишет предупреждение
// о размере буфера на каждый вызов
func (u *udpConn) SetReadBuffer(n int) error  { return u.relay.SetReadBuffer(n) }
func (u *udpConn) SetWriteBuffer(n int) error { return u.relay.SetWriteBuffer(n) }

func (u *udpConn) LocalAddr() net.Addr                { return u.relay.LocalAddr() }
func (u *udpConn) SetDeadline(t time.Time) error      { return u.relay.SetDeadline(t) }
func (u *udpConn) SetReadDeadline(t time.Time) error  { return u.relay.SetReadDeadline(t) }
func (u *udpConn) SetWriteDeadline(t time.Time) error { return u.relay.SetWriteDeadline(t) }
