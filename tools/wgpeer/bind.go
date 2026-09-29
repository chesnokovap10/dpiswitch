package main

import (
	"net"
	"net/netip"
	"sync"

	"github.com/metacubex/wireguard-go/conn"
)

// loopBind: the peer's UDP socket on 127.0.0.1 alone -- the client is the
// core on this machine, and a socket on every address would have Windows
// ask to let the program through its firewall
type loopBind struct {
	mu sync.Mutex
	c  *net.UDPConn
}

type loopEndpoint netip.AddrPort

func (e loopEndpoint) ClearSrc()           {}
func (e loopEndpoint) SrcToString() string { return "" }
func (e loopEndpoint) DstToString() string { return netip.AddrPort(e).String() }
func (e loopEndpoint) DstToBytes() []byte  { b, _ := netip.AddrPort(e).MarshalBinary(); return b }
func (e loopEndpoint) DstIP() netip.Addr   { return netip.AddrPort(e).Addr() }
func (e loopEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

func (b *loopBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	b.c = c
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, from, err := c.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			return 0, err
		}
		sizes[0], eps[0] = n, loopEndpoint(netip.AddrPortFrom(from.Addr().Unmap(), from.Port()))
		return 1, nil
	}
	return []conn.ReceiveFunc{recv}, uint16(c.LocalAddr().(*net.UDPAddr).Port), nil
}

func (b *loopBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.c == nil {
		return nil
	}
	err := b.c.Close()
	b.c = nil
	return err
}

func (b *loopBind) SetMark(uint32) error { return nil }
func (b *loopBind) BatchSize() int       { return 1 }

func (b *loopBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	c := b.c
	b.mu.Unlock()
	if c == nil {
		return net.ErrClosed
	}
	for _, p := range bufs {
		if _, err := c.WriteToUDPAddrPort(p, netip.AddrPort(ep.(loopEndpoint))); err != nil {
			return err
		}
	}
	return nil
}

func (b *loopBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	return loopEndpoint(ap), err
}
