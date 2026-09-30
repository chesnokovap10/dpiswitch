// wgpeer: a WireGuard peer for the routing checks on the real core
// (internal/awgconf, TestCoreRouting). It takes one client, as the servers
// of the tunnels take the program, and answers every TCP connection coming
// through the tunnel -- to any address, any port -- with "204 No Content":
// the core's health check passes, so the tunnel counts as alive. Every
// connection taken is printed, "conn <address:port>".
//
// A module of its own: the TCP stack (gVisor) stays out of the program's.
//
//	wgpeer -port 51820 -key <private, hex> -peer <client's public, hex>
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"syscall"
	"time"

	awg "github.com/metacubex/amneziawg-go/device"
	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv6"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/waiter"
	"github.com/metacubex/wireguard-go/device"
	"github.com/metacubex/wireguard-go/tun"
)

const mtu = 1420

func main() {
	port := flag.Int("port", 0, "UDP port to listen on")
	key := flag.String("key", "", "this peer's private key, hex")
	peer := flag.String("peer", "", "the client's public key, hex")
	flag.Parse()
	if *port == 0 || *key == "" || *peer == "" {
		flag.Usage()
		os.Exit(2)
	}

	t, err := newNetTun()
	if err != nil {
		log.Fatal(err)
	}
	dev := awg.NewDevice(t, &loopBind{}, device.NewLogger(device.LogLevelVerbose, "wgpeer: "), 2)
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n",
		*key, *port, *peer)); err != nil {
		log.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("ready")
	// until the parent closes stdin
	bufio.NewReader(os.Stdin).ReadString(0)
	dev.Close()
}

// netTun: the device's side of a gVisor stack that takes every address
type netTun struct {
	ep     *channel.Endpoint
	stack  *stack.Stack
	events chan tun.Event
	in     chan *buffer.View
}

func newNetTun() (*netTun, error) {
	t := &netTun{
		ep: channel.New(1024, mtu, ""),
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
			// not true: with promiscuous mode every source address would be
			// the stack's own, and every packet dropped as a martian
			HandleLocal: false,
		}),
		events: make(chan tun.Event, 10),
		in:     make(chan *buffer.View, 1024),
	}
	t.ep.AddNotify(t)
	if err := t.stack.CreateNIC(1, t.ep); err != nil {
		return nil, fmt.Errorf("CreateNIC: %v", err)
	}
	// an address of each family, which the stack wants before it takes a
	// packet at all; then any destination is its own
	for _, a := range []netip.Addr{netip.MustParseAddr("10.255.255.1"), netip.MustParseAddr("fd00::1")} {
		proto := ipv4.ProtocolNumber
		if a.Is6() {
			proto = ipv6.ProtocolNumber
		}
		if err := t.stack.AddProtocolAddress(1, tcpip.ProtocolAddress{
			Protocol:          proto,
			AddressWithPrefix: tcpip.AddrFromSlice(a.AsSlice()).WithPrefix(),
		}, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("AddProtocolAddress(%v): %v", a, err)
		}
	}
	t.stack.SetPromiscuousMode(1, true)
	t.stack.SetSpoofing(1, true)
	t.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	t.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})

	fwd := tcp.NewForwarder(t.stack, 0, 1024, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		debugf("syn %v:%d", id.LocalAddress, id.LocalPort)
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			debugf("endpoint: %v", err)
			r.Complete(true)
			return
		}
		r.Complete(false)
		dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte(id.LocalAddress.AsSlice()[:4])), id.LocalPort)
		if id.LocalAddress.Len() == 16 {
			dst = netip.AddrPortFrom(netip.AddrFrom16([16]byte(id.LocalAddress.AsSlice())), id.LocalPort)
		}
		fmt.Printf("conn %s\n", dst)
		c := gonet.NewTCPConn(&wq, ep)
		go func() {
			defer c.Close()
			// the speed checks: port 9 takes and drops what comes, port 19
			// sends zeros until the client goes -- any address
			switch id.LocalPort {
			case 9:
				io.Copy(io.Discard, c)
				return
			case 19:
				zeros := make([]byte, 64<<10)
				for {
					if _, err := c.Write(zeros); err != nil {
						return
					}
				}
			}
			if req, err := http.ReadRequest(bufio.NewReader(c)); err == nil {
				req.Body.Close()
			}
			c.Write([]byte("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"))
		}()
	})
	t.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	if os.Getenv("WGPEER_DEBUG") != "" {
		go func() {
			for range time.Tick(2 * time.Second) {
				s := t.stack.Stats()
				debugf("stats ip rcv %d valid %d disabled %d badSrc %d prerouteDrop %d inputDrop %d delivered %d badDst %d malformed %d | tcp seg %d invalid %d cksum %d | nic drop %d",
					s.IP.PacketsReceived.Value(), s.IP.ValidPacketsReceived.Value(), s.IP.DisabledPacketsReceived.Value(), s.IP.InvalidSourceAddressesReceived.Value(), s.IP.IPTablesPreroutingDropped.Value(), s.IP.IPTablesInputDropped.Value(), s.IP.PacketsDelivered.Value(), s.IP.InvalidDestinationAddressesReceived.Value(),
					s.IP.MalformedPacketsReceived.Value(), s.TCP.ValidSegmentsReceived.Value(), s.TCP.InvalidSegmentsReceived.Value(),
					s.TCP.ChecksumErrors.Value(), s.NICs.MalformedL4RcvdPackets.Value())
			}
		}()
	}
	t.events <- tun.EventUp
	return t, nil
}

func (t *netTun) Name() (string, error)    { return "wgpeer", nil }
func (t *netTun) File() *os.File           { return nil }
func (t *netTun) Events() <-chan tun.Event { return t.events }
func (t *netTun) MTU() (int, error)        { return mtu, nil }
func (t *netTun) BatchSize() int           { return 1 }

func (t *netTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	v, ok := <-t.in
	if !ok {
		return 0, os.ErrClosed
	}
	n, err := v.Read(bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (t *netTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		p := b[offset:]
		if len(p) == 0 {
			continue
		}
		if os.Getenv("WGPEER_DEBUG") != "" && p[0]>>4 == 4 && len(p) >= 20 {
			fmt.Printf("pkt v4 proto %d %v -> %v len %d\n", p[9], netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20])), len(p))
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
		switch p[0] >> 4 {
		case 4:
			t.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			t.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			return 0, syscall.EAFNOSUPPORT
		}
	}
	return len(bufs), nil
}

// WriteNotify: a packet the stack sends, for the device to read
func (t *netTun) WriteNotify() {
	pkt := t.ep.Read()
	if pkt == nil {
		return
	}
	v := pkt.ToView()
	pkt.DecRef()
	debugf("out %d bytes", v.Size())
	t.in <- v
}

func (t *netTun) Close() error {
	t.stack.RemoveNIC(1)
	close(t.events)
	t.ep.Close()
	close(t.in)
	return nil
}

// debugf: with WGPEER_DEBUG set, what the peer does, one line each
func debugf(f string, a ...any) {
	if os.Getenv("WGPEER_DEBUG") != "" {
		fmt.Printf(f+"\n", a...)
	}
}
