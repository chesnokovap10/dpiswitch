package probe

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func doqTestServer(t *testing.T, handle func(*quic.Stream, []byte)) (Resolver, *atomic.Int32) {
	t.Helper()
	cert := httptest.NewUnstartedServer(nil)
	cert.StartTLS()
	t.Cleanup(cert.Close)
	roots := x509.NewCertPool()
	roots.AddCert(cert.Certificate())
	old := resolverRoots
	resolverRoots = roots
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsConf := cert.TLS.Clone()
	tlsConf.NextProtos = []string{"doq"}
	ln, err := quic.Listen(pc, tlsConf, nil)
	if err != nil {
		pc.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		doqClients.Range(func(k, v any) bool {
			c := v.(*doqClient)
			c.mu.Lock()
			if c.conn != nil {
				c.conn.CloseWithError(0, "")
			}
			c.mu.Unlock()
			doqClients.Delete(k)
			return true
		})
		ln.Close()
		pc.Close()
		resolverRoots = old
	})
	count := new(atomic.Int32)
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			count.Add(1)
			go func() {
				for {
					stream, err := conn.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go func() {
						defer stream.Close()
						var prefix [2]byte
						if _, err := io.ReadFull(stream, prefix[:]); err != nil {
							return
						}
						q := make([]byte, binary.BigEndian.Uint16(prefix[:]))
						if len(q) < 12 {
							return
						}
						if _, err := io.ReadFull(stream, q); err != nil {
							return
						}
						var extra [1]byte
						if n, err := stream.Read(extra[:]); n != 0 || err != io.EOF {
							t.Error("DoQ query has no FIN")
							return
						}
						if q[0] != 0 || q[1] != 0 {
							t.Error("DoQ query ID is not zero")
							return
						}
						if handle != nil {
							handle(stream, q)
							return
						}
						doqTestReply(stream, answerWith(q, 0))
					}()
				}
			}()
		}
	}()
	r, err := ParseResolver("quic://" + pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	return r, count
}

func doqTestReply(stream *quic.Stream, b []byte) {
	wire := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(wire, uint16(len(b)))
	copy(wire[2:], b)
	io.Copy(stream, bytes.NewReader(wire))
}

func TestParseDoQ(t *testing.T) {
	for in, host := range map[string]string{"quic://1.1.1.1": "1.1.1.1", "quic://dns.example": "dns.example", "quic://2606:4700:4700::1111": "2606:4700:4700::1111"} {
		r, err := ParseResolver(in)
		if err != nil || r.Scheme != "quic" || r.Port != 853 || r.Host != host {
			t.Fatalf("%s: %+v %v", in, r, err)
		}
	}
	if r, err := ParseResolver("quic://[::1]:8853"); err != nil || r.Port != 8853 {
		t.Fatalf("custom port: %+v %v", r, err)
	}
	for _, in := range []string{"quic://127.0.0.1:53", "quic://dns.example/dns-query"} {
		if _, err := ParseResolver(in); err == nil {
			t.Errorf("accepted %s", in)
		}
	}
}

func TestDoQExchangeAndPing(t *testing.T) {
	r, connections := doqTestServer(t, nil)
	d := Dialer{Direct: true, Timeout: 3 * time.Second}
	q, _ := buildQuery("a.example.org", typeA)
	q[0], q[1] = 0x12, 0x34
	original := bytes.Clone(q)
	b, err := r.Exchange(d, q)
	if err != nil || !bytes.Equal(b[:2], q[:2]) || !bytes.Equal(q, original) {
		t.Fatalf("query/response IDs: %x %v", b, err)
	}
	ips, _, used, kind, err := PingEitherProtocol(d, r.Raw, "a.example.org")
	if err != nil || kind != "DoQ" || used != r.Raw || len(ips) != 1 {
		t.Fatalf("ping: %v %s %s %v", ips, used, kind, err)
	}
	if ips, err := r.LookupV6(d, "a.example.org"); err != nil || len(ips) != 1 || ips[0] != "2001:db8::7" {
		t.Fatalf("AAAA: %v %v", ips, err)
	}
	if connections.Load() != 1 {
		t.Fatalf("%d connections for repeated queries", connections.Load())
	}
}

func TestDoQConcurrentStreams(t *testing.T) {
	r, connections := doqTestServer(t, nil)
	errs := make(chan error, 16)
	for i := 0; i < cap(errs); i++ {
		go func() {
			ips, err := r.Lookup(Dialer{Direct: true, Timeout: 3 * time.Second}, "a.example.org")
			if err == nil && len(ips) != 1 {
				err = fmt.Errorf("unexpected answer %v", ips)
			}
			errs <- err
		}()
	}
	for i := 0; i < cap(errs); i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if connections.Load() != 1 {
		t.Fatalf("parallel requests opened %d connections", connections.Load())
	}
}

func TestDoQRejectsMalformedResponses(t *testing.T) {
	for _, mode := range []string{"nonzero ID", "short", "extra message", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			r, _ := doqTestServer(t, func(s *quic.Stream, q []byte) {
				b := answerWith(q, 0)
				switch mode {
				case "nonzero ID":
					b[0] = 1
					doqTestReply(s, b)
				case "short":
					doqTestReply(s, []byte{0, 0})
				case "extra message":
					doqTestReply(s, b)
					s.Write([]byte{0})
				case "truncated":
					s.Write([]byte{0, 40, 0})
				}
			})
			if _, err := r.Lookup(Dialer{Direct: true, Timeout: time.Second}, "a.example.org"); err == nil {
				t.Fatal("malformed DoQ response accepted")
			}
		})
	}
}

func TestDoQDeadlineAndReconnect(t *testing.T) {
	var stall atomic.Bool
	r, connections := doqTestServer(t, func(s *quic.Stream, q []byte) {
		if stall.Load() {
			<-s.Context().Done()
			return
		}
		doqTestReply(s, answerWith(q, 0))
	})
	d := Dialer{Direct: true, Timeout: 250 * time.Millisecond}
	if _, err := r.Lookup(d, "a.example.org"); err != nil {
		t.Fatal(err)
	}
	stall.Store(true)
	start := time.Now()
	if _, err := r.Lookup(d, "a.example.org"); err == nil {
		t.Fatal("stalled DoQ stream did not time out")
	}
	if time.Since(start) > time.Second {
		t.Fatal("DoQ exceeded its deadline")
	}
	stall.Store(false)
	if _, err := r.Lookup(d, "a.example.org"); err != nil {
		t.Fatal(err)
	}
	if connections.Load() < 2 {
		t.Fatal("failed connection was not replaced")
	}
}

func TestDoQSOCKSHostnameAndCertificate(t *testing.T) {
	r, _ := doqTestServer(t, nil)
	addr, names := doh3SOCKSRelay(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: r.Port})
	r.Host = "example.com"
	r.Raw = "quic://" + net.JoinHostPort(r.Host, strconv.Itoa(r.Port))
	d := Dialer{Addr: addr, Timeout: 3 * time.Second}
	if _, err := r.Lookup(d, "a.example.org"); err != nil {
		t.Fatal(err)
	}
	select {
	case name := <-names:
		if name != r.Host {
			t.Fatal(name)
		}
	default:
		t.Fatal("resolver name did not go through SOCKS")
	}
	wrong := d
	wrong.Pass = "wrong password"
	if _, err := r.Lookup(wrong, "a.example.org"); err == nil {
		t.Fatal("connection reused with wrong SOCKS credentials")
	}
	// A fresh direct connection must reject the same server when untrusted.
	resolverRoots = x509.NewCertPool()
	r.Host = "127.0.0.1"
	if _, err := r.Lookup(Dialer{Direct: true, Timeout: time.Second}, "a.example.org"); err == nil {
		t.Fatal("untrusted DoQ certificate accepted")
	}
}
