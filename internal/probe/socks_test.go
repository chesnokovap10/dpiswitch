package probe

import (
	"io"
	"net"
	"testing"
	"time"
)

// authStub: a SOCKS5 listener that takes SocksUser with its password only,
// as the core's prober listeners do; it answers a CONNECT and a UDP
// ASSOCIATE, and tells what the latter named.
func authStub(t *testing.T, pass string) (addr string, named chan int) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	named = make(chan int, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 512)
				// whatever methods are offered, the listener asks for a password
				if _, err := io.ReadFull(c, buf[:2]); err != nil {
					return
				}
				io.ReadFull(c, buf[:buf[1]])
				c.Write([]byte{5, 2})
				if _, err := io.ReadFull(c, buf[:2]); err != nil {
					return
				}
				user := make([]byte, buf[1])
				io.ReadFull(c, user)
				io.ReadFull(c, buf[:1])
				got := make([]byte, buf[0])
				io.ReadFull(c, got)
				if string(user) != SocksUser || string(got) != pass {
					c.Write([]byte{1, 1})
					return
				}
				c.Write([]byte{1, 0})
				io.ReadFull(c, buf[:10]) // VER CMD RSV ATYP=1 ADDR PORT
				if buf[1] == 3 {
					named <- int(buf[8])<<8 | int(buf[9])
				}
				c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 53})
				io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().String(), named
}

// The prober's listeners take its user and password; a UDP association
// names the port its datagrams go from -- the core takes UDP from no other.
func TestSocksAuth(t *testing.T) {
	addr, named := authStub(t, "secret")
	d := Dialer{Addr: addr, Timeout: 2 * time.Second, Pass: "secret"}
	c, err := d.dial("192.0.2.1", 443)
	if err != nil {
		t.Fatalf("with the password: %v", err)
	}
	c.Close()

	u, err := d.DialUDP()
	if err != nil {
		t.Fatalf("UDP with the password: %v", err)
	}
	defer u.Close()
	select {
	case p := <-named:
		if want := u.LocalAddr().(*net.UDPAddr).Port; p != want {
			t.Fatalf("the association named port %d, the datagrams go from %d", p, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no association made")
	}

	if _, err := (Dialer{Addr: addr, Timeout: 2 * time.Second, Pass: "wrong"}).dial("192.0.2.1", 443); err == nil {
		t.Fatal("a wrong password let in")
	}
	if _, err := (Dialer{Addr: addr, Timeout: 2 * time.Second}).dial("192.0.2.1", 443); err == nil {
		t.Fatal("no password let in")
	}
}
