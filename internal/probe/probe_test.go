package probe

import (
	"net"
	"testing"
	"time"
)

// pair returns a real TCP connection and the server side of it: the probe
// identifies its connection to the core by the local port.
func pair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); ch <- c }()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return client, <-ch
}

// mihomo replies "succeeded" to CONNECT before it dials and closes the
// connection if the dial then fails. The close alone proves nothing -- a
// speedtest server hangs up on a silent client after four seconds -- so the
// core's own connection list decides.
func TestConfirmDial(t *testing.T) {
	confirmWindow, confirmPoll = 600*time.Millisecond, 20*time.Millisecond
	defer func() { confirmWindow, confirmPoll = 6*time.Second, 100*time.Millisecond }()

	never := func(int) (bool, error) { return false, nil }
	afterDial := func(d time.Duration) func(int) (bool, error) {
		at := time.Now().Add(d)
		return func(int) (bool, error) { return time.Now().After(at), nil }
	}

	cases := []struct {
		name        string
		established func(int) (bool, error)
		server      func(c net.Conn)
		ok          bool
	}{
		// the dial failed: the core never tracked it and hung up
		{"dial failed, core hangs up", never, func(c net.Conn) { c.Close() }, false},
		// the regression of the first fix: the dial went through, the server
		// then closed on a silent client -- that is not a failed dial
		{"server closes a silent client", afterDial(50 * time.Millisecond),
			func(c net.Conn) { time.Sleep(200 * time.Millisecond); c.Close() }, true},
		// the core answers but never has the connection, and it stays open
		{"core never tracks it", never, func(c net.Conn) { time.Sleep(time.Second); c.Close() }, false},
		// a server-first protocol answers before the core is even asked twice
		{"server speaks first", never, func(c net.Conn) { c.Write([]byte("SSH-2.0\r\n")); time.Sleep(time.Second); c.Close() }, true},
		// no way to ask the core: an open connection after the window counts
		{"no core to ask, open", nil, func(c net.Conn) { time.Sleep(time.Second); c.Close() }, true},
	}
	for _, tc := range cases {
		client, server := pair(t)
		go tc.server(server)
		err := confirmDial(client, tc.established)
		client.Close()
		if (err == nil) != tc.ok {
			t.Errorf("%s: err=%v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}
