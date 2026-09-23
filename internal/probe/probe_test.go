package probe

import (
	"net"
	"testing"
	"time"
)

// mihomo replies "succeeded" to CONNECT before it dials, and closes the
// connection if the dial then fails. confirmDial must read the close as a
// failure and anything else as a connection that is really there.
func TestConfirmDial(t *testing.T) {
	confirmWindow = 300 * time.Millisecond
	defer func() { confirmWindow = 6 * time.Second }()

	cases := []struct {
		name   string
		server func(c net.Conn)
		ok     bool
	}{
		// the regression: the core could not reach the target and hung up
		{"proxy hangs up after CONNECT", func(c net.Conn) { c.Close() }, false},
		// a client-first protocol: silence until we speak, connection open
		{"target silent, connection open", func(c net.Conn) { time.Sleep(time.Second); c.Close() }, true},
		// a server-first protocol (SSH, SMTP banner)
		{"target speaks first", func(c net.Conn) { c.Write([]byte("SSH-2.0\r\n")); time.Sleep(time.Second); c.Close() }, true},
	}
	for _, tc := range cases {
		client, server := net.Pipe()
		go tc.server(server)
		err := confirmDial(client)
		client.Close()
		if (err == nil) != tc.ok {
			t.Errorf("%s: err=%v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}
