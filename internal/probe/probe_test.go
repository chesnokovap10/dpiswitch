package probe

import (
	"bufio"
	"errors"
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
		// a core whose API never answers proves nothing: not a dial
		{"API never answers, open", func(int) (bool, error) { return false, errors.New("timeout") },
			func(c net.Conn) { time.Sleep(time.Second); c.Close() }, false},
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

// ClassifyErr names both how DPI acted (reset / silent drop / refused) and the
// level it acted at (the address, the ClientHello that carries the name, or the
// open session) -- what the verdict's reason shows.
func TestClassifyErr(t *testing.T) {
	cases := []struct {
		err, stage string
		want       string
	}{
		{"read: connection reset by peer", "tls", "RST (reset) on the ClientHello (carries the name/SNI)"},
		{"tls: i/o timeout", "tls", "silent drop (no reply) on the ClientHello (carries the name/SNI)"},
		{"dial tcp: i/o timeout", "tcp", "silent drop (no reply) on the address (SYN/connect)"},
		{"read: connection reset by peer", "tcp", "RST (reset) on the address (SYN/connect)"},
		{"wsarecv: An existing connection was forcibly closed", "body", "RST (reset) on the session after it opened"},
		{"connect: connection refused", "tcp", "connection refused on the address (SYN/connect)"},
		{"dial tcp: connect: network is unreachable", "tcp", "host unreachable"},
	}
	for _, c := range cases {
		got := ClassifyErr(PathResult{Err: c.err, ErrStage: c.stage})
		if got != c.want {
			t.Errorf("%q/%s:\n got  %q\n want %q", c.err, c.stage, got, c.want)
		}
	}
}

// A body cut short counts as a failure where its length was announced; one
// that simply ends with the connection cannot be told from a complete one.
func TestHTTPGet(t *testing.T) {
	cases := []struct {
		name, reply  string
		stage        string
		redirectHost string
		reset        bool // close with a RST instead of a clean FIN
	}{
		{"content-length cut short", "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789", "body", "", false},
		{"ends with the connection", "HTTP/1.1 200 OK\r\n\r\n0123456789", "", "", false},
		// a close-delimited body the peer resets mid-way is a cut too: DPI
		// stalling a session after some kilobytes leaves exactly this, and by
		// length alone it was indistinguishable from a clean end
		{"close-delimited body reset", "HTTP/1.1 200 OK\r\n\r\n0123456789", "body", "", true},
		{"relative redirect", "HTTP/1.1 302 Found\r\nLocation: /ru/\r\nContent-Length: 0\r\n\r\n", "", "example.com", false},
		{"redirect elsewhere", "HTTP/1.1 302 Found\r\nLocation: http://Warning.RT.ru/?id=1\r\nContent-Length: 0\r\n\r\n", "", "warning.rt.ru", false},
	}
	for _, tc := range cases {
		client, server := pair(t)
		go func() {
			// read the request first: closing on unread data sends a reset,
			// which may discard the reply before the client reads it
			br := bufio.NewReader(server)
			for {
				l, err := br.ReadString('\n')
				if err != nil || l == "\r\n" {
					break
				}
			}
			server.Write([]byte(tc.reply))
			if tc.reset {
				// SO_LINGER 0: the close sends a RST, as a stalled session does
				if c, ok := server.(*net.TCPConn); ok {
					_ = c.SetLinger(0)
				}
			}
			server.Close()
		}()
		_ = client.SetDeadline(time.Now().Add(5 * time.Second))
		var r PathResult
		httpGet(&r, client, "example.com")
		client.Close()
		if r.ErrStage != tc.stage {
			t.Errorf("%s: stage %q (%s), want %q", tc.name, r.ErrStage, r.Err, tc.stage)
		}
		if r.HTTPFailed() != (tc.stage != "") {
			t.Errorf("%s: HTTPFailed = %v", tc.name, r.HTTPFailed())
		}
		if r.RedirectHost != tc.redirectHost {
			t.Errorf("%s: redirect host %q, want %q", tc.name, r.RedirectHost, tc.redirectHost)
		}
	}
}
