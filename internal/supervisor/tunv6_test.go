package supervisor

import (
	"context"
	"testing"
	"time"
)

// A DNS query as the wire carries it: the ID, one question, the name by
// its labels, type A, class IN.
func TestDNSQuery(t *testing.T) {
	q := dnsQuery(0x1234, "a.bc")
	want := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 2, 'b', 'c', 0, 0, 1, 0, 1}
	if string(q) != string(want) {
		t.Fatalf("%v, want %v", q, want)
	}
}

// IPv6 is found not reaching the adapter only when IPv4 is answered and
// IPv6 is not; an adapter not answering at all is no verdict.
func TestTunIPv6(t *testing.T) {
	old := dnsAnswered
	defer func() { dnsAnswered = old }()
	for _, c := range []struct {
		name      string
		v4, v6    bool
		ok, known bool
		cancelled bool
	}{
		{"both answered", true, true, true, true, false},
		{"IPv6 taken on the way", true, false, false, true, false},
		{"the adapter silent", false, false, false, false, true},
	} {
		dnsAnswered = func(addr string, _ time.Duration) bool {
			if addr == tunProbe6 {
				return c.v6
			}
			return c.v4
		}
		ctx, cancel := context.WithCancel(context.Background())
		if c.cancelled {
			// the service stopping while it waits: no verdict, at once
			cancel()
		}
		ok, known := tunIPv6(ctx)
		cancel()
		if ok != c.ok || known != c.known {
			t.Errorf("%s: %v, %v; want %v, %v", c.name, ok, known, c.ok, c.known)
		}
	}
}
