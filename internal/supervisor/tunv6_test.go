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

// The adapter's answers: IPv4 blocked only when the core answers its API
// all along and no query through the adapter is; IPv6 blocked when IPv4 was
// answered and IPv6 is not. A core not up, or the service stopping, is no
// verdict.
func TestTunProbes(t *testing.T) {
	old, oldWait := dnsAnswered, tunProbeWait
	defer func() { dnsAnswered, tunProbeWait = old, oldWait }()
	tunProbeWait = 3 * time.Millisecond
	for _, c := range []struct {
		name           string
		v4, v6, coreUp bool
		ok4, known4    bool
		ok6, known6    bool
	}{
		{"both answered", true, true, true, true, true, true, true},
		{"IPv6 taken on the way", true, false, true, true, true, false, true},
		{"IPv4 taken too", false, false, true, false, true, false, true},
		{"the core not up", false, false, false, false, false, false, true},
	} {
		dnsAnswered = func(addr string, _ time.Duration) bool {
			if addr == tunProbe6 {
				return c.v6
			}
			return c.v4
		}
		ok, known := tunIPv4(context.Background(), func() bool { return c.coreUp })
		if ok != c.ok4 || known != c.known4 {
			t.Errorf("%s, IPv4: %v, %v; want %v, %v", c.name, ok, known, c.ok4, c.known4)
		}
		if ok, known = tunIPv6(context.Background()); ok != c.ok6 || known != c.known6 {
			t.Errorf("%s, IPv6: %v, %v; want %v, %v", c.name, ok, known, c.ok6, c.known6)
		}
	}
	// the service stopping while it waits: no verdict, at once
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dnsAnswered = func(string, time.Duration) bool { return false }
	if _, known := tunIPv4(ctx, func() bool { return true }); known {
		t.Error("IPv4: a verdict with the service stopping")
	}
	if _, known := tunIPv6(ctx); known {
		t.Error("IPv6: a verdict with the service stopping")
	}
}
