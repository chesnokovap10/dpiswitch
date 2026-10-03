package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dpiswitch/internal/ctl"
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

// A core starts with the adapter's answers of the last check, and a
// tunnel's "no IPv6" within the hold: IPv6 found blocked builds the same
// config each start, and the core is not restarted for it again. A tunnel's
// IPv6 working is not kept -- unknown is the same to the config -- nor is
// "no IPv6" past the hold, or with no time, or a time ahead of the clock.
func TestStartIPv6State(t *testing.T) {
	now := time.Now()
	last := ctl.TunnelIPv6{ctl.TunKey: false, ctl.Tun4Key: true, "awg1": false, "awg2": true}
	got := startIPv6State(last, v6Held{}, now)
	if len(got) != 2 || !got.SystemBlocked() || got.TrafficBlocked() || got.Dead("awg1") {
		t.Fatalf("%v", got)
	}
	if len(startIPv6State(ctl.TunnelIPv6{"awg1": false}, nil, now)) != 0 {
		t.Fatal("a tunnel's answer kept with no time to it")
	}
	for _, c := range []struct {
		name string
		at   time.Time
		kept bool
	}{
		{"found an hour ago", now.Add(-time.Hour), true},
		{"found past the hold", now.Add(-tunnelV6Hold - time.Minute), false},
		{"found ahead of the clock", now.Add(time.Hour), false},
	} {
		got := startIPv6State(ctl.TunnelIPv6{"awg1": false, "awg2": true}, v6Held{"awg1": c.at, "awg2": c.at}, now)
		want := 0 // awg2 works: not kept either way
		if c.kept {
			want = 1
		}
		if got.Dead("awg1") != c.kept || len(got) != want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

// The hold survives the file it is kept in; a missing or broken one holds
// nothing.
func TestV6HeldFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "held.json")
	if h := loadV6Held(p); len(h) != 0 {
		t.Fatalf("no file: %v", h)
	}
	at := time.Now().Add(-time.Hour).Round(time.Second)
	if err := (v6Held{"awg2": at}).save(p); err != nil {
		t.Fatal(err)
	}
	if h := loadV6Held(p); !h["awg2"].Equal(at) || !h.holds("awg2", time.Now()) || h.holds("awg1", time.Now()) {
		t.Fatalf("read back: %v", h)
	}
	os.WriteFile(p, []byte("{broken"), 0o644)
	if h := loadV6Held(p); h == nil || len(h) != 0 {
		t.Fatalf("broken file: %v", h)
	}
	if h := (v6Held{"awg1": at, "awg2": at}).only([]string{"awg2", "awg3"}); len(h) != 1 || !h["awg2"].Equal(at) {
		t.Fatalf("only: %v", h)
	}
}

// IPv6 not reaching the adapter, the tunnels are not checked: on IPv4
// alone, they would be found without IPv6 whatever they carry. Nor is a
// tunnel whose "no IPv6" the start kept, for the same reason.
func TestTunnelsToCheck(t *testing.T) {
	names := []string{"awg1", "awg2"}
	if got := tunnelsToCheck(ctl.TunnelIPv6{ctl.TunKey: false}, names); len(got) != 0 {
		t.Errorf("IPv6 blocked: %v checked", got)
	}
	for _, st := range []ctl.TunnelIPv6{{}, {ctl.TunKey: true}} {
		if got := tunnelsToCheck(st, names); len(got) != 2 {
			t.Errorf("%v: %v checked", st, got)
		}
	}
	found := ctl.TunnelIPv6{ctl.TunKey: true}
	keepTunnelIPv6(ctl.TunnelIPv6{ctl.TunKey: false, ctl.Tun4Key: false, "awg2": false, "awg1": true}, found)
	if len(found) != 2 || !found.Dead("awg2") || found.SystemBlocked() {
		t.Fatalf("kept: %v", found)
	}
	if got := tunnelsToCheck(found, names); len(got) != 1 || got[0] != "awg1" {
		t.Errorf("awg2 kept without IPv6: %v checked", got)
	}
}

// With IPv6 off there is no IPv6 on the adapter to probe: its last answer
// is kept, for the start with IPv6 back on. An answer this check found is
// not overwritten.
func TestKeepAdapterIPv6(t *testing.T) {
	found := ctl.TunnelIPv6{ctl.Tun4Key: true}
	keepAdapterIPv6(ctl.TunnelIPv6{ctl.TunKey: false}, found)
	if !found.SystemBlocked() || found.TrafficBlocked() {
		t.Fatalf("%v", found)
	}
	found = ctl.TunnelIPv6{ctl.TunKey: true}
	keepAdapterIPv6(ctl.TunnelIPv6{ctl.TunKey: false}, found)
	if found.SystemBlocked() {
		t.Fatal("this check's answer overwritten")
	}
}

// A core restartCore stopped comes back at once, and resets the pause; one
// that fell waits, longer each time, up to a minute; one that lasted long
// starts the pause over.
func TestCorePause(t *testing.T) {
	for _, c := range []struct {
		planned      bool
		ran, backoff time.Duration
		wait, next   time.Duration
	}{
		{true, time.Second, 16 * time.Second, 0, 2 * time.Second},
		{false, time.Second, 2 * time.Second, 2 * time.Second, 4 * time.Second},
		{false, time.Second, 16 * time.Second, 16 * time.Second, 32 * time.Second},
		{false, time.Second, 64 * time.Second, 64 * time.Second, 64 * time.Second},
		{false, 3 * time.Minute, 32 * time.Second, 2 * time.Second, 4 * time.Second},
	} {
		wait, next := corePause(c.planned, c.ran, c.backoff)
		if wait != c.wait || next != c.next {
			t.Errorf("planned %v, ran %s, pause %s: wait %s then %s; want %s then %s",
				c.planned, c.ran, c.backoff, wait, next, c.wait, c.next)
		}
	}
}
