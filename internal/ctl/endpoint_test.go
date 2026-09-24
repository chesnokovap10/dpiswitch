package ctl

import (
	"reflect"
	"testing"

	"dpiswitch/internal/probe"
)

// A re-check made while the name is idle must still probe the ports it is
// used on: a speedtest server lives on 20000 and has nothing on 443.
func TestMergeEndpoints(t *testing.T) {
	stored := []string{"tcp/20000", "tcp/443", "garbage", "quic/443"}

	// idle this minute: only what was remembered, the junk entry skipped
	got, _ := mergeEndpoints(nil, stored)
	want := []endpoint{{port: 20000}, {port: 443}, {udp: true, port: 443}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("idle: got %v, want %v", got, want)
	}

	// seen now on a new port: it comes first, duplicates are dropped
	got, _ = mergeEndpoints([]endpoint{{port: 8080}, {port: 443}}, stored)
	want = []endpoint{{port: 8080}, {port: 443}, {port: 20000}, {udp: true, port: 443}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merged: got %v, want %v", got, want)
	}

	// round trip through the state file
	if back, _ := mergeEndpoints(nil, endpointStrings(want)); !reflect.DeepEqual(back, want) {
		t.Fatalf("round trip: got %v", back)
	}

	// the cap: every remembered port costs a probe
	var many []endpoint
	for p := 1; p <= 20; p++ {
		many = append(many, endpoint{port: p})
	}
	// and says how many it left out: see TestCycleTooManyPorts
	if eps, dropped := mergeEndpoints(many, nil); len(eps) != maxEndpoints || dropped != 20-maxEndpoints {
		t.Fatalf("cap: kept %d, dropped %d; want %d and %d", len(eps), dropped, maxEndpoints, 20-maxEndpoints)
	}
}

// The direct path counts as down on a port only when the tunnel did not fail
// the same way: a speedtest server has no TLS on 443 on either path, and its
// working 20000 must still decide.
func TestDirectDownOn(t *testing.T) {
	tlsFail := probe.PathResult{TCPOk: true, TLSTried: true, Err: "EOF", ErrStage: "tls"}
	tlsOK := probe.PathResult{TCPOk: true, TLSTried: true, TLSOk: true}
	noTunnel := probe.PathResult{Err: "socks connect: refused", ErrStage: "tcp"}
	httpFail := probe.PathResult{TCPOk: true, TLSTried: true, TLSOk: true, Err: "malformed", ErrStage: "http_read"}
	cases := []struct {
		name string
		d, t probe.PathResult
		want bool
	}{
		{"no TLS on either path", tlsFail, tlsFail, false},
		{"not HTTP on either path", httpFail, httpFail, false},
		{"direct cut, tunnel unreachable", tlsFail, noTunnel, true},
		{"direct fine, tunnel unreachable", tlsOK, noTunnel, false},
		{"direct DNS gave nothing", probe.PathResult{}, probe.PathResult{}, true},
	}
	for _, c := range cases {
		if got := directDownOn(probe.Report{Direct: c.d, Tunnel: c.t}); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
