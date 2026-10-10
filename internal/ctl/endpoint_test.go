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

// The direct path counts as down on a port only when the tunnel got past the
// stage it failed at: a speedtest server has no TLS on 443 on either path,
// and its working 20000 must still decide; a tunnel that never got a TCP
// connection shows nothing of what the server does at TLS.
func TestDirectDownOn(t *testing.T) {
	tlsFail := probe.PathResult{TCPOk: true, TLSTried: true, Err: "EOF", ErrStage: "tls"}
	tlsOK := probe.PathResult{TCPOk: true, TLSTried: true, TLSOk: true}
	noTunnel := probe.PathResult{Err: "socks connect: refused", ErrStage: "tcp"}
	tcpFail := probe.PathResult{Err: "i/o timeout", ErrStage: "tcp"}
	tcpOK := probe.PathResult{TCPOk: true}
	httpFail := probe.PathResult{TCPOk: true, TLSTried: true, TLSOk: true, Err: "malformed", ErrStage: "http_read"}
	cases := []struct {
		name string
		d, t probe.PathResult
		want bool
	}{
		{"no TLS on either path", tlsFail, tlsFail, false},
		{"not HTTP on either path", httpFail, httpFail, false},
		{"direct cut at TLS, tunnel failed at TCP", tlsFail, noTunnel, false},
		{"direct fine, tunnel unreachable", tlsOK, noTunnel, false},
		{"direct DNS gave nothing", probe.PathResult{}, probe.PathResult{}, true},
		{"direct cut at TLS, tunnel through", tlsFail, tlsOK, true},
		{"direct cut at TLS, tunnel cut at HTTP", tlsFail, httpFail, true},
		{"direct cut at HTTP, tunnel cut at TLS", httpFail, tlsFail, false},
		{"direct no TCP, tunnel cut at TLS", tcpFail, tlsFail, true},
		{"direct no TCP, plain TCP through the tunnel", tcpFail, tcpOK, true},
		{"no TCP on either path", tcpFail, tcpFail, false},
	}
	for _, c := range cases {
		if got := directDownOn(probe.Report{Direct: c.d, Tunnel: c.t}); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// A name on eight ports, one of them QUIC with no TCP seen beside it: the
// check adds that TCP (withTCP) and remembers nine. The ninth is no port
// left out -- it is probed every time -- and counted as one it held the name
// INCONCLUSIVE for good.
func TestMergeEndpointsQUICTwin(t *testing.T) {
	now := []endpoint{{udp: true, port: 443}}
	for p := 1; p < maxEndpoints; p++ {
		now = append(now, endpoint{port: 20000 + p})
	}
	eps, dropped := mergeEndpoints(now, nil)
	if dropped != 0 {
		t.Fatalf("first check: %d left out", dropped)
	}
	eps = withTCP(eps)
	if len(eps) != maxEndpoints+1 {
		t.Fatalf("setup: %d endpoints probed, want %d", len(eps), maxEndpoints+1)
	}
	again, dropped := mergeEndpoints(nil, endpointStrings(eps))
	if dropped != 0 {
		t.Errorf("re-check: %d counted as left out, want none", dropped)
	}
	if got := withTCP(again); !reflect.DeepEqual(got, eps) {
		t.Errorf("re-check probes %v, want %v", got, eps)
	}
	// a ninth port of its own is left out, and said so
	if _, dropped := mergeEndpoints([]endpoint{{port: 9}}, endpointStrings(eps)); dropped != 1 {
		t.Errorf("a ninth port: %d left out, want 1", dropped)
	}
}
