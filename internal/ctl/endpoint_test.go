package ctl

import (
	"reflect"
	"testing"
)

// A re-check made while the name is idle must still probe the ports it is
// used on: a speedtest server lives on 20000 and has nothing on 443.
func TestMergeEndpoints(t *testing.T) {
	stored := []string{"tcp/20000", "tcp/443", "garbage", "quic/443"}

	// idle this minute: only what was remembered, the junk entry skipped
	got := mergeEndpoints(nil, stored)
	want := []endpoint{{port: 20000}, {port: 443}, {udp: true, port: 443}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("idle: got %v, want %v", got, want)
	}

	// seen now on a new port: it comes first, duplicates are dropped
	got = mergeEndpoints([]endpoint{{port: 8080}, {port: 443}}, stored)
	want = []endpoint{{port: 8080}, {port: 443}, {port: 20000}, {udp: true, port: 443}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merged: got %v, want %v", got, want)
	}

	// round trip through the state file
	if back := mergeEndpoints(nil, endpointStrings(want)); !reflect.DeepEqual(back, want) {
		t.Fatalf("round trip: got %v", back)
	}

	// the cap: every remembered port costs a probe
	var many []endpoint
	for p := 1; p <= 20; p++ {
		many = append(many, endpoint{port: p})
	}
	if n := len(mergeEndpoints(many, nil)); n != maxEndpoints {
		t.Fatalf("cap: got %d, want %d", n, maxEndpoints)
	}
}
