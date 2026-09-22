package ctl

import (
	"path/filepath"
	"testing"
)

func TestTunnelIPv6(t *testing.T) {
	var empty TunnelIPv6 = TunnelIPv6{}
	// an unchecked tunnel keeps IPv6: a first run must behave as before
	if empty.Dead("awg") {
		t.Error("an unchecked tunnel must not count as dead")
	}
	st := TunnelIPv6{"awg": true, "awg2": false}
	if st.Dead("awg") || !st.Dead("awg2") {
		t.Error("Dead reads the stored answer wrong")
	}

	p := filepath.Join(t.TempDir(), "tunnel-ipv6.json")
	if err := st.Save(p); err != nil {
		t.Fatal(err)
	}
	back := LoadTunnelIPv6(p)
	if !back.Same(st) {
		t.Fatalf("round trip lost the state: %v", back)
	}
	if back.Same(TunnelIPv6{"awg": true}) {
		t.Error("Same must notice a missing tunnel")
	}
	// a missing or broken file is not a verdict either
	if LoadTunnelIPv6(filepath.Join(t.TempDir(), "none.json")).Dead("awg") {
		t.Error("a missing file must not mark a tunnel dead")
	}
}
