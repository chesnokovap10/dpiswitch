package ctl

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTunnelIPv6(t *testing.T) {
	var empty TunnelIPv6 = TunnelIPv6{}
	// an unchecked tunnel keeps IPv6: a first run must behave as before
	if empty.Dead("awg1") {
		t.Error("an unchecked tunnel must not count as dead")
	}
	st := TunnelIPv6{"awg1": true, "awg2": false}
	if st.Dead("awg1") || !st.Dead("awg2") {
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
	if back.Same(TunnelIPv6{"awg1": true}) {
		t.Error("Same must notice a missing tunnel")
	}
	// a missing or broken file is not a verdict either
	if LoadTunnelIPv6(filepath.Join(t.TempDir(), "none.json")).Dead("awg1") {
		t.Error("a missing file must not mark a tunnel dead")
	}
}

// A file written while the first tunnel's proxy was "awg" is read as awg1's:
// its IPv6 found dead stays dead after the rename.
func TestTunnelIPv6OldName(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tunnel-ipv6.json")
	if err := os.WriteFile(p, []byte(`{"awg": false, "awg2": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got := LoadTunnelIPv6(p)
	if !got.Dead("awg1") || got.Dead("awg2") {
		t.Fatalf("read as %v", got)
	}
	if _, old := got["awg"]; old {
		t.Errorf("the old name kept: %v", got)
	}
}
