package ctl

import (
	"testing"
	"time"

	"dpiswitch/internal/probe"
)

// A bare address seen without a name gets a verdict of its own, keyed "@ip".
func TestAddressVerdicts(t *testing.T) {
	if ip, ok := probe.AddrKey("@91.204.108.4"); !ok || ip != "91.204.108.4" {
		t.Fatalf("AddrKey: %q %v", ip, ok)
	}
	if _, ok := probe.AddrKey("@not-an-ip"); ok {
		t.Error("a non-address after @ must not count")
	}
	// the public suffix list would read "@91.204.108.4" as a name in "108.4"
	if f := familyOf("@91.204.108.4"); f != "" {
		t.Errorf("an address must not form a family, got %q", f)
	}

	live := time.Now().Add(time.Hour)
	st := &state{Networks: map[string]map[string]*entry{"net": {
		"@91.204.108.4": {Verdict: probe.Clean, ExpiresAt: live, TestedIP: "91.204.108.4"},
		"tula.qms.ru":   {Verdict: probe.Clean, ExpiresAt: live, TestedIP: "212.12.2.243"},
	}}}
	if got := st.verified("net"); len(got) != 1 || got[0] != "tula.qms.ru" {
		t.Errorf("the name list must hold names only, got %v", got)
	}
	if got := st.verifiedIPs("net"); len(got) != 2 {
		t.Errorf("both nodes belong in the address list, got %v", got)
	}
}

// Only plain TCP off 443 can be judged without a name.
func TestPlainTCP(t *testing.T) {
	got := plainTCP([]endpoint{{port: 20000}, {port: 443}, {udp: true, port: 19302}, {port: 22}})
	if len(got) != 2 || got[0].port != 20000 || got[1].port != 22 {
		t.Fatalf("got %v", got)
	}
}

// An address becomes a candidate only after it shows up in two cycles.
func TestAddrNeedsTwoCycles(t *testing.T) {
	w := &watcher{seen: map[string]map[endpoint]bool{}, bare: map[string]bool{},
		addrPorts: map[string]map[endpoint]bool{}, addrCycles: map[string]int{}}
	see := func() { w.addrPorts["91.204.108.4"] = map[endpoint]bool{{port: 20000}: true} }

	see()
	if out := w.drain(); len(out) != 0 {
		t.Fatalf("first cycle: %v, want nothing yet", out)
	}
	see()
	out := w.drain()
	if eps := out["@91.204.108.4"]; len(eps) != 1 || eps[0].port != 20000 {
		t.Fatalf("second cycle: %v", out)
	}
}
