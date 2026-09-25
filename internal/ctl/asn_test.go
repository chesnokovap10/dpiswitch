package ctl

import (
	"path/filepath"
	"testing"
	"time"
)

// The router switched to another uplink, the gateway and its MAC the same:
// the changed public address has the ISP looked up at once, not after the
// hour the ISP is cached for.
func TestResolveNetworkUplinkChange(t *testing.T) {
	netIDMu.Lock()
	netIDVal, netIDWhen = "gw1", time.Now().Add(time.Hour)
	netIDMu.Unlock()
	ip, asn := "203.0.113.1", "AS1"
	lookups, ipChecks := 0, 0
	oldLookup, oldIP, oldRetry := lookupASNFn, publicIPFn, lookupRetry
	lookupASNFn = func(string) (string, string, error) { lookups++; return asn, ip, nil }
	publicIPFn = func(string) (string, error) { ipChecks++; return ip, nil }
	lookupRetry = 0
	t.Cleanup(func() {
		lookupASNFn, publicIPFn, lookupRetry = oldLookup, oldIP, oldRetry
		netIDMu.Lock()
		netIDVal, netIDWhen = "", time.Time{}
		netIDMu.Unlock()
	})

	st := loadState(filepath.Join(t.TempDir(), "state.json"))
	if got := resolveNetwork(Config{}, st); got != "AS1" || lookups != 1 {
		t.Fatalf("first: %s after %d lookups", got, lookups)
	}
	// within ipRecheck: nothing asked
	if got := resolveNetwork(Config{}, st); got != "AS1" || lookups != 1 || ipChecks != 0 {
		t.Fatalf("cached: %s, %d lookups, %d address checks", got, lookups, ipChecks)
	}
	age := func() {
		st.mu.Lock()
		a := st.Attach["gw1"]
		a.IPChecked = time.Now().Add(-2 * ipRecheck)
		st.Attach["gw1"] = a
		st.mu.Unlock()
	}
	// the same address: the ISP is not looked up again
	age()
	if got := resolveNetwork(Config{}, st); got != "AS1" || lookups != 1 || ipChecks != 1 {
		t.Fatalf("same address: %s, %d lookups, %d address checks", got, lookups, ipChecks)
	}
	// another uplink
	age()
	ip, asn = "198.51.100.7", "AS2"
	if got := resolveNetwork(Config{}, st); got != "AS2" || lookups != 2 {
		t.Fatalf("new uplink: %s after %d lookups", got, lookups)
	}
}
