package ctl

import (
	"errors"
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

// The public address could not be checked: it is not asked again at the
// next tick, but after ipBackoff -- it was, every ten seconds, with RIPE
// out of reach
func TestResolveNetworkIPBackoff(t *testing.T) {
	netIDMu.Lock()
	netIDVal, netIDWhen = "gw1", time.Now().Add(time.Hour)
	netIDMu.Unlock()
	checks := 0
	fail := true
	oldLookup, oldIP, oldRetry := lookupASNFn, publicIPFn, lookupRetry
	lookupASNFn = func(string) (string, string, error) { return "AS1", "203.0.113.1", nil }
	publicIPFn = func(string) (string, error) {
		checks++
		if fail {
			return "", errors.New("RIPE down")
		}
		return "203.0.113.1", nil
	}
	lookupRetry = 0
	t.Cleanup(func() {
		lookupASNFn, publicIPFn, lookupRetry = oldLookup, oldIP, oldRetry
		netIDMu.Lock()
		netIDVal, netIDWhen = "", time.Time{}
		netIDMu.Unlock()
	})
	st := loadState(filepath.Join(t.TempDir(), "state.json"))
	resolveNetwork(Config{}, st)
	age := func() {
		st.mu.Lock()
		a := st.Attach["gw1"]
		a.IPChecked = time.Now().Add(-2 * ipRecheck)
		st.Attach["gw1"] = a
		st.mu.Unlock()
	}
	age()
	for range 3 {
		if got := resolveNetwork(Config{}, st); got != "AS1" {
			t.Fatalf("got %s", got)
		}
	}
	if checks != 1 {
		t.Fatalf("the failing check asked %d times in a row", checks)
	}
	// the backoff over: asked again, and it answers
	st.mu.Lock()
	st.ipFailed["gw1"] = time.Now().Add(-2 * ipBackoff)
	st.mu.Unlock()
	fail = false
	resolveNetwork(Config{}, st)
	if checks != 2 || st.ipHeld("gw1") {
		t.Fatalf("after the backoff: %d checks, held %v", checks, st.ipHeld("gw1"))
	}
}

// The public address changed and the ISP lookup failed: the old ISP's
// verdicts are not borrowed -- the gateway's memory until the lookup works.
func TestResolveNetworkMovedLookupFails(t *testing.T) {
	netIDMu.Lock()
	netIDVal, netIDWhen = "gw1", time.Now().Add(time.Hour)
	netIDMu.Unlock()
	ip := "203.0.113.1"
	var failing bool
	oldLookup, oldIP, oldRetry := lookupASNFn, publicIPFn, lookupRetry
	lookupASNFn = func(string) (string, string, error) {
		if failing {
			return "", "", errors.New("RIPE down")
		}
		return "AS1", ip, nil
	}
	publicIPFn = func(string) (string, error) { return ip, nil }
	lookupRetry = 0
	t.Cleanup(func() {
		lookupASNFn, publicIPFn, lookupRetry = oldLookup, oldIP, oldRetry
		netIDMu.Lock()
		netIDVal, netIDWhen = "", time.Time{}
		netIDMu.Unlock()
	})
	st := loadState(filepath.Join(t.TempDir(), "state.json"))
	if got := resolveNetwork(Config{}, st); got != "AS1" {
		t.Fatalf("first: %s", got)
	}
	st.staleIP("gw1")
	ip, failing = "198.51.100.7", true
	if got := resolveNetwork(Config{}, st); got != "gw1" {
		t.Fatalf("moved, lookup failed: %s, want the gateway's memory", got)
	}
	// the address check alone failing is no sign of a move
	st.staleIP("gw1")
	publicIPFn = func(string) (string, error) { return "", errors.New("RIPE down") }
	if got := resolveNetwork(Config{}, st); got != "AS1" {
		t.Fatalf("address unknown: %s, want the cached ISP", got)
	}
}

// A cycle's results are filed only while the public address is the one
// the ISP was found by.
func TestIPStill(t *testing.T) {
	ip := "203.0.113.1"
	checks := 0
	oldIP := publicIPFn
	publicIPFn = func(string) (string, error) { checks++; return ip, nil }
	t.Cleanup(func() { publicIPFn = oldIP })
	st := loadState(filepath.Join(t.TempDir(), "state.json"))
	st.attach("gw1", "AS1", ip)
	if !ipStill(Config{}, st, "gw1") || checks != 0 {
		t.Fatalf("checked just now: asked %d times", checks)
	}
	st.staleIP("gw1")
	if !ipStill(Config{}, st, "gw1") || checks != 1 {
		t.Fatal("the same address taken for a change")
	}
	st.staleIP("gw1")
	ip = "198.51.100.7"
	if ipStill(Config{}, st, "gw1") {
		t.Fatal("a changed address not seen")
	}
	if a, _ := st.attached("gw1"); !a.IPChecked.IsZero() {
		t.Fatal("the change not left for the main loop to look up")
	}
	if !ipStill(Config{}, st, "unknown-gw") {
		t.Fatal("a gateway with no ISP known held the results back")
	}
}

// The ISP not found, the lookup is left alone for a while: with RIPE out of
// reach every tick spent most of its minute in three tries. The answer is
// what the failure gave -- the gateway's own memory for a gateway with no
// ISP known -- and the lookup is tried again once the pause is over.
func TestResolveNetworkLookupBackoff(t *testing.T) {
	netIDMu.Lock()
	netIDVal, netIDWhen = "gw1", time.Now().Add(time.Hour)
	netIDMu.Unlock()
	lookups := 0
	oldLookup, oldIP, oldRetry, oldBackoff := lookupASNFn, publicIPFn, lookupRetry, lookupBackoff
	lookupASNFn = func(string) (string, string, error) { lookups++; return "", "", errors.New("RIPE down") }
	publicIPFn = func(string) (string, error) { return "", errors.New("RIPE down") }
	lookupRetry = 0
	t.Cleanup(func() {
		lookupASNFn, publicIPFn, lookupRetry, lookupBackoff = oldLookup, oldIP, oldRetry, oldBackoff
		netIDMu.Lock()
		netIDVal, netIDWhen = "", time.Time{}
		netIDMu.Unlock()
	})
	st := loadState(filepath.Join(t.TempDir(), "state.json"))
	if got := resolveNetwork(Config{}, st); got != "gw1" || lookups != 3 {
		t.Fatalf("first: %s after %d lookups", got, lookups)
	}
	if got := resolveNetwork(Config{}, st); got != "gw1" || lookups != 3 {
		t.Fatalf("within the pause: %s, %d lookups", got, lookups)
	}
	lookupBackoff = 0
	lookupASNFn = func(string) (string, string, error) { lookups++; return "AS1", "203.0.113.1", nil }
	if got := resolveNetwork(Config{}, st); got != "AS1" || lookups != 4 {
		t.Fatalf("after the pause: %s, %d lookups", got, lookups)
	}
}
