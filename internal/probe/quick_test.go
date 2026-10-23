package probe

import (
	"sync"
	"testing"
	"time"
)

// Dead: neither direct way gets through the handshake while the tunnel
// gets the name's certificate. Anything else is for the full check.
func TestQuickDead(t *testing.T) {
	oldLookup, oldHello := lookupAnyFn, runHello
	t.Cleanup(func() { lookupAnyFn, runHello = oldLookup, oldHello })
	lookupAnyFn = func(Dialer, []Resolver, string) ([]string, error) { return []string{"192.0.2.10"}, nil }
	direct := Dialer{Addr: "direct", DNS: []Resolver{{}}, Timeout: 8 * time.Second}
	split, tunnel := Dialer{Addr: "split"}, Dialer{Addr: "tunnel"}
	for _, c := range []struct {
		name               string
		direct, split, tun PathResult
		dead               bool
	}{
		{"dead both direct ways", PathResult{}, PathResult{TCPOk: true}, PathResult{TLSOk: true, CertValid: true}, true},
		{"the cut gets through", PathResult{}, PathResult{TLSOk: true, CertValid: true}, PathResult{TLSOk: true, CertValid: true}, false},
		{"direct gets through", PathResult{TLSOk: true}, PathResult{}, PathResult{TLSOk: true, CertValid: true}, false},
		{"the tunnel silent too", PathResult{}, PathResult{}, PathResult{}, false},
		{"the tunnel's certificate not the name's", PathResult{}, PathResult{}, PathResult{TLSOk: true}, false},
	} {
		var mu sync.Mutex
		var waits []time.Duration
		runHello = func(d Dialer, ip, host string) PathResult {
			if ip != "192.0.2.10" || host != "rr1.example" {
				t.Errorf("%s: tried %s for %s", c.name, ip, host)
			}
			mu.Lock()
			waits = append(waits, d.Timeout)
			mu.Unlock()
			return map[string]PathResult{"direct": c.direct, "split": c.split, "tunnel": c.tun}[d.Addr]
		}
		ip, dead := QuickDead(direct, split, tunnel, "rr1.example", time.Second)
		if ip != "192.0.2.10" || dead != c.dead {
			t.Errorf("%s: %s dead=%v, want %v", c.name, ip, dead, c.dead)
		}
		for _, w := range waits {
			if w != time.Second {
				t.Errorf("%s: a way given %s, not the quick wait", c.name, w)
			}
		}
	}
	// no direct DNS to find the node by: nothing tried
	if _, dead := QuickDead(Dialer{}, split, tunnel, "rr1.example", time.Second); dead {
		t.Error("dead with no node to try")
	}
}
