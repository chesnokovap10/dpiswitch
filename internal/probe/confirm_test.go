package probe

import (
	"strings"
	"sync"
	"testing"
)

// A pass failed direct on the handshake, the tunnel got through: a block by
// name only if direct never gets through with the name and mostly does
// without it; the address, if both fail every pass and the tunnel mostly
// gets through;
// anything else an unreliable server (e2c61.gcp.gvt2.com, 09.10: one lucky
// pass with no name kept its BLOCKED_TLS).
func TestConfirmByName(t *testing.T) {
	oldNo, oldTLS := runNoName, runTLS
	t.Cleanup(func() { runNoName, runTLS = oldNo, oldTLS })
	for _, c := range []struct {
		name                     string
		withName, noName, tunnel int // passes through, of 3
		want                     Verdict
		inReason                 string
	}{
		{"by name", 0, 3, 3, BlockedTLS, "silent"},
		{"by name, the tunnel unsteady", 0, 3, 1, BlockedTLS, "silent"},
		{"by name, a lossy direct path (rr17, Beeline)", 0, 2, 3, BlockedTLS, "silent"},
		{"address", 0, 0, 3, BlockedTCP, "the tunnel did 3 of 3"},
		{"address, the tunnel losing one", 0, 0, 2, BlockedTCP, "the tunnel did 2 of 3"},
		{"unreliable, lucky without the name", 0, 1, 1, Inconcl, "0 with the name and 1 without, the tunnel 1"},
		{"unreliable, lucky with the name", 1, 3, 3, Inconcl, "1 with the name"},
		{"a fluke: through with the name every pass", 3, 3, 3, Inconcl, "the failed pass made again"},
		{"unreliable everywhere", 0, 0, 1, Inconcl, "the tunnel 1"},
	} {
		var mu sync.Mutex
		left := map[string]int{"name": c.withName, "none": c.noName, "tunnel": c.tunnel}
		take := func(k string) bool {
			mu.Lock()
			defer mu.Unlock()
			left[k]--
			return left[k] >= 0
		}
		runNoName = func(Dialer, string) PathResult { return PathResult{TLSOk: take("none")} }
		runTLS = func(d Dialer, _, _ string) PathResult {
			if d.Addr == "tunnel" {
				return PathResult{TLSOk: take("tunnel")}
			}
			return PathResult{TLSOk: take("name")}
		}
		rep := Report{Verdict: BlockedTLS, Reason: "silent drop (no reply) on the ClientHello"}
		confirmByName(Dialer{Addr: "direct"}, Dialer{Addr: "tunnel"}, "34.17.18.17", "e2c61.gcp.gvt2.com", &rep)
		if rep.Verdict != c.want || !strings.Contains(rep.Reason, c.inReason) {
			t.Errorf("%s: %s %q", c.name, rep.Verdict, rep.Reason)
		}
	}
}
