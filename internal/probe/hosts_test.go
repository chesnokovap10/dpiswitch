package probe

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestProtectedProbesNeverDialRealAddress(t *testing.T) {
	old := lookupProbeHosts
	t.Cleanup(func() { lookupProbeHosts = old })
	for _, readErr := range []error{nil, errors.New("hosts unreadable")} {
		lookupProbeHosts = func(string) ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, readErr }
		d := Dialer{RespectHosts: true, Addr: "invalid-listener", Timeout: time.Millisecond}
		for _, r := range []PathResult{Run(d, "203.0.113.1", "protected.example"), RunHTTP(d, "203.0.113.1", "protected.example"), RunQUIC(d, "203.0.113.1", 443, "protected.example"), runHello(d, "203.0.113.1", "protected.example"), RunNoName(d.forDomain("protected.example"), "203.0.113.1"), RunTCP(d.forDomain("protected.example"), "203.0.113.1", 1234)} {
			if r.TCPOk || !strings.Contains(r.Err, "hosts") {
				t.Fatalf("probe reached dial instead of hosts guard: %+v", r)
			}
		}
		rep, _ := checkFamily(d, Dialer{}, "protected.example", 443, 1, false, "", false)
		if !rep.Unmeasured || rep.TestedIP != "" || rep.Verdict != Inconcl {
			t.Fatalf("protected host was measured: %+v", rep)
		}
		// Tunnel diagnostics remain independent of the direct-only guard.
		if err := (Dialer{}).checkHosts("protected.example"); err != nil {
			t.Fatal(err)
		}
	}
}
