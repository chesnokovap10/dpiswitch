package ctl

import (
	"testing"

	"dpiswitch/internal/probe"
)

// A name's verdict is its worst port's, whatever order the ports come in:
// SLOWER on 443 first held its place against BLOCKED_TLS on 5228 after it,
// and a CLEAN kept once before sent the name direct.
func TestWorseOrderFree(t *testing.T) {
	fold := func(vs []probe.Verdict) probe.Verdict {
		var rep probe.Verdict
		for i, v := range vs {
			if i == 0 || worse(v, rep) {
				rep = v
			}
		}
		return rep
	}
	for _, tc := range []struct {
		ports []probe.Verdict
		want  probe.Verdict
	}{
		{[]probe.Verdict{probe.Slower, probe.BlockedTLS}, probe.BlockedTLS},
		{[]probe.Verdict{probe.Slower, probe.BlockedQUIC}, probe.BlockedQUIC},
		{[]probe.Verdict{probe.ContentDiff, probe.BlockedTLS}, probe.BlockedTLS},
		{[]probe.Verdict{probe.Clean, probe.Inconcl}, probe.Clean},
		{[]probe.Verdict{probe.Inconcl, probe.Inconcl}, probe.Inconcl},
		{[]probe.Verdict{probe.MITM, probe.BlockedTCP, probe.Clean}, probe.MITM},
	} {
		rev := make([]probe.Verdict, len(tc.ports))
		for i, v := range tc.ports {
			rev[len(rev)-1-i] = v
		}
		if a, b := fold(tc.ports), fold(rev); a != tc.want || b != tc.want {
			t.Errorf("%v: %s / reversed %s, want %s", tc.ports, a, b, tc.want)
		}
	}
	// every verdict has a rank: an unknown one would sink below INCONCLUSIVE
	for _, v := range []probe.Verdict{probe.Clean, probe.BlockedTCP, probe.BlockedTLS, probe.MITM,
		probe.ContentDiff, probe.BlockedQUIC, probe.Slower, probe.Inconcl} {
		if _, ok := verdictRank[v]; !ok {
			t.Errorf("%s has no rank", v)
		}
	}
}
