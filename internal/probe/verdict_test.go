package probe

import "testing"

func TestJudge(t *testing.T) {
	tls := func(ok bool) PathResult {
		return PathResult{TCPOk: true, TLSTried: true, TLSOk: ok, CertValid: ok, Err: "handshake failure"}
	}
	plain := func() PathResult { return PathResult{TCPOk: true} }

	cases := []struct {
		name string
		d, t PathResult
		want Verdict
	}{
		// the regression: fbcdn answered on neither path, and the verdict was
		// CLEAN, so the host was routed direct and stayed broken
		{"tls fails on both paths", tls(false), tls(false), BlockedTLS},
		{"tls fails direct only", tls(false), tls(true), BlockedTLS},
		{"tls fails through tunnel only", tls(true), tls(false), Inconcl},
		{"tls fine on both", tls(true), tls(true), Clean},
		{"port without tls", plain(), plain(), Clean},
		{"tcp fails direct", PathResult{}, tls(true), BlockedTCP},
		{"tcp fails through tunnel", tls(true), PathResult{}, Inconcl},
	}
	for _, c := range cases {
		if got, reason := Judge(c.d, c.t); got != c.want {
			t.Errorf("%s: got %v (%s), want %v", c.name, got, reason, c.want)
		}
	}
}
