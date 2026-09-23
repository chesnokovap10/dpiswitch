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
		// failing identically on both paths is not a blocking signal. It used
		// to be CLEAN (a dead Meta node went direct), then BLOCKED_TLS
		// (speedtest servers, which have no TLS on 443, went to the tunnel)
		{"tls fails on both paths", tls(false), tls(false), Inconcl},
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
