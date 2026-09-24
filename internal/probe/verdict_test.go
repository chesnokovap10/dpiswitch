package probe

import (
	"testing"
	"time"
)

func TestJudge(t *testing.T) {
	tls := func(ok bool) PathResult {
		return PathResult{TCPOk: true, TLSTried: true, TLSOk: ok, CertValid: ok, Err: "handshake failure"}
	}
	plain := func() PathResult { return PathResult{TCPOk: true} }
	cut := func(r PathResult, stage string) PathResult {
		r.Err, r.ErrStage = "read: connection reset by peer", stage
		return r
	}
	answered := func(r PathResult, status int) PathResult {
		r.Err, r.ErrStage = "", ""
		r.HTTPStatus, r.BodyLen = status, 5000
		return r
	}
	redirect := func(status int, to string) PathResult {
		r := answered(plain(), status)
		r.RedirectHost, r.BodyLen = to, 150
		return r
	}

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
		// the handshake passes and the session is cut once data flows: it
		// used to be CLEAN, the failure recorded and then ignored
		{"cut after the handshake, direct", cut(tls(true), "http_read"), answered(tls(true), 200), ContentDiff},
		{"body cut short, direct", cut(answered(tls(true), 200), "body"), answered(tls(true), 200), ContentDiff},
		{"no http answer on both paths", cut(tls(true), "http_read"), cut(tls(true), "http_read"), Inconcl},
		{"no http answer via tunnel only", answered(tls(true), 200), cut(tls(true), "http_read"), Clean},
		// plain HTTP on 80: the ISP redirects a blocked Host to its own page
		{"http reset after the request", cut(plain(), "http_read"), answered(plain(), 200), ContentDiff},
		{"http redirect to a block page", redirect(302, "warning.rt.ru"), redirect(302, "example.com"), ContentDiff},
		{"http same redirect", redirect(301, "example.com"), redirect(301, "example.com"), Clean},
	}
	for _, c := range cases {
		if got, reason := Judge(c.d, c.t); got != c.want {
			t.Errorf("%s: got %v (%s), want %v", c.name, got, reason, c.want)
		}
	}
}

// Only what was really timed counts: the SOCKS reply is loopback's.
func TestLatency(t *testing.T) {
	ms := time.Millisecond
	cases := []struct {
		name string
		r    PathResult
		want time.Duration
		ok   bool
	}{
		{"tls: dial and handshake", PathResult{TCPOk: true, TCPTime: ms, TLSTried: true, TLSOk: true, TLSTime: 40 * ms}, 41 * ms, true},
		{"tls failed", PathResult{TCPOk: true, TLSTried: true}, 0, false},
		{"plain http: first byte", PathResult{TCPOk: true, TCPTime: ms, HTTPStatus: 200, TTFB: 30 * ms}, 30 * ms, true},
		{"plain tcp: nothing to time", PathResult{TCPOk: true, TCPTime: ms}, 0, false},
	}
	for _, c := range cases {
		if got, ok := latency(c.r); got != c.want || ok != c.ok {
			t.Errorf("%s: got %v %v, want %v %v", c.name, got, ok, c.want, c.ok)
		}
	}
}
