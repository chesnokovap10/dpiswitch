package probe

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

type Verdict string

const (
	Clean       Verdict = "CLEAN"        // direct path is clean -- a DIRECT candidate
	BlockedTCP  Verdict = "BLOCKED_TCP"  // cut at the connection level
	BlockedTLS  Verdict = "BLOCKED_TLS"  // cut on ClientHello -- SNI filter
	MITM        Verdict = "MITM"         // certificate substitution
	ContentDiff Verdict = "CONTENT_DIFF" // the response differs -- possibly a block page
	BlockedQUIC Verdict = "BLOCKED_QUIC" // QUIC is blocked (TCP may still be clean)
	Slower      Verdict = "SLOWER"       // not blocked, but the direct path is slower than the tunnel
	Inconcl     Verdict = "INCONCLUSIVE" // the tunnel fails too, nothing to compare against
)

type Report struct {
	Domain    string  `json:"domain"`
	Time      string  `json:"time"`
	Verdict   Verdict `json:"verdict"`
	Reason    string  `json:"reason,omitempty"`
	Attempts  int     `json:"attempts"`
	TestedIP  string  `json:"tested_ip,omitempty"`
	DNSDirect string  `json:"dns_direct,omitempty"`
	DNSTunnel string  `json:"dns_tunnel,omitempty"`
	Port      int     `json:"port,omitempty"`
	Proto     string  `json:"proto,omitempty"`
	Note      string  `json:"note,omitempty"`
	// Aborted: the check failed on our side (the core was restarting);
	// the result says nothing about the site and must not be remembered
	Aborted bool `json:"aborted,omitempty"`
	// DirectNoV6: the node is IPv6 and the direct path did not reach it --
	// see checkProto. No block was seen, but the host does not work direct.
	DirectNoV6 bool `json:"direct_no_v6,omitempty"`
	// Unmeasured: an INCONCLUSIVE because our own side of the check failed --
	// the direct resolver did not answer, the tunnel did not get through. It
	// says nothing about the host: the controller does not back off on it.
	Unmeasured bool       `json:"unmeasured,omitempty"`
	DirectMs   int64      `json:"direct_ms,omitempty"`
	TunnelMs   int64      `json:"tunnel_ms,omitempty"`
	Direct     PathResult `json:"direct"`
	Tunnel     PathResult `json:"tunnel"`
}

// Probing: N passes in a row, CLEAN only if all of them are clean.
// The asymmetry is deliberate -- a false "clean" breaks the site,
// a false "blocked" only costs a detour through the tunnel.
// "not blocked" and "faster" are different things. A domain that opens
// directly but slower than the tunnel is not worth switching: it only gets worse.
// Both a multiplicative and an absolute margin -- so close values don't flap.
const slowMargin = 10 * time.Millisecond

// the factor is configurable from the UI; probes read it from several
// goroutines, so it is stored atomically (in thousandths)
var slowFactorMilli atomic.Int64

func init() { slowFactorMilli.Store(1200) }

// slowBand: hysteresis around the SLOWER threshold. A direct path hovering
// at it flipped CLEAN and SLOWER from one check to the next, and every flip
// to SLOWER counted as a revert: cloudflare-ech.com went 147, 153 and 159 ms
// against a threshold of 144, clean in between.
const slowBand = 0.1

// slower: whether the direct path is too slow to switch to. A CLEAN name
// must get clearly slower to leave, a SLOWER one clearly faster to come back.
func slower(direct, tunnel time.Duration, prev Verdict) bool {
	if tunnel <= 0 {
		return false
	}
	limit := float64(tunnel)*slowFactor() + float64(slowMargin)
	switch prev {
	case Clean:
		limit *= 1 + slowBand
	case Slower:
		limit *= 1 - slowBand
	}
	return float64(direct) > limit
}

func SetSlowFactor(f float64) { slowFactorMilli.Store(int64(f * 1000)) }

func slowFactor() float64 { return float64(slowFactorMilli.Load()) / 1000 }

// CheckProto: udp=true means a QUIC probe on this port. prev is the name's
// current verdict, if any: the latency threshold holds a band around it.
func CheckProto(direct, tunnel Dialer, dom string, port, attempts int, udp bool, prev Verdict) Report {
	rep := checkProto(direct, tunnel, dom, port, attempts, udp, prev)
	// a failure while the core restarts looks like blocking: the prober's
	// listeners simply don't answer. Counting it would revert a working
	// site into the tunnel and postpone its re-check
	if rep.Verdict != Clean && (!direct.Alive() || !tunnel.Alive()) {
		rep.Verdict, rep.Aborted = Inconcl, true
		rep.Reason = "core unavailable (restarting?), check discarded"
	}
	return rep
}

func checkProto(direct, tunnel Dialer, dom string, port, attempts int, udp bool, prev Verdict) Report {
	proto := "tcp"
	if udp {
		proto = "quic"
	}
	rep := Report{Domain: dom, Port: port, Proto: proto, Time: time.Now().Format(time.RFC3339), Attempts: attempts}

	var ip string
	a, isAddr := AddrKey(dom)
	if isAddr {
		// an address seen with no name: there is nothing to resolve, and
		// only plain TCP is probed this way (see the controller)
		ip = a
	} else if len(direct.DNS) > 0 {
		// test exactly the node direct traffic will go to:
		// the address comes from the same resolver the core uses. A spoofed
		// answer is caught by certificate verification -- it fails on a foreign node.
		// if the resolver does not answer, direct traffic would not work either
		ips, err := LookupAny(direct, direct.DNS, dom)
		if err != nil {
			// No A record does not mean "nothing can be said": the host may
			// live on IPv6 only, and then the question is simply whether the
			// direct path has IPv6 at all. Probing its AAAA answers that --
			// on a network without IPv6 the connection fails and the host
			// goes through the tunnel, instead of staying INCONCLUSIVE
			// forever and being swept along direct by its family.
			if v6, e6 := LookupAnyV6(direct, direct.DNS, dom); e6 == nil && len(v6) > 0 {
				ips, err = v6, nil
			}
		}
		if err != nil {
			rep.Verdict, rep.Reason = Inconcl, "direct DNS did not answer: "+errText(err)
			rep.Unmeasured = true
			return rep
		}
		rep.DNSDirect = JoinIPs(ips)
		ip = ips[0]
	} else {
		// reference resolution through the tunnel, which is known not to be spoofed
		tunIPs, err := ResolveVia(tunnel, dom)
		if err != nil || len(tunIPs) == 0 {
			rep.Verdict, rep.Reason = Inconcl, "does not resolve even through the tunnel: "+errText(err)
			rep.Unmeasured = true
			return rep
		}
		rep.DNSTunnel = JoinIPs(tunIPs)
		dirIPs, _ := ResolveVia(direct, dom)
		rep.DNSDirect = JoinIPs(dirIPs)
		ip = tunIPs[0]
	}

	// both sides are tested on the SAME node, otherwise the comparison is meaningless:
	// different CDN nodes are blocked differently
	rep.TestedIP = ip
	v6 := net.ParseIP(ip).To4() == nil
	// a network whose direct path has reached no IPv6 node time after time:
	// probing one more would only show that again (see the controller)
	if v6 && direct.NoV6 {
		rep.Verdict, rep.DirectNoV6 = Inconcl, true
		rep.Reason = "IPv6 node, and the direct path here has no IPv6: not probed"
		return rep
	}

	// take the best measurement across passes, not the last one: the minimum
	// is more robust to random spikes than the average
	var bestDirect, bestTunnel time.Duration
	measured := false
	for i := 0; i < attempts; i++ {
		var d, t PathResult
		switch {
		case udp:
			d, t = RunQUIC(direct, ip, port, dom), RunQUIC(tunnel, ip, port, dom)
		case port == 443:
			d, t = Run(direct, ip, dom), Run(tunnel, ip, dom)
		case port == 80 && !isAddr:
			d, t = RunHTTP(direct, ip, dom), RunHTTP(tunnel, ip, dom)
		default:
			d, t = RunTCP(direct, ip, port), RunTCP(tunnel, ip, port)
		}
		rep.Direct, rep.Tunnel = d, t
		v, reason, noV6 := judgeNode(d, t, v6)
		rep.DirectNoV6 = rep.DirectNoV6 || noV6
		rep.Unmeasured = v == Inconcl && strings.HasPrefix(reason, tunnelDown)
		// for QUIC the handshake is indivisible, so both "transport"
		// failures mean the same thing -- packets did not get through; and an
		// HTTP/3 answer cut or different on the direct path is QUIC's alone
		// too -- as CONTENT_DIFF it would outrank a TCP that works and send
		// the whole name to the tunnel
		if udp && (v == BlockedTCP || v == BlockedTLS || v == ContentDiff) {
			v = BlockedQUIC
		}
		rep.Verdict, rep.Reason = v, reason
		if v != Clean {
			return rep // the first non-clean pass decides
		}
		dt, dok := latency(d)
		tt, tok := latency(t)
		if !dok || !tok {
			continue
		}
		if !measured || dt < bestDirect {
			bestDirect = dt
		}
		if !measured || tt < bestTunnel {
			bestTunnel = tt
		}
		measured = true
	}
	if !measured {
		return rep // plain TCP: nothing to time, see latency
	}
	rep.DirectMs = bestDirect.Milliseconds()
	rep.TunnelMs = bestTunnel.Milliseconds()

	if slower(bestDirect, bestTunnel, prev) {
		rep.Verdict = Slower
		rep.Reason = fmt.Sprintf("direct path is slower: %d ms vs %d via tunnel",
			bestDirect.Milliseconds(), bestTunnel.Milliseconds())
		return rep
	}

	// differing address sets between paths are NOT a sign of blocking:
	// resolvers apply EDNS Client Subnet, and from the VPS address the same google
	// returns a different CDN node than from home. Verified on example.com.
	return rep
}

// latency: how long a path took, by what the probe can time on it.
//
// The SOCKS reply arrives before the core even dials (see confirmDial), so
// TCPTime is the loopback's, not the path's. Over TLS and QUIC the dial and
// the handshake land in TLSTime. Plain HTTP times the request to the first
// byte of the answer -- one round trip over the established path. Plain TCP
// has nothing to time: it used to compare two loopback replies, and the
// 10 ms margin covered them, so SLOWER could never fire there while the log
// showed figures that looked measured.
func latency(r PathResult) (time.Duration, bool) {
	switch {
	case r.TLSTried:
		return r.TCPTime + r.TLSTime, r.TLSOk
	case r.HTTPStatus != 0:
		return r.TTFB, true
	}
	return 0, false
}

// judgeNode: Judge, knowing whether the node is IPv6. An IPv6 node the
// direct path cannot reach is no block the probe saw: the network may have no
// IPv6 at all (this one has none), and the failure then says only that. It
// used to read BLOCKED_TLS with "tls: EOF" -- and a revert. The host still
// must not go direct: the controller counts the direct side as down.
func judgeNode(d, t PathResult, v6 bool) (Verdict, string, bool) {
	v, reason := Judge(d, t)
	if v6 && (v == BlockedTCP || v == BlockedTLS) {
		return Inconcl, "IPv6 node the direct path does not reach (no IPv6 here?): " + reason, true
	}
	return v, reason, false
}

// tunnelDown: the reason Judge gives when the tunnel side failed -- the
// reference is missing, nothing was measured
const tunnelDown = "tunnel path unavailable: "

func Judge(d, t PathResult) (Verdict, string) {
	if !t.TCPOk {
		return Inconcl, tunnelDown + ClassifyErr(t)
	}
	if !d.TCPOk {
		return BlockedTCP, ClassifyErr(d)
	}
	if d.TLSTried || t.TLSTried {
		// The handshake failing on BOTH paths the same way says nothing about
		// blocking: the host does not speak TLS on this port at all, or is dead
		// everywhere. Neither answer is right for it -- CLEAN sent a host that
		// works nowhere direct (a Meta FNA node), and BLOCKED_TLS locked
		// speedtest servers, which serve plain TCP on 20000 and nothing on 443,
		// into the tunnel. INCONCLUSIVE lets another port decide, and a host with
		// no definite verdict at all does not go direct.
		if !d.TLSOk && !t.TLSOk {
			return Inconcl, "fails the same on both paths: " + ClassifyErr(d)
		}
		// Only the direct path failing is blocking. A false "blocked" only
		// costs a detour through the tunnel.
		if !d.TLSOk {
			return BlockedTLS, ClassifyErr(d)
		}
		if !t.TLSOk {
			return Inconcl, tunnelDown + ClassifyErr(t)
		}
		// certificate fingerprints cannot be compared -- different CDN nodes serve
		// different valid certificates. The sign of substitution: the direct path's
		// chain fails verification while the tunnel's passes.
		if t.CertValid && !d.CertValid {
			return MITM, "direct path certificate fails chain verification (CN=" + d.CertCN + ")"
		}
	}
	// The handshake going through is not the end of it: DPI may let the
	// ClientHello pass and cut the session once data flows. Those failures
	// used to be recorded and then ignored -- no status and no body on the
	// direct path meant "nothing to compare", and the host came out CLEAN.
	// The same failure on both paths is the server's doing, as with TLS.
	dh, th := d.HTTPFailed(), t.HTTPFailed()
	if dh && th {
		return Inconcl, "no HTTP answer on either path: " + ClassifyErr(d)
	}
	if dh {
		return ContentDiff, "direct path cut after connecting: " + ClassifyErr(d)
	}
	if d.HTTPStatus != 0 && t.HTTPStatus != 0 && d.HTTPStatus != t.HTTPStatus {
		// the tunnel is not an absolute reference. Its exit is in a data centre,
		// and Cloudflare serves such addresses a challenge instead of content.
		// if the direct path gets a normal answer and the tunnel gets
		// a blocking status, it is the tunnel that is broken, and moving the domain
		// into it would pick a known-broken path.
		if d.HTTPStatus < 400 && isChallenge(t.HTTPStatus) {
			return Clean, ""
		}
		return ContentDiff, fmt.Sprintf("HTTP %d direct vs %d via tunnel", d.HTTPStatus, t.HTTPStatus)
	}
	// plain HTTP: an ISP answers a blocked Host with a redirect to its own
	// block page, often with the very status the site uses for its HTTPS
	// redirect. Over TLS nobody in between can forge a redirect, and a
	// different target there is the site's own geo choice.
	if !d.TLSTried && d.RedirectHost != "" && t.RedirectHost != "" && d.RedirectHost != t.RedirectHost {
		return ContentDiff, "redirected to " + d.RedirectHost + " direct vs " + t.RedirectHost + " via tunnel"
	}
	// a body the tunnel failed to finish is no reference for its size
	if !th && d.BodyLen > 0 && t.BodyLen > 0 && !isChallenge(t.HTTPStatus) {
		ratio := float64(d.BodyLen) / float64(t.BodyLen)
		if ratio < 0.25 || ratio > 4 {
			return ContentDiff, fmt.Sprintf("response size %d vs %d bytes", d.BodyLen, t.BodyLen)
		}
	}
	return Clean, ""
}

// statuses returned by bot protection rather than the site itself
func isChallenge(code int) bool {
	return code == 403 || code == 429 || code == 503
}

func errText(err error) string {
	if err == nil {
		return "-"
	}
	return Truncate(err.Error(), 70)
}
