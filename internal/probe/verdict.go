package probe

import (
	"fmt"
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
	Aborted  bool       `json:"aborted,omitempty"`
	DirectMs int64      `json:"direct_ms,omitempty"`
	TunnelMs int64      `json:"tunnel_ms,omitempty"`
	Direct   PathResult `json:"direct"`
	Tunnel   PathResult `json:"tunnel"`
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

func SetSlowFactor(f float64) { slowFactorMilli.Store(int64(f * 1000)) }

func slowFactor() float64 { return float64(slowFactorMilli.Load()) / 1000 }

// CheckProto: udp=true means a QUIC probe on this port.
func CheckProto(direct, tunnel Dialer, dom string, port, attempts int, udp bool) Report {
	rep := checkProto(direct, tunnel, dom, port, attempts, udp)
	// a failure while the core restarts looks like blocking: the prober's
	// listeners simply don't answer. Counting it would revert a working
	// site into the tunnel and postpone its re-check
	if rep.Verdict != Clean && (!direct.Alive() || !tunnel.Alive()) {
		rep.Verdict, rep.Aborted = Inconcl, true
		rep.Reason = "core unavailable (restarting?), check discarded"
	}
	return rep
}

func checkProto(direct, tunnel Dialer, dom string, port, attempts int, udp bool) Report {
	proto := "tcp"
	if udp {
		proto = "quic"
	}
	rep := Report{Domain: dom, Port: port, Proto: proto, Time: time.Now().Format(time.RFC3339), Attempts: attempts}

	var ip string
	if len(direct.DNS) > 0 {
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
			return rep
		}
		rep.DNSDirect = JoinIPs(ips)
		ip = ips[0]
	} else {
		// reference resolution through the tunnel, which is known not to be spoofed
		tunIPs, err := ResolveVia(tunnel, dom)
		if err != nil || len(tunIPs) == 0 {
			rep.Verdict, rep.Reason = Inconcl, "does not resolve even through the tunnel: "+errText(err)
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

	// take the best measurement across passes, not the last one: the minimum
	// is more robust to random spikes than the average
	var bestDirect, bestTunnel time.Duration
	for i := 0; i < attempts; i++ {
		var d, t PathResult
		switch {
		case udp:
			d, t = RunQUIC(direct, ip, port, dom), RunQUIC(tunnel, ip, port, dom)
		case port == 443:
			d, t = Run(direct, ip, dom), Run(tunnel, ip, dom)
		default:
			d, t = RunTCP(direct, ip, port), RunTCP(tunnel, ip, port)
		}
		rep.Direct, rep.Tunnel = d, t
		v, reason := Judge(d, t)
		// for QUIC the handshake is indivisible, so both "transport"
		// failures mean the same thing -- packets did not get through
		if udp && (v == BlockedTCP || v == BlockedTLS) {
			v = BlockedQUIC
		}
		rep.Verdict, rep.Reason = v, reason
		if v != Clean {
			return rep // the first non-clean pass decides
		}
		if dt := d.TCPTime + d.TLSTime; bestDirect == 0 || dt < bestDirect {
			bestDirect = dt
		}
		if tt := t.TCPTime + t.TLSTime; bestTunnel == 0 || tt < bestTunnel {
			bestTunnel = tt
		}
	}
	rep.DirectMs = bestDirect.Milliseconds()
	rep.TunnelMs = bestTunnel.Milliseconds()

	if bestTunnel > 0 && bestDirect > time.Duration(float64(bestTunnel)*slowFactor())+slowMargin {
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

func Judge(d, t PathResult) (Verdict, string) {
	if !t.TCPOk {
		return Inconcl, "tunnel path unavailable: " + ClassifyErr(t)
	}
	if !d.TCPOk {
		return BlockedTCP, ClassifyErr(d)
	}
	// a probe without TLS (not 443): nothing more to compare
	if !d.TLSTried && !t.TLSTried {
		return Clean, ""
	}
	// The direct path decides on its own: if its handshake fails, the site
	// does not work direct, whatever the tunnel did. This used to be checked
	// after the tunnel, so a host that answered on neither path fell into the
	// "no TLS anywhere" branch above and came out CLEAN -- and a host that
	// works nowhere was then sent direct, where it kept not working.
	// A false "blocked" only costs a detour through the tunnel.
	if !d.TLSOk {
		return BlockedTLS, ClassifyErr(d)
	}
	if !t.TLSOk {
		return Inconcl, "tunnel path unavailable: " + ClassifyErr(t)
	}
	// certificate fingerprints cannot be compared -- different CDN nodes serve
	// different valid certificates. The sign of substitution: the direct path's
	// chain fails verification while the tunnel's passes.
	if t.CertValid && !d.CertValid {
		return MITM, "direct path certificate fails chain verification (CN=" + d.CertCN + ")"
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
	if d.BodyLen > 0 && t.BodyLen > 0 && !isChallenge(t.HTTPStatus) {
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
