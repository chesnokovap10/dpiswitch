package probe

import (
	"crypto/tls"
	"sync"
	"time"
)

// QuickDead: one pass at once on the name's node -- the handshake direct,
// with the ClientHello cut, and through the tunnel, each given wait -- for a
// host that goes direct by its family's rule before it has a verdict of its
// own. dead: neither direct way got through the handshake while the tunnel
// got the name's own certificate. The full check takes three timeouts for
// it: its pass, the passes confirming it, then the cut's -- 25 s on 23.10,
// a googlevideo node whose address does not answer direct, the player
// hanging on it meanwhile. ip: the node tried, the one direct DNS gives
// first, as the full check takes it; "" when there is none to try.
func QuickDead(direct, split, tunnel Dialer, dom string, wait time.Duration) (ip string, dead bool) {
	if len(direct.DNS) == 0 {
		return "", false
	}
	ips, err := lookupAnyFn(direct, direct.DNS, dom)
	if err != nil || len(ips) == 0 {
		return "", false
	}
	ip = ips[0]
	var d, s, t PathResult
	var wg sync.WaitGroup
	for _, p := range []struct {
		dl  Dialer
		out *PathResult
	}{{direct, &d}, {split, &s}, {tunnel, &t}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dl := p.dl
			dl.Timeout = wait
			*p.out = runHello(dl, ip, dom)
		}()
	}
	wg.Wait()
	return ip, !d.TLSOk && !s.TLSOk && t.TLSOk && t.CertValid
}

// runHello: the TLS handshake on 443 with the name, and the certificate
// checked -- Run's first half, with no request after it
var runHello = func(d Dialer, ip, host string) PathResult {
	var r PathResult
	r.IP = ip
	conn, err := d.dial(ip, 443)
	if err != nil {
		r.Err, r.ErrStage = err.Error(), "tcp"
		return r
	}
	defer conn.Close()
	r.TCPOk, r.TLSTried = true, true
	tc := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
	_ = tc.SetDeadline(time.Now().Add(d.Timeout))
	if err := tc.Handshake(); err != nil {
		r.Err, r.ErrStage = err.Error(), "tls"
		return r
	}
	r.TLSOk = true
	r.CertValid = verifyChain(host, tc.ConnectionState().PeerCertificates)
	return r
}
