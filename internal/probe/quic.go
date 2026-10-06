package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// QUIC probe. A real handshake rather than a hand-crafted probe packet:
// servers silently ignore anything invalid, so a missing answer to a crafted
// packet would be mistaken for blocking. A false "blocked" is tolerable, but a
// false "clean" breaks the site -- and a crafted probe yields exactly that if
// DPI filters on the SNI inside the Initial packet.
func RunQUIC(d Dialer, ip string, port int, host string) PathResult {
	var r PathResult
	r.IP = ip

	pc, err := d.DialUDP()
	if err != nil {
		r.Err, r.ErrStage = err.Error(), "udp_associate"
		return r
	}
	defer pc.Close()

	addr := &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
	if addr.IP == nil {
		r.Err, r.ErrStage = "cannot parse address "+ip, "udp_associate"
		return r
	}

	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	t0 := time.Now()
	conn, err := quic.Dial(ctx, pc, addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // we need the certificate even if forged: that is the signal
		NextProtos:         []string{"h3"},
	}, &quic.Config{
		HandshakeIdleTimeout: d.Timeout,
		KeepAlivePeriod:      0,
	})
	if err != nil {
		r.Err, r.ErrStage = err.Error(), "quic"
		return r
	}
	defer conn.CloseWithError(0, "")

	// for QUIC the handshake is indivisible: success means both datagram
	// delivery and a completed TLS. Map it onto the same fields so Judge
	// works without special cases.
	r.TCPOk, r.TLSOk, r.TLSTried = true, true, true
	r.TLSTime = time.Since(t0)

	st := conn.ConnectionState().TLS
	r.ALPN = st.NegotiatedProtocol
	if len(st.PeerCertificates) > 0 {
		leaf := st.PeerCertificates[0]
		sum := sha256.Sum256(leaf.Raw)
		r.CertSHA256 = hex.EncodeToString(sum[:])
		r.CertCN = leaf.Subject.CommonName
		r.CertValid = verifyChain(host, st.PeerCertificates)
	}
	// and a request: a handshake alone called a site clean that DPI lets
	// through the Initial and cuts after
	if r.ALPN == "h3" {
		h3Get(ctx, &r, conn, host)
	}
	return r
}

// StatusUnreadableH3: the status of an HTTP/3 answer quic-go would not
// read, see h3Get. Not a real status: alike on both paths, it compares equal.
const StatusUnreadableH3 = 1

// h3Get sends GET / over an established QUIC connection that chose h3.
func h3Get(ctx context.Context, r *PathResult, conn *quic.Conn, host string) {
	t2 := time.Now()
	resp, err := (&http3.Transport{}).NewClientConn(conn).RoundTrip(probeRequest(host).WithContext(ctx))
	if err != nil && strings.HasPrefix(err.Error(), "http3: invalid response:") {
		// the server's HEADERS frame came whole, and quic-go turned it down:
		// googlevideo.com answers with a "connection" field, which HTTP/3
		// forbids. An answer all the same -- what the request is there to
		// show is that the path carries one past the handshake
		r.TTFB = time.Since(t2)
		r.HTTPStatus = StatusUnreadableH3
		return
	}
	if err != nil {
		r.Err, r.ErrStage = err.Error(), "http_read"
		return
	}
	readResponse(r, resp, host, t2)
}
