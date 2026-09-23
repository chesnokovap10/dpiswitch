package probe

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// result of one pass over one path (direct or tunnel)
type PathResult struct {
	IP      string        `json:"ip,omitempty"`
	TCPOk   bool          `json:"tcp_ok"`
	TCPTime time.Duration `json:"tcp_time_ns"`
	TLSOk   bool          `json:"tls_ok"`
	// TLSTried separates "not a TLS port, nothing was attempted" from
	// "the handshake was attempted and failed" -- the two used to be
	// indistinguishable in Judge, which read the second as "no difference
	// between the paths" and called a host that answers nowhere clean.
	TLSTried   bool          `json:"tls_tried"`
	TLSTime    time.Duration `json:"tls_time_ns"`
	CertSHA256 string        `json:"cert_sha256,omitempty"`
	CertCN     string        `json:"cert_cn,omitempty"`
	CertValid  bool          `json:"cert_valid"`
	ALPN       string        `json:"alpn,omitempty"`
	HTTPStatus int           `json:"http_status,omitempty"`
	BodySHA256 string        `json:"body_sha256,omitempty"`
	BodyLen    int           `json:"body_len"`
	TTFB       time.Duration `json:"ttfb_ns"`
	Err        string        `json:"err,omitempty"`
	ErrStage   string        `json:"err_stage,omitempty"`
}

const bodyLimit = 64 << 10 // read at most 64 KB: we need a fingerprint, not the content

// ip is the exact node under test; host is the name for SNI and Host.
// We connect by IP so a broken handshake cannot be confused with a failed
// resolution, and we know exactly which node was tested.
func Run(d Dialer, ip, host string) PathResult {
	var r PathResult
	r.IP = ip

	t0 := time.Now()
	conn, err := d.dial(ip, 443)
	if err != nil {
		r.Err, r.ErrStage = err.Error(), "tcp"
		return r
	}
	defer conn.Close()
	r.TCPOk, r.TCPTime = true, time.Since(t0)

	// InsecureSkipVerify: we need the certificate even if it is forged --
	// the forgery is the signal. Validity is checked separately, by hand.
	t1 := time.Now()
	r.TLSTried = true
	tc := tls.Client(conn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	_ = tc.SetDeadline(time.Now().Add(d.Timeout))
	if err := tc.Handshake(); err != nil {
		r.Err, r.ErrStage = err.Error(), "tls"
		return r
	}
	r.TLSOk, r.TLSTime = true, time.Since(t1)

	st := tc.ConnectionState()
	r.ALPN = st.NegotiatedProtocol
	if len(st.PeerCertificates) > 0 {
		leaf := st.PeerCertificates[0]
		sum := sha256.Sum256(leaf.Raw)
		r.CertSHA256 = hex.EncodeToString(sum[:])
		r.CertCN = leaf.Subject.CommonName
		r.CertValid = verifyChain(host, st.PeerCertificates)
	}

	// a hand-written HTTP/1.1 request: http.Client on top of an existing
	// conn would take timing out of our control
	if st.NegotiatedProtocol == "h2" {
		// h2 is not parsed; a successful TLS handshake is enough
		return r
	}
	req := "GET / HTTP/1.1\r\nHost: " + host + "\r\n" +
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140.0.0.0 Safari/537.36\r\n" +
		"Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
	t2 := time.Now()
	if _, err := tc.Write([]byte(req)); err != nil {
		r.Err, r.ErrStage = err.Error(), "http_write"
		return r
	}
	br := bufio.NewReader(tc)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		r.Err, r.ErrStage = err.Error(), "http_read"
		return r
	}
	r.TTFB = time.Since(t2)
	r.HTTPStatus = resp.StatusCode
	body, err := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
	resp.Body.Close()
	if err != nil && len(body) == 0 {
		r.Err, r.ErrStage = err.Error(), "body"
		return r
	}
	r.BodyLen = len(body)
	sum := sha256.Sum256(body)
	r.BodySHA256 = hex.EncodeToString(sum[:])
	return r
}

// TCP-only probe for ports that may not speak TLS. A weaker signal --
// no SNI, certificate or response body -- but DPI connection resets
// still show up here.
func RunTCP(d Dialer, ip string, port int) PathResult {
	var r PathResult
	r.IP = ip
	t0 := time.Now()
	conn, err := d.dial(ip, port)
	if err != nil {
		r.Err, r.ErrStage = err.Error(), "tcp"
		return r
	}
	defer conn.Close()
	r.TCPTime = time.Since(t0)
	if err := confirmDial(conn, d.Established); err != nil {
		r.Err, r.ErrStage = err.Error(), "tcp"
		return r
	}
	r.TCPOk = true
	return r
}

// AddrPrefix marks a verdict kept for a bare address rather than a name.
const AddrPrefix = "@"

// AddrKey reports whether a verdict key stands for a bare address, and which.
func AddrKey(key string) (string, bool) {
	if !strings.HasPrefix(key, AddrPrefix) {
		return "", false
	}
	ip := net.ParseIP(strings.TrimPrefix(key, AddrPrefix))
	if ip == nil {
		return "", false
	}
	return ip.String(), true
}

// confirmWindow covers mihomo's own dial: C.DefaultTCPTimeout is 5 s, and
// the retries it makes all fit inside that one context.
var confirmWindow = 6 * time.Second

// confirmPoll: how often the core is asked while waiting.
var confirmPoll = 100 * time.Millisecond

// confirmDial: the SOCKS "succeeded" reply means nothing yet. mihomo answers
// CONNECT BEFORE it dials the target (listener/socks and listener/http both
// write success and only then hand the connection to the tunnel), and when
// the dial fails it simply closes the connection. On 443 the TLS handshake
// exposes that; on any other port the reply was all the probe looked at, so a
// host unreachable over the direct path came out CLEAN.
//
// The connection closing is not proof of a failed dial either: a speedtest
// server hangs up on a silent client after four seconds. What does tell is the
// core itself -- a dial that went through is tracked in its connection list,
// a failed one never appears there. So poll it, and watch the connection in
// between: seen by the core -> dialled; data from the server -> dialled;
// closed without ever being seen -> the dial failed. Nothing is written: the
// probe does not know the protocol behind the port.
func confirmDial(conn net.Conn, established func(int) (bool, error)) error {
	port := 0
	if a, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		port = a.Port
	}
	ask := func() (seen, usable bool) {
		if established == nil || port == 0 {
			return false, false
		}
		ok, err := established(port)
		return ok, err == nil
	}
	defer conn.SetReadDeadline(time.Time{})
	deadline := time.Now().Add(confirmWindow)
	apiUsable := false
	var b [1]byte
	for time.Now().Before(deadline) {
		seen, usable := ask()
		apiUsable = apiUsable || usable
		if seen {
			return nil
		}
		_ = conn.SetReadDeadline(time.Now().Add(confirmPoll))
		_, err := conn.Read(b[:])
		switch {
		case err == nil:
			return nil // the server spoke first
		case isTimeout(err):
			continue
		default:
			if seen, _ := ask(); seen {
				return nil
			}
			return fmt.Errorf("closed by the proxy after CONNECT, the dial failed: %w", err)
		}
	}
	if apiUsable {
		// the core answered all along and never had this connection
		return errors.New("the core never established the connection")
	}
	// no way to ask the core: an open connection after its whole dial
	// budget is the best evidence there is
	return nil
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// chain verification against system roots, separate from the handshake
func verifyChain(host string, certs []*x509.Certificate) bool {
	if len(certs) == 0 {
		return false
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		DNSName:       host,
		Intermediates: inter,
	})
	return err == nil
}

// classify the direct-path error -- what exactly DPI did
func ClassifyErr(r PathResult) string {
	e := strings.ToLower(r.Err)
	switch {
	case strings.Contains(e, "reset"):
		if r.ErrStage == "tls" {
			return "RST on ClientHello -- SNI filter"
		}
		return "RST on " + r.ErrStage
	case strings.Contains(e, "timeout") || strings.Contains(e, "deadline"):
		return "timeout on " + r.ErrStage
	case strings.Contains(e, "refused"):
		return "connection refused on " + r.ErrStage
	case strings.Contains(e, "unreachable"):
		return "host unreachable"
	}
	if r.Err != "" {
		return fmt.Sprintf("%s: %s", r.ErrStage, Truncate(r.Err, 60))
	}
	return ""
}

func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

var _ = net.Dial
