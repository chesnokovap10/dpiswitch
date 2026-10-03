package probe

import (
	"bufio"
	"context"
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
	"sync/atomic"
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
	// RedirectHost: where a redirect points, the request's own host for a
	// relative one. Plain HTTP only is judged by it -- see Judge.
	RedirectHost string        `json:"redirect_host,omitempty"`
	BodySHA256   string        `json:"body_sha256,omitempty"`
	BodyLen      int           `json:"body_len"`
	TTFB         time.Duration `json:"ttfb_ns"`
	Err          string        `json:"err,omitempty"`
	ErrStage     string        `json:"err_stage,omitempty"`
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

	if st.NegotiatedProtocol == "h2" {
		// a real request over h2 as well: a handshake alone called a site
		// clean that DPI lets through the ClientHello and stalls after
		h2Get(&r, tc, host)
		return r
	}
	httpGet(&r, tc, host)
	return r
}

// RunHTTP: plain HTTP on port 80. Blocking there works on the Host header,
// once the connection is up -- the ISP answers with a redirect to its own
// block page, or resets the session -- so a bare connect called such a host
// clean.
func RunHTTP(d Dialer, ip, host string) PathResult {
	conn, r := dialConfirmed(d, ip, 80)
	if conn == nil {
		return r
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(d.Timeout))
	httpGet(&r, conn, host)
	return r
}

// httpGet sends GET / over an established connection and records the answer.
// A hand-written HTTP/1.1 request: http.Client on top of an existing conn
// would take timing out of our control.
func httpGet(r *PathResult, conn net.Conn, host string) {
	req := "GET / HTTP/1.1\r\nHost: " + host + "\r\n" +
		"User-Agent: " + userAgent + "\r\n" +
		"Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
	t2 := time.Now()
	if _, err := conn.Write([]byte(req)); err != nil {
		r.Err, r.ErrStage = err.Error(), "http_write"
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		r.Err, r.ErrStage = err.Error(), "http_read"
		return
	}
	readResponse(r, resp, host, t2)
}

// userAgent: what the probes present themselves as
const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140.0.0.0 Safari/537.36"

// h2Get sends GET / over an established TLS connection that chose h2.
// The standard transport does the h2 itself, over this very connection:
// it is handed out as the one and only dial.
func h2Get(r *PathResult, conn net.Conn, host string) {
	t2 := time.Now()
	var given atomic.Bool
	tr := &http.Transport{
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			if given.Swap(true) {
				return nil, errors.New("the probe has one connection only")
			}
			return conn, nil
		},
		ForceAttemptHTTP2:  true,
		DisableCompression: true,
	}
	defer tr.CloseIdleConnections()
	resp, err := tr.RoundTrip(probeRequest(host))
	if err != nil {
		r.Err, r.ErrStage = err.Error(), "http_read"
		return
	}
	readResponse(r, resp, host, t2)
}

// probeRequest: GET / as the h2 and h3 probes send it
func probeRequest(host string) *http.Request {
	req, _ := http.NewRequest(http.MethodGet, "https://"+host+"/", nil)
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity")
	return req
}

// readResponse records an answer: status, redirect, and the body, read up
// to bodyLimit.
func readResponse(r *PathResult, resp *http.Response, host string, t2 time.Time) {
	r.TTFB = time.Since(t2)
	r.HTTPStatus = resp.StatusCode
	if u, err := resp.Location(); err == nil {
		r.RedirectHost = strings.ToLower(u.Hostname())
		if r.RedirectHost == "" {
			r.RedirectHost = strings.ToLower(host) // relative: the same host
		}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
	resp.Body.Close()
	r.BodyLen = len(body)
	sum := sha256.Sum256(body)
	r.BodySHA256 = hex.EncodeToString(sum[:])
	// A body cut short is what DPI leaves when it lets a session start and
	// stalls it after some kilobytes. With the length known (Content-Length
	// or chunked) an error means exactly that. A close-delimited body cannot
	// tell a clean end from a cut by its length alone -- but a reset is never
	// how a server ends one normally, so a reset there is a cut too; without
	// one it counts only when nothing arrived at all.
	if err != nil && (len(body) == 0 || resp.ContentLength >= 0 || len(resp.TransferEncoding) > 0 || isReset(err)) {
		r.Err, r.ErrStage = err.Error(), "body"
	}
}

// isReset: the peer reset the connection rather than closing it. Reading it
// off the error text keeps this independent of the OS's syscall constants,
// which the probe never sees directly through the SOCKS relay anyway.
func isReset(err error) bool {
	e := strings.ToLower(err.Error())
	return strings.Contains(e, "reset") || strings.Contains(e, "forcibly closed")
}

// HTTPFailed: the connection (and TLS, if any) went through, but the HTTP
// exchange on top of it did not.
func (r PathResult) HTTPFailed() bool {
	switch r.ErrStage {
	case "http_write", "http_read", "body":
		return r.Err != ""
	}
	return false
}

// TCP-only probe for ports that may not speak TLS. A weaker signal --
// no SNI, certificate or response body -- but DPI connection resets
// still show up here.
func RunTCP(d Dialer, ip string, port int) PathResult {
	conn, r := dialConfirmed(d, ip, port)
	if conn != nil {
		conn.Close()
	}
	return r
}

// dialConfirmed: a connection the core has really dialled (see confirmDial),
// or nil and the failure.
func dialConfirmed(d Dialer, ip string, port int) (net.Conn, PathResult) {
	var r PathResult
	r.IP = ip
	t0 := time.Now()
	conn, err := d.dial(ip, port)
	if err != nil {
		r.Err, r.ErrStage = err.Error(), "tcp"
		return nil, r
	}
	r.TCPTime = time.Since(t0)
	if err := confirmDial(conn, d.Established); err != nil {
		conn.Close()
		r.Err, r.ErrStage = err.Error(), "tcp"
		return nil, r
	}
	r.TCPOk = true
	return conn, r
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
	if established != nil {
		// the core was there to ask and never answered -- busy, or stuck.
		// An open connection is no proof: the SOCKS reply comes before the
		// dial. Taken as one, an overloaded core turned failed dials into
		// CLEAN; a failure keeps the name in the tunnel, which is safe.
		return errors.New("the dial could not be confirmed: the core's API did not answer")
	}
	// nothing to ask (no core behind the dialer): an open connection after
	// the whole dial budget is the best evidence there is
	return nil
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// chainRoots: the roots a chain is verified against; nil, the system's. A
// var for the tests, whose servers have certificates of their own.
var chainRoots *x509.CertPool

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
		Roots:         chainRoots,
	})
	return err == nil
}

// classify the direct-path error -- what exactly DPI did, and at which level.
// The stage says where: "tcp" is the address itself (nothing was sent yet but
// the SYN), "tls" is the ClientHello that carries the name, "body"/"http_*" is
// mid-session once data flows. The kind says how: a reset is an active RST, a
// timeout is a silent drop (the packets vanish with no answer), and refused or
// unreachable is the far end or the route, not a filter.
func ClassifyErr(r PathResult) string {
	e := strings.ToLower(r.Err)
	switch {
	case strings.Contains(e, "refused"):
		return "connection refused on " + where(r.ErrStage)
	case strings.Contains(e, "unreachable"):
		return "host unreachable"
	case strings.Contains(e, "reset") || strings.Contains(e, "forcibly closed"):
		return "RST (reset) on " + where(r.ErrStage)
	case strings.Contains(e, "timeout") || strings.Contains(e, "deadline"):
		return "silent drop (no reply) on " + where(r.ErrStage)
	}
	if r.Err != "" {
		return fmt.Sprintf("%s: %s", where(r.ErrStage), Truncate(r.Err, 60))
	}
	return ""
}

// where: the stage named as the level DPI acted at.
func where(stage string) string {
	switch stage {
	case "tcp":
		return "the address (SYN/connect)"
	case "tls":
		return "the ClientHello (carries the name/SNI)"
	case "body", "http_read", "http_write":
		return "the session after it opened"
	}
	if stage == "" {
		return "the connection"
	}
	return stage
}

func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
