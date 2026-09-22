package probe

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// результат одного прохода по одному пути (direct или tunnel)
type PathResult struct {
	IP         string        `json:"ip,omitempty"`
	TCPOk      bool          `json:"tcp_ok"`
	TCPTime    time.Duration `json:"tcp_time_ms"`
	TLSOk      bool          `json:"tls_ok"`
	TLSTime    time.Duration `json:"tls_time_ms"`
	CertSHA256 string        `json:"cert_sha256,omitempty"`
	CertCN     string        `json:"cert_cn,omitempty"`
	CertValid  bool          `json:"cert_valid"`
	ALPN       string        `json:"alpn,omitempty"`
	HTTPStatus int           `json:"http_status,omitempty"`
	BodySHA256 string        `json:"body_sha256,omitempty"`
	BodyLen    int           `json:"body_len"`
	TTFB       time.Duration `json:"ttfb_ms"`
	Err        string        `json:"err,omitempty"`
	ErrStage   string        `json:"err_stage,omitempty"`
}

const bodyLimit = 64 << 10 // читаем не больше 64 КБ: нам нужна подпись, не контент

// ip -- конкретный узел, который проверяем; host -- имя для SNI и Host.
// подключаемся именно по IP: так обрыв хендшейка нельзя перепутать
// с несостоявшимся резолвом, и мы точно знаем, какой узел проверен.
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

	// InsecureSkipVerify: сертификат нужен даже если он поддельный --
	// именно подделка и есть сигнал. валидность проверяем отдельно, вручную.
	t1 := time.Now()
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

	// HTTP/1.1 запрос руками: http.Client поверх готового conn
	// увёл бы нас от контроля над таймингом
	if st.NegotiatedProtocol == "h2" {
		// h2 в v1 не разбираем, достаточно факта успешного TLS
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

// проба только на уровне TCP: для порта, где TLS может не быть.
// сигнал слабее -- ни SNI, ни сертификата, ни тела ответа, --
// но обрыв соединения DPI показывает и здесь.
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
	r.TCPOk, r.TCPTime = true, time.Since(t0)
	return r
}

// проверка цепочки против системных корней, отдельно от рукопожатия
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

// классификация ошибки прямого пути -- что именно сделал DPI
func ClassifyErr(r PathResult) string {
	e := strings.ToLower(r.Err)
	switch {
	case strings.Contains(e, "reset"):
		if r.ErrStage == "tls" {
			return "RST на ClientHello -- фильтр по SNI"
		}
		return "RST на " + r.ErrStage
	case strings.Contains(e, "timeout") || strings.Contains(e, "deadline"):
		return "таймаут на " + r.ErrStage
	case strings.Contains(e, "refused"):
		return "connection refused на " + r.ErrStage
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
