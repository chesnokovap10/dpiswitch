package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// проба QUIC. делаем настоящее рукопожатие, а не самодельный пробный
// пакет: сервер молча игнорирует всё невалидное, и отсутствие ответа
// на кустарный пакет я бы принял за блокировку. ложное "заблокировано"
// терпимо, но ложное "чисто" ломает сайт -- а самодельная проба даёт
// ровно его, если DPI режет по SNI внутри Initial.
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
		r.Err, r.ErrStage = "не разобран адрес "+ip, "udp_associate"
		return r
	}

	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	t0 := time.Now()
	conn, err := quic.Dial(ctx, pc, addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // сертификат нужен даже поддельный: он и есть сигнал
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

	// для QUIC рукопожатие неразделимо: успех означает и доставку
	// датаграмм, и согласованный TLS. разносим по тем же полям,
	// чтобы Judge работал без особых случаев.
	r.TCPOk, r.TLSOk = true, true
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
	return r
}

var _ = fmt.Sprintf
