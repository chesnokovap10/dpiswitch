package probe

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// A QUIC site gets a real HTTP/3 request after the handshake.
func TestH3Get(t *testing.T) {
	cert := httptest.NewUnstartedServer(nil)
	cert.StartTLS() // only for its certificate
	defer cert.Close()
	tlsConf := cert.TLS.Clone()
	tlsConf.NextProtos = []string{"h3"}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{TLSConfig: tlsConf, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "5")
		w.Write([]byte("hello"))
	})}
	go srv.Serve(pc)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, pc.LocalAddr().String(),
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	var r PathResult
	h3Get(ctx, &r, conn, "example.com")
	if r.HTTPStatus != 200 || r.BodyLen != 5 || r.Err != "" {
		t.Fatalf("%+v", r)
	}
}
