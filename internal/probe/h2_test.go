package probe

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// An h2 site gets a real request: the handshake alone called clean a site
// that DPI lets through the ClientHello and stalls after.
func TestH2Get(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.Header.Get("X-Cut") == "" {
			w.Header().Set("Content-Length", "100000")
			w.WriteHeader(200)
			w.Write([]byte(strings.Repeat("x", 20000)))
			w.(http.Flusher).Flush()
			// the rest never comes: a stalled session
			time.Sleep(2 * time.Second)
		}
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if p := conn.ConnectionState().NegotiatedProtocol; p != "h2" {
		t.Fatalf("negotiated %q", p)
	}
	conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	var r PathResult
	h2Get(&r, conn, "example.com")
	if r.HTTPStatus != 200 || r.BodyLen == 0 {
		t.Fatalf("no answer read: %+v", r)
	}
	if r.ErrStage != "body" || !r.HTTPFailed() {
		t.Fatalf("a stalled body is not a failure: stage %q err %q", r.ErrStage, r.Err)
	}
}
