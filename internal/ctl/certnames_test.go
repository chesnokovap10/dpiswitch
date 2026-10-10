package ctl

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

// A CDN's certificate is read only when it is the host's own: its chain
// known, its name the host's. A node's default certificate, or one put in
// on the way, names no family.
func TestCertNamesVerified(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	own := x509.NewCertPool()
	own.AddCert(srv.Certificate())
	read := func(host string, roots *x509.CertPool) ([]string, error) {
		conn, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return certNames(ctx, conn, host, roots)
	}
	// the test server's certificate is for example.com
	names, err := read("example.com", own)
	if err != nil || !slices.Contains(names, "example.com") {
		t.Fatalf("the host's own certificate: %v, %v", names, err)
	}
	if names, err := read("cdn.example.org", own); err == nil {
		t.Errorf("a certificate for another name was read: %v", names)
	}
	if names, err := read("example.com", nil); err == nil {
		t.Errorf("a certificate of an unknown chain was read: %v", names)
	}
}
