package webui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/presets"
	"dpiswitch/internal/probe"
)

func TestDNSPingRetriesTransportFailure(t *testing.T) {
	old := pingEither
	t.Cleanup(func() { pingEither = old })
	for _, first := range []error{
		context.DeadlineExceeded,
		fmt.Errorf("read: %w", io.EOF),
		&net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")},
	} {
		t.Run(first.Error(), func(t *testing.T) {
			calls := 0
			pingEither = func(_ probe.Dialer, srv, name string) ([]string, time.Duration, string, string, error) {
				calls++
				if srv != "quic://192.0.2.53" || name != "whoami.akamai.net" {
					t.Fatalf("retry changed query: %s %s", srv, name)
				}
				if calls == 1 {
					return nil, 0, srv, "DoQ", first
				}
				return []string{"192.0.2.1"}, 7 * time.Millisecond, srv, "DoQ", nil
			}
			r := pingDNS(probe.Dialer{}, "quic://192.0.2.53")
			if calls != 2 || !r.OK || r.Kind != "DoQ" || r.Ms != 7 || r.Error != "" {
				t.Fatalf("calls=%d result=%+v", calls, r)
			}
		})
	}
}

func TestDNSPingRetryIsBounded(t *testing.T) {
	old := pingEither
	t.Cleanup(func() { pingEither = old })
	for _, tc := range []struct {
		err   error
		calls int
	}{
		{context.DeadlineExceeded, 2},
		{errors.New("NXDOMAIN"), 1},
		{errors.New("tls: certificate verification failed"), 1},
	} {
		t.Run(tc.err.Error(), func(t *testing.T) {
			calls := 0
			pingEither = func(_ probe.Dialer, srv, _ string) ([]string, time.Duration, string, string, error) {
				calls++
				return nil, 0, srv, "DoQ", tc.err
			}
			r := pingDNS(probe.Dialer{}, "quic://192.0.2.53")
			if calls != tc.calls || r.OK || r.Error != tc.err.Error() {
				t.Fatalf("calls=%d result=%+v", calls, r)
			}
		})
	}
	pingEither = func(probe.Dialer, string, string) ([]string, time.Duration, string, string, error) {
		t.Fatal("invalid resolver reached network test")
		return nil, 0, "", "", nil
	}
	if r := pingDNS(probe.Dialer{}, "quic://192.0.2.53:53"); r.OK || r.Error == "" {
		t.Fatalf("invalid resolver: %+v", r)
	}
}

func TestDNSPingReportsActualTransport(t *testing.T) {
	old := pingEither
	defer func() { pingEither = old }()
	for _, kind := range []string{"DoH3", "DoH", "DoQ"} {
		pingEither = func(_ probe.Dialer, srv, _ string) ([]string, time.Duration, string, string, error) {
			return []string{"192.0.2.1"}, 7 * time.Millisecond, srv, kind, nil
		}
		srv := "https://192.0.2.53/dns-query"
		if kind == "DoQ" {
			srv = "quic://192.0.2.53"
		}
		r := pingDNS(probe.Dialer{}, srv)
		if !r.OK || r.Kind != kind || r.Ms != 7 || r.Fixed != "" {
			t.Fatalf("%s: %+v", kind, r)
		}
	}
}

// A preset's address rules carry no-resolve: a named connection whose
// address falls in them is not theirs, and is not closed when the preset
// changes. One made by address is.
func TestRulesMatchNoResolve(t *testing.T) {
	m := rulesMatch(ctl.PresetRules(presets.Preset{Lines: []string{"1.2.3.0/24", "+.example.org", "app.exe"}}))
	for _, c := range []struct {
		conn ctl.Conn
		want bool
	}{
		{ctl.Conn{IP: "1.2.3.4"}, true},
		{ctl.Conn{Host: "example.com", IP: "1.2.3.4"}, false},
		{ctl.Conn{Host: "a.example.org", IP: "9.9.9.9"}, true},
		{ctl.Conn{Host: "example.com", IP: "9.9.9.9", Process: "app.exe"}, true},
		{ctl.Conn{IP: "1.2.4.4"}, false},
	} {
		if got := m(c.conn); got != c.want {
			t.Errorf("%+v: %v, want %v", c.conn, got, c.want)
		}
	}
}

// the tunnel's server catches port 53: a public server written in the box is
// answered by the server itself -- marked; its own resolver, the endpoint
// itself, DoH and a resolver with its own exit are not
func TestCaughtBy(t *testing.T) {
	ep := "46.8.182.121"
	res := []dnsResult{
		{Server: "84.252.75.74", Kind: "DNS", OK: true, IPs: []string{ep}},
		{Server: "xbox-dns.ru", Kind: "DNS", OK: true, IPs: []string{ep}},
		{Server: "10.8.1.0", Kind: "DNS", OK: true, IPs: []string{ep}},
		{Server: "fd7a:a1c3:8b42:8::", Kind: "DNS", OK: true, IPs: []string{ep}},
		{Server: ep, Kind: "DNS", OK: true, IPs: []string{ep}},
		{Server: "https://xbox-dns.ru/dns-query", Kind: "DoH", OK: true, IPs: []string{ep}},
		{Server: "1.1.1.1", Kind: "DNS", OK: true, IPs: []string{"172.69.50.55"}},
		{Server: "9.9.9.9", Kind: "DNS", OK: false},
	}
	caughtBy(ep, res)
	want := []bool{true, true, false, false, false, false, false, false}
	for i, r := range res {
		if r.Caught != want[i] {
			t.Errorf("%s: caught %v, want %v", r.Server, r.Caught, want[i])
		}
	}
	// an endpoint given by name: nothing to compare with
	res = []dnsResult{{Server: "84.252.75.74", Kind: "DNS", OK: true, IPs: []string{ep}}}
	caughtBy("vpn.example.com", res)
	if res[0].Caught {
		t.Error("marked with an endpoint given by name")
	}
}
