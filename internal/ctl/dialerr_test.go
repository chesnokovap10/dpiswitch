package ctl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The core's warnings as they are in mihomo.log.
func TestParseDialErr(t *testing.T) {
	for _, c := range []struct {
		line string
		want DialErr
	}{
		{"[TCP] dial tunnel (match Match/) 198.18.0.1:50427(chrome.exe) --> tls-outer.browserleaks.com:443 error: dns resolve failed: couldn't find ip",
			DialErr{Network: "tcp", Proxy: "tunnel", Rule: "Match", Process: "chrome.exe", Host: "tls-outer.browserleaks.com", Port: 443,
				Err: "dns resolve failed: couldn't find ip"}},
		// the payload has a slash of its own; no program; the error twice
		{"[TCP] dial DIRECT (match IPCIDR/46.8.182.121/32) 198.18.0.1:50001 --> ecs.office.com:443 error: interface not found\ninterface not found",
			DialErr{Network: "tcp", Proxy: "DIRECT", Rule: "IPCIDR", RulePayload: "46.8.182.121/32", Host: "ecs.office.com", Port: 443,
				Err: "interface not found"}},
		{"[TCP] dial DIRECT (match RuleSet/direct-verified) 198.18.0.1:50002(Some App.exe) --> www.msftconnecttest.com:80 error: dial tcp 13.107.4.52:80: i/o timeout",
			DialErr{Network: "tcp", Proxy: "DIRECT", Rule: "RuleSet", RulePayload: "direct-verified", Process: "Some App.exe",
				Host: "www.msftconnecttest.com", IP: "13.107.4.52", Port: 80, Err: "dial tcp 13.107.4.52:80: i/o timeout"}},
		// the prober's: from loopback, bound to an outbound, no rule
		{"[TCP] dial DIRECT 127.0.0.1:58476 --> [2a09:5302:ffff::6ab:8443]:443 error: dial tcp [2a09:5302:ffff::6ab:8443]:443: i/o timeout",
			DialErr{Network: "tcp", Proxy: "DIRECT", Probe: true, IP: "2a09:5302:ffff::6ab:8443", Port: 443,
				Err: "dial tcp [2a09:5302:ffff::6ab:8443]:443: i/o timeout"}},
		// inside the tunnel the error names the tunnel's own address first
		{"[TCP] dial awg 127.0.0.1:58728 --> example.org:443 error: dial tcp [fd7a:a1c3:8b42::3]:51834->[2a09:5302:ffff::6ab]:443: context deadline exceeded",
			DialErr{Network: "tcp", Proxy: "awg", Probe: true, Host: "example.org", IP: "2a09:5302:ffff::6ab", Port: 443,
				Err: "dial tcp [fd7a:a1c3:8b42::3]:51834->[2a09:5302:ffff::6ab]:443: context deadline exceeded"}},
		{"[UDP] dial tunnel2 (match RuleSet/preset-youtube) 198.18.0.1:60000(chrome.exe, uid=0) --> rr1.googlevideo.com:443 error: connection refused",
			DialErr{Network: "udp", Proxy: "tunnel2", Rule: "RuleSet", RulePayload: "preset-youtube", Process: "chrome.exe",
				Host: "rr1.googlevideo.com", Port: 443, Err: "connection refused"}},
	} {
		got, ok := ParseDialErr(c.line)
		if !ok || got != c.want {
			t.Errorf("%s\n got %+v %v\nwant %+v", c.line, got, ok, c.want)
		}
	}
	for _, other := range []string{
		"[UDP] DoSniff error: short packet",
		"[TCP] 198.18.0.1:50427(chrome.exe) --> example.com:443 match Match using tunnel[awg]",
		"[Metadata] not valid: ...",
	} {
		if e, ok := ParseDialErr(other); ok {
			t.Errorf("%q read as a dial error: %+v", other, e)
		}
	}
}

func TestFailKind(t *testing.T) {
	for err, want := range map[string]string{
		"interface not found":                                            "nonet",
		"dns resolve failed: couldn't find ip":                           "dns",
		"dial tcp 1.2.3.4:443: i/o timeout":                              "timeout",
		"dial tcp [fd7a::3]:1->[2a09::1]:443: context deadline exceeded": "timeout",
		"dial tcp [2a09::1]:443: connectex: No connection could be made because the target machine actively refused it.": "refused",
		"read: connection reset by peer":                "reset",
		"connect: network is unreachable":               "unreach",
		"awg connect error: handshake did not complete": "other",
	} {
		if got := FailKind(err); got != want {
			t.Errorf("%q: %s, want %s", err, got, want)
		}
	}
}

// The log is read as it comes, and what is not a failed dial is skipped.
func TestDialErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/logs" || r.URL.Query().Get("level") != "warning" || r.Header.Get("Authorization") != "Bearer s3" {
			http.Error(w, "no", http.StatusBadRequest)
			return
		}
		for _, p := range []string{"[Metadata] not valid", "[TCP] dial DIRECT 127.0.0.1:1 --> 1.2.3.4:443 error: i/o timeout"} {
			fmt.Fprintf(w, "{\"type\":\"warning\",\"payload\":%q}\n", p)
		}
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()
	l := NewLiveClient(strings.TrimPrefix(srv.URL, "http://"), "s3")
	defer l.Release()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var got []DialErr
	err := l.DialErrors(ctx, func(e DialErr) {
		got = append(got, e)
		cancel()
	})
	if len(got) != 1 || got[0].IP != "1.2.3.4" || !got[0].Probe {
		t.Fatalf("%v: %+v", err, got)
	}

	// nothing listening: the core is not running
	srv.Close()
	if err := l.DialErrors(context.Background(), func(DialErr) {}); err != ErrCoreDown {
		t.Errorf("no core: %v", err)
	}
}
