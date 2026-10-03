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
		{"[TCP] dial awg1 127.0.0.1:58728 --> example.org:443 error: dial tcp [fd7a:a1c3:8b42::3]:51834->[2a09:5302:ffff::6ab]:443: context deadline exceeded",
			DialErr{Network: "tcp", Proxy: "awg1", Probe: true, Host: "example.org", IP: "2a09:5302:ffff::6ab", Port: 443,
				Err: "dial tcp [fd7a:a1c3:8b42::3]:51834->[2a09:5302:ffff::6ab]:443: context deadline exceeded"}},
		// both families dialled, one line each: the first address
		{"[TCP] dial DIRECT (match RuleSet/direct-verified) 198.18.0.1:50003(chrome.exe) --> dual.example:443 error: dial tcp [2001:db8::1]:443: i/o timeout\ndial tcp 192.0.2.1:443: i/o timeout",
			DialErr{Network: "tcp", Proxy: "DIRECT", Rule: "RuleSet", RulePayload: "direct-verified", Process: "chrome.exe",
				Host: "dual.example", IP: "2001:db8::1", Port: 443, Err: "dial tcp [2001:db8::1]:443: i/o timeout; dial tcp 192.0.2.1:443: i/o timeout"}},
		// a local client through the rules is no probe, loopback or not
		{"[TCP] dial tunnel (match Match/) 127.0.0.1:49157(app.exe) --> example.net:443 error: i/o timeout",
			DialErr{Network: "tcp", Proxy: "tunnel", Rule: "Match", Process: "app.exe", Host: "example.net", Port: 443, Err: "i/o timeout"}},
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
		"[TCP] 198.18.0.1:50427(chrome.exe) --> example.com:443 match Match using tunnel[awg1]",
		"[Metadata] not valid: ...",
	} {
		if e, ok := ParseDialErr(other); ok {
			t.Errorf("%q read as a dial error: %+v", other, e)
		}
	}
}

// A try the user's forbidden list refused is only an info line of the core;
// a refusal by any other rule is not the list's.
func TestParseReject(t *testing.T) {
	e, ok := ParseReject("[TCP] 198.18.0.1:50427(chrome.exe) --> Example.com.:443 match RuleSet(force-block) using REJECT")
	if !ok || e.Network != "tcp" || e.Process != "chrome.exe" || e.Host != "example.com" || e.Port != 443 ||
		e.RulePayload != "force-block" || e.Proxy != "REJECT" || e.Err != Forbidden {
		t.Fatalf("%v %+v", ok, e)
	}
	e, ok = ParseReject("[TCP] 198.18.0.1:1 --> [2001:db8::1]:443 match RuleSet(force-block-ip) using REJECT")
	if !ok || e.IP != "2001:db8::1" || e.Host != "" || e.Process != "" {
		t.Fatalf("an address: %v %+v", ok, e)
	}
	for _, l := range []string{
		"[TCP] 198.18.0.1:1 --> a.example:443 match RuleSet(other) using REJECT",
		"[TCP] 198.18.0.1:1 --> a.example:443 match RuleSet(force-block) using DIRECT",
	} {
		if _, ok := ParseReject(l); ok {
			t.Errorf("taken: %s", l)
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
		"read: connection reset by peer":                 "reset",
		"connect: network is unreachable":                "unreach",
		"awg1 connect error: handshake did not complete": "other",
		"no ip address": "dns",
		"ipv6 disabled": "dns",
		"wsarecv: An existing connection was forcibly closed by the remote host.":                                 "reset",
		"A connection attempt failed because the connected party did not properly respond after a period of time": "timeout",
		"context canceled":        "canceled",
		"unexpected EOF":          "eof",
		"read tcp 1.2.3.4:5: EOF": "eof",
		"dial tcp 1.2.3.4:443: connectex: An invalid argument was supplied.": "other",
	} {
		if got := FailKind(err); got != want {
			t.Errorf("%q: %s, want %s", err, got, want)
		}
	}
}

// The log is read as it comes: a failed dial and a try the forbidden list
// refused are handed on, every other line is skipped.
func TestDialErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/logs" || r.URL.Query().Get("level") != "info" || r.Header.Get("Authorization") != "Bearer s3" {
			http.Error(w, "no", http.StatusBadRequest)
			return
		}
		for _, p := range []string{"[Metadata] not valid",
			"[TCP] 198.18.0.1:5(chrome.exe) --> a.example:443 match RuleSet(force-tunnel) using tunnel[awg1]",
			"[TCP] dial DIRECT 127.0.0.1:1 --> 1.2.3.4:443 error: i/o timeout",
			"[UDP] 198.18.0.1:6(chrome.exe) --> ads.example:443 match RuleSet(force-block) using REJECT"} {
			fmt.Fprintf(w, "{\"type\":\"info\",\"payload\":%q}\n", p)
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
	opened := 0
	err := l.DialErrors(ctx, func() { opened++ }, func(e DialErr) {
		if opened != 1 {
			t.Errorf("a line before the stream was opened, or opened %d times", opened)
		}
		if got = append(got, e); len(got) == 2 {
			cancel()
		}
	})
	if len(got) != 2 || got[0].IP != "1.2.3.4" || !got[0].Probe || got[1].Host != "ads.example" || FailKind(got[1].Err) != "forbidden" {
		t.Fatalf("%v: %+v", err, got)
	}

	// nothing listening: the core is not running
	srv.Close()
	if err := l.DialErrors(context.Background(), func() { t.Error("opened with no core") }, func(DialErr) {}); err != ErrCoreDown {
		t.Errorf("no core: %v", err)
	}
}

// A failed dial names a group; what it went through is the group's choice.
func TestGroups(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"proxies":{"tunnel":{"type":"Fallback","now":"DIRECT","all":["awg1","DIRECT"]},"awg1":{"type":"WireGuard"},"DIRECT":{"type":"Direct"}}}`)
	}))
	defer srv.Close()
	l := NewLiveClient(strings.TrimPrefix(srv.URL, "http://"), "")
	defer l.Release()
	g, err := l.Groups()
	if err != nil || len(g) != 1 || g["tunnel"] != "DIRECT" {
		t.Errorf("%v: %v", err, g)
	}
}
