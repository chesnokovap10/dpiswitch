package probe

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DoH resolution over a given path (direct or tunnel).
// The resolver is dialed by IP literal: plain UDP/53 may be blocked, and
// bootstrapping by name would be a chicken-and-egg problem.
type dohResolver struct {
	ip   string // DoH server address
	sni  string // name for SNI and certificate verification
	path string
}

var defaultResolvers = []dohResolver{
	{ip: "8.8.8.8", sni: "dns.google", path: "/resolve"},
	{ip: "1.1.1.1", sni: "cloudflare-dns.com", path: "/dns-query"},
}

type dnsAnswer struct {
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func ResolveVia(d Dialer, host string) ([]string, error) {
	var lastErr error
	for _, r := range defaultResolvers {
		ips, err := r.query(d, host)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("empty answer from all resolvers")
	}
	return nil, lastErr
}

func (r dohResolver) query(d Dialer, host string) ([]string, error) {
	conn, err := d.dial(r.ip, 443)
	if err != nil {
		return nil, fmt.Errorf("doh dial: %w", err)
	}
	defer conn.Close()

	tc := tls.Client(conn, &tls.Config{ServerName: r.sni, NextProtos: []string{"http/1.1"}})
	_ = tc.SetDeadline(time.Now().Add(d.Timeout))
	if err := tc.Handshake(); err != nil {
		return nil, fmt.Errorf("doh tls: %w", err)
	}

	req := fmt.Sprintf("GET %s?name=%s&type=A HTTP/1.1\r\nHost: %s\r\n"+
		"Accept: application/dns-json\r\nConnection: close\r\n\r\n", r.path, host, r.sni)
	if _, err := tc.Write([]byte(req)); err != nil {
		return nil, fmt.Errorf("doh write: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		return nil, fmt.Errorf("doh read: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	var a dnsAnswer
	if err := json.Unmarshal(body, &a); err != nil {
		return nil, fmt.Errorf("doh json: %w", err)
	}
	var out []string
	for _, ans := range a.Answer {
		if ans.Type == 1 && net.ParseIP(ans.Data) != nil {
			out = append(out, ans.Data)
		}
	}
	return out, nil
}

func JoinIPs(s []string) string { return strings.Join(s, ",") }
