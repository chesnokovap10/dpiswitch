package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Resolver: a DNS server in the same notation the core understands
// (https://…, tls://…, tcp://…, udp://… or a bare address).
//
// The prober must ask THE SAME resolver the core uses for direct
// traffic: a CDN's node depends on who asked and from where. Testing
// one node while sending traffic to another means judging
// something other than what will actually be used.
type Resolver struct {
	Raw    string
	Scheme string // https, tls, tcp, udp
	Host   string
	Port   int
	Path   string
}

func ParseResolver(s string) (Resolver, error) {
	s = strings.TrimSpace(s)
	r := Resolver{Raw: s}
	if s == "" {
		return r, errors.New("empty resolver address")
	}
	if !strings.Contains(s, "://") {
		s = "udp://" + s
	}
	// a bare IPv6 without brackets: otherwise the address's last colon
	// is parsed as the port separator ("fd7a::" -> "fd7a:")
	if scheme, rest, ok := strings.Cut(s, "://"); ok {
		host, path, _ := strings.Cut(rest, "/")
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			s = scheme + "://[" + host + "]"
			if path != "" {
				s += "/" + path
			}
		}
	}
	u, err := url.Parse(s)
	if err != nil {
		return r, fmt.Errorf("%q: %v", r.Raw, err)
	}
	r.Scheme = strings.ToLower(u.Scheme)
	r.Host = u.Hostname()
	defPort := map[string]int{"https": 443, "tls": 853, "tcp": 53, "udp": 53}
	p, ok := defPort[r.Scheme]
	if !ok {
		return r, fmt.Errorf("%q: supported schemes are https://, tls://, tcp://, udp://", r.Raw)
	}
	r.Port = p
	if ps := u.Port(); ps != "" {
		if r.Port, err = strconv.Atoi(ps); err != nil || r.Port < 1 || r.Port > 65535 {
			return r, fmt.Errorf("%q: invalid port", r.Raw)
		}
	}
	if r.Host == "" {
		return r, fmt.Errorf("%q: no server specified", r.Raw)
	}
	if u.Fragment != "" {
		return r, fmt.Errorf("%q: a #… suffix is not allowed here", r.Raw)
	}
	r.Path = u.EscapedPath()
	if r.Scheme == "https" && r.Path == "" {
		r.Path = "/dns-query"
	}
	return r, nil
}

// Lookup: A records of a name via this resolver, over the dialer's path.
// Plain udp:// is checked over TCP to the same server: the prober's
// SOCKS listener is TCP, and the server and answers are the same.
func (r Resolver) Lookup(d Dialer, name string) ([]string, error) {
	q, id := buildQuery(name)
	var resp []byte
	var err error
	switch r.Scheme {
	case "https":
		resp, err = r.doh(d, q)
	default:
		resp, err = r.stream(d, q)
	}
	if err != nil {
		return nil, err
	}
	return parseA(resp, id)
}

func (r Resolver) tlsConf() *tls.Config {
	// for an address literal the certificate is verified by IP (Yandex and Google
	// list their IPs in the certificate), for a name -- by name
	return &tls.Config{ServerName: r.Host, NextProtos: []string{"h2", "http/1.1"}}
}

func (r Resolver) doh(d Dialer, q []byte) ([]byte, error) {
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			c, err := d.dial(r.Host, r.Port)
			if err != nil {
				return nil, err
			}
			tc := tls.Client(c, r.tlsConf())
			_ = tc.SetDeadline(time.Now().Add(d.Timeout))
			if err := tc.HandshakeContext(ctx); err != nil {
				c.Close()
				return nil, fmt.Errorf("tls: %w", err)
			}
			_ = tc.SetDeadline(time.Time{})
			return tc, nil
		},
		// some servers (Yandex) only answer over HTTP/2
		ForceAttemptHTTP2: true,
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: d.Timeout}

	u := fmt.Sprintf("https://%s%s", net.JoinHostPort(r.Host, strconv.Itoa(r.Port)), r.Path)
	req, err := http.NewRequest("POST", u, bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<10))
}

func (r Resolver) stream(d Dialer, q []byte) ([]byte, error) {
	c, err := d.dial(r.Host, r.Port)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if r.Scheme == "tls" {
		tc := tls.Client(c, &tls.Config{ServerName: r.Host})
		c = tc
	}
	_ = c.SetDeadline(time.Now().Add(d.Timeout))
	msg := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(msg, uint16(len(q)))
	copy(msg[2:], q)
	if _, err := c.Write(msg); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	out := make([]byte, binary.BigEndian.Uint16(l[:]))
	_, err = io.ReadFull(c, out)
	return out, err
}

// LookupAny queries resolvers concurrently and takes the first answer --
// just like the core: otherwise the prober and traffic would get different nodes
func LookupAny(d Dialer, rs []Resolver, name string) ([]string, error) {
	type res struct {
		ips []string
		err error
	}
	ch := make(chan res, len(rs))
	for _, r := range rs {
		go func(r Resolver) {
			ips, err := r.Lookup(d, name)
			if err == nil && len(ips) == 0 {
				err = errors.New("no A records")
			}
			ch <- res{ips, err}
		}(r)
	}
	var errs []string
	for range rs {
		x := <-ch
		if x.err == nil {
			return x.ips, nil
		}
		errs = append(errs, x.err.Error())
	}
	return nil, errors.New(strings.Join(errs, "; "))
}

// --- DNS message format: exactly what an A query needs ---

func buildQuery(name string) ([]byte, uint16) {
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	b := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], 0x0100) // RD
	binary.BigEndian.PutUint16(b[4:], 1)      // one question
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0, 0, 1, 0, 1) // type A, class IN
	return b, id
}

var rcodeText = map[int]string{2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}

func parseA(m []byte, id uint16) ([]string, error) {
	if len(m) < 12 {
		return nil, errors.New("short DNS response")
	}
	if binary.BigEndian.Uint16(m) != id {
		return nil, errors.New("mismatched DNS response")
	}
	if rc := int(m[3] & 0x0f); rc != 0 {
		if t, ok := rcodeText[rc]; ok {
			return nil, errors.New(t)
		}
		return nil, fmt.Errorf("rcode %d", rc)
	}
	qd, an := int(binary.BigEndian.Uint16(m[4:])), int(binary.BigEndian.Uint16(m[6:]))
	off := 12
	for i := 0; i < qd; i++ {
		var ok bool
		if off, ok = skipName(m, off); !ok || off+4 > len(m) {
			return nil, errors.New("malformed DNS question")
		}
		off += 4
	}
	var out []string
	for i := 0; i < an; i++ {
		var ok bool
		if off, ok = skipName(m, off); !ok || off+10 > len(m) {
			break
		}
		typ := binary.BigEndian.Uint16(m[off:])
		rdl := int(binary.BigEndian.Uint16(m[off+8:]))
		off += 10
		if off+rdl > len(m) {
			break
		}
		if typ == 1 && rdl == 4 {
			out = append(out, net.IP(m[off:off+4]).String())
		}
		off += rdl
	}
	return out, nil
}

func skipName(m []byte, off int) (int, bool) {
	for off < len(m) {
		l := int(m[off])
		switch {
		case l == 0:
			return off + 1, true
		case l&0xc0 == 0xc0: // compression: a pointer takes two bytes and ends the name
			return off + 2, off+2 <= len(m)
		default:
			off += 1 + l
		}
	}
	return off, false
}
