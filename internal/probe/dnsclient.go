package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
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
// Plain udp:// is asked over UDP, through the listener's UDP ASSOCIATE, as
// the core asks it: it used to go over TCP to the same server, and a network
// that passes TCP/53 and drops UDP/53 had the resolver checked as working
// while the core could not resolve through it.
func (r Resolver) Lookup(d Dialer, name string) ([]string, error) {
	return r.lookup(d, name, typeA)
}

// LookupV6 asks for AAAA. A host with no A record at all is not "unknown":
// it is reachable only over IPv6, and whether the direct path has IPv6 is
// exactly what the probe then finds out by connecting to that address.
func (r Resolver) LookupV6(d Dialer, name string) ([]string, error) {
	return r.lookup(d, name, typeAAAA)
}

func (r Resolver) lookup(d Dialer, name string, qtype uint16) ([]string, error) {
	q, id := buildQuery(name, qtype)
	var resp []byte
	var err error
	switch r.Scheme {
	case "https":
		resp, err = r.doh(d, q)
	case "udp":
		resp, err = r.datagram(d, q, id)
	default:
		resp, err = r.stream(d, q)
	}
	if err != nil {
		return nil, err
	}
	return parseAnswer(resp, id, qtype)
}

// resolverRoots: the certificates a resolver's chain is verified against;
// nil is the system's. Tests put their own server's here.
var resolverRoots *x509.CertPool

func (r Resolver) tlsConf() *tls.Config {
	// for an address literal the certificate is verified by IP (Yandex and Google
	// list their IPs in the certificate), for a name -- by name
	return &tls.Config{ServerName: r.Host, NextProtos: []string{"h2", "http/1.1"}, RootCAs: resolverRoots}
}

// dohClients: one HTTP client per resolver and path, kept between queries.
// Every query used to open a TCP and TLS connection of its own -- one per
// probed port, some 350 in three hours to a single DoH server -- and
// "direct DNS did not answer: tls: EOF" came from those handshakes. Over
// HTTP/2 the queries of a cycle now share one connection, closed after
// dohIdle unused.
var dohClients sync.Map // "listener|timeout|host:port" -> *http.Client

const dohIdle = 90 * time.Second

func (r Resolver) dohClient(d Dialer) *http.Client {
	server := net.JoinHostPort(r.Host, strconv.Itoa(r.Port))
	key := d.Addr + "|" + d.Timeout.String() + "|" + server
	if c, ok := dohClients.Load(key); ok {
		return c.(*http.Client)
	}
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
		IdleConnTimeout:   dohIdle,
		// a kept connection can die without a word -- the network changed
		// under it -- and queries sent into it would wait out their timeout.
		// A quiet connection is pinged, and dropped if the ping goes unanswered
		HTTP2: &http.HTTP2Config{SendPingTimeout: 15 * time.Second, PingTimeout: 5 * time.Second},
	}
	c, _ := dohClients.LoadOrStore(key, &http.Client{Transport: tr})
	return c.(*http.Client)
}

func (r Resolver) doh(d Dialer, q []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()
	u := fmt.Sprintf("https://%s%s", net.JoinHostPort(r.Host, strconv.Itoa(r.Port)), r.Path)
	post := func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(q))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		return r.dohClient(d).Do(req)
	}
	resp, err := post()
	if err != nil && ctx.Err() == nil {
		// The kept connection may be dead by the time a query is written
		// into it -- a core restart cuts every connection it carries -- and
		// the transport does not always notice first: it fails the query
		// with the write error and retries nothing, a POST over HTTP/2 (a test
		// caught it, about once in 300 runs). A query is safe to
		// send twice: once more, on a fresh connection.
		r.dohClient(d).CloseIdleConnections()
		resp, err = post()
	}
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
	c, err := r.streamConn(d)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return exchange(c, d, q)
}

// streamConn: a TCP connection to the resolver, in TLS for tls://
func (r Resolver) streamConn(d Dialer) (net.Conn, error) {
	c, err := d.dial(r.Host, r.Port)
	if err != nil {
		return nil, err
	}
	if r.Scheme == "tls" {
		c = tls.Client(c, &tls.Config{ServerName: r.Host, RootCAs: resolverRoots})
	}
	return c, nil
}

// exchange: one query and its answer over a stream connection; several
// may follow one another on it (RFC 7766, 7858)
func exchange(c net.Conn, d Dialer, q []byte) ([]byte, error) {
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
	_, err := io.ReadFull(c, out)
	return out, err
}

// Ping: how long a query takes once the connection is up -- what the core
// pays per query, not the handshake it pays once per connection. The first
// query sets the connection up, the second is timed: over DoH on the kept
// connection, over DoT and TCP on the same connection, over UDP it is just
// asked again. A server that closes a stream after one answer is timed with
// its handshake, the only way it can be used.
func (r Resolver) Ping(d Dialer, name string) ([]string, time.Duration, error) {
	if r.Scheme == "tls" || r.Scheme == "tcp" || (r.Scheme == "udp" && net.ParseIP(r.Host) == nil) {
		return r.pingStream(d, name)
	}
	if _, err := r.Lookup(d, name); err != nil {
		return nil, 0, err
	}
	t := time.Now()
	ips, err := r.Lookup(d, name)
	return ips, time.Since(t), err
}

func (r Resolver) pingStream(d Dialer, name string) ([]string, time.Duration, error) {
	ask := func(c net.Conn) ([]string, error) {
		q, id := buildQuery(name, typeA)
		resp, err := exchange(c, d, q)
		if err != nil {
			return nil, err
		}
		return parseAnswer(resp, id, typeA)
	}
	t := time.Now()
	c, err := r.streamConn(d)
	if err != nil {
		return nil, 0, err
	}
	defer c.Close()
	ips, err := ask(c)
	if err != nil {
		return nil, 0, err
	}
	cold := time.Since(t)
	t = time.Now()
	if warm, err := ask(c); err == nil {
		return warm, time.Since(t), nil
	}
	return ips, cold, nil
}

// udpResend: a datagram may be lost; the query goes again after this long,
// until the dialer's timeout
var udpResend = 2 * time.Second

// datagram asks over UDP through the listener. A truncated answer is asked
// again over TCP, as a resolver client does. A resolver given by name is
// asked over TCP as before: a datagram goes to an address, and resolving the
// name here would ask the system, not the path under test.
func (r Resolver) datagram(d Dialer, q []byte, id uint16) ([]byte, error) {
	ip := net.ParseIP(r.Host)
	if ip == nil {
		return r.stream(d, q)
	}
	u, err := d.DialUDP()
	if err != nil {
		return nil, err
	}
	defer u.Close()
	to := &net.UDPAddr{IP: ip, Port: r.Port}
	deadline := time.Now().Add(d.Timeout)
	buf := make([]byte, 64<<10)
	for {
		if _, err := u.WriteTo(q, to); err != nil {
			return nil, err
		}
		resend := time.Now().Add(udpResend)
		_ = u.SetReadDeadline(minTime(resend, deadline))
		for {
			n, from, err := u.ReadFrom(buf)
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				break
			}
			if err != nil {
				return nil, err
			}
			m := buf[:n]
			// an answer is the resolver's, to this very question: a 16-bit ID
			// alone let any datagram that guessed it pass for one
			if fa, ok := from.(*net.UDPAddr); !ok || !fa.IP.Equal(to.IP) || fa.Port != to.Port ||
				len(m) < len(q) || binary.BigEndian.Uint16(m) != id || m[2]&0x80 == 0 ||
				!bytes.EqualFold(m[12:len(q)], q[12:]) {
				continue // not the answer to this query
			}
			if m[2]&0x02 != 0 {
				return r.stream(d, q) // truncated
			}
			return append([]byte(nil), m...), nil
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("udp: no answer in %s", d.Timeout)
		}
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// LookupAny queries resolvers concurrently and takes the first answer --
// just like the core: otherwise the prober and traffic would get different nodes
func LookupAny(d Dialer, rs []Resolver, name string) ([]string, error) {
	return lookupAny(d, rs, name, Resolver.Lookup)
}

// LookupAnyV6: the same across the resolvers, but for AAAA.
func LookupAnyV6(d Dialer, rs []Resolver, name string) ([]string, error) {
	return lookupAny(d, rs, name, Resolver.LookupV6)
}

func lookupAny(d Dialer, rs []Resolver, name string, lookup func(Resolver, Dialer, string) ([]string, error)) ([]string, error) {
	type res struct {
		ips []string
		err error
	}
	ch := make(chan res, len(rs))
	for _, r := range rs {
		go func(r Resolver) {
			ips, err := lookup(r, d, name)
			if err == nil && len(ips) == 0 {
				err = errors.New("no records")
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

// --- DNS message format: exactly what an A or AAAA query needs ---

const (
	typeA    uint16 = 1
	typeAAAA uint16 = 28
)

func buildQuery(name string, qtype uint16) ([]byte, uint16) {
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
	b = append(b, 0)                            // end of name
	b = binary.BigEndian.AppendUint16(b, qtype) // type
	b = binary.BigEndian.AppendUint16(b, 1)     // class IN
	return b, id
}

var rcodeText = map[int]string{2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}

func parseAnswer(m []byte, id uint16, qtype uint16) ([]string, error) {
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
		if typ == qtype && ((qtype == typeA && rdl == 4) || (qtype == typeAAAA && rdl == 16)) {
			out = append(out, net.IP(m[off:off+rdl]).String())
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
