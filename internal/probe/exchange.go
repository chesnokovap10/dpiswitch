package probe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// local: the program's own DNS cache (dnscache), asked in its process --
// the detector's resolver while the cache answers the core for the direct
// path, so both get the same node. nil while there is none.
var local atomic.Pointer[func(q []byte) ([]byte, error)]

// SetLocal: the cache that answers LocalResolver, nil for none
func SetLocal(f func(q []byte) ([]byte, error)) {
	if f == nil {
		local.Store(nil)
		return
	}
	local.Store(&f)
}

// askLocal: a query asked of the cache
func askLocal(q []byte) ([]byte, error) {
	f := local.Load()
	if f == nil {
		return nil, errors.New("no local DNS cache")
	}
	return (*f)(q)
}

// LocalResolver: the cache as a resolver of the detector's (see Local)
func LocalResolver() Resolver { return Resolver{Raw: "local DNS cache", Scheme: "local"} }

// Exchange: a query as it is, and the answer as the server gives it, over d.
// Connections are kept between queries -- DoH's by its client, a stream's and
// a UDP association in a pool of their own: the DNS cache asks one server
// for everything it has not, and a connection set up for each query cost
// that query a handshake.
func (r Resolver) Exchange(d Dialer, q []byte) ([]byte, error) {
	if len(q) < 12 {
		return nil, errors.New("short DNS query")
	}
	var resp []byte
	var err error
	switch {
	case r.Scheme == "https":
		resp, err = r.doh(d, q)
	case r.Scheme == "local":
		resp, err = askLocal(q)
	case r.Scheme == "udp" && net.ParseIP(r.Host) != nil:
		resp, err = r.pooledDatagram(d, q)
	default:
		resp, err = r.pooledStream(d, q)
	}
	if err == nil && (len(resp) < 12 || !bytes.Equal(resp[:2], q[:2])) {
		err = errors.New("mismatched DNS response")
	}
	return resp, err
}

// keptIdle: how long a kept connection may wait for its next query. A
// server closes a quiet one in its own time, and a query written into it
// then is lost -- or, a connection dead without a word, waits out its
// timeout: kept no longer than servers commonly keep them.
var keptIdle = 30 * time.Second

type kept[T any] struct {
	c    T
	used time.Time
}

// pool: the idle connections to one server over one path
type pool[T interface{ Close() error }] struct {
	mu   sync.Mutex
	idle []kept[T]
}

func (p *pool[T]) get() (T, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.idle) > 0 {
		k := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		if time.Since(k.used) < keptIdle {
			return k.c, true
		}
		k.c.Close()
	}
	var none T
	return none, false
}

// put keeps c for the next query; a few at most, the rest are closed
func (p *pool[T]) put(c T) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.idle) >= 4 {
		c.Close()
		return
	}
	p.idle = append(p.idle, kept[T]{c, time.Now()})
}

var (
	streamPools   sync.Map // poolKey -> *pool[net.Conn]
	datagramPools sync.Map // poolKey -> *pool[*udpConn]
)

func (r Resolver) poolKey(d Dialer) string {
	return d.Addr + "|" + r.Scheme + "|" + net.JoinHostPort(r.Host, strconv.Itoa(r.Port))
}

// pooledStream: a query over a kept TCP or TLS connection (RFC 7766,
// 7858), one query at a time on it
func (r Resolver) pooledStream(d Dialer, q []byte) ([]byte, error) {
	v, _ := streamPools.LoadOrStore(r.poolKey(d), &pool[net.Conn]{})
	p := v.(*pool[net.Conn])
	for {
		c, reused := p.get()
		if !reused {
			var err error
			if c, err = r.streamConn(d); err != nil {
				return nil, err
			}
		}
		resp, err := exchange(c, d, q)
		if err == nil && len(resp) >= 2 && bytes.Equal(resp[:2], q[:2]) {
			_ = c.SetDeadline(time.Time{})
			p.put(c)
			return resp, nil
		}
		c.Close()
		if err == nil {
			err = errors.New("mismatched DNS response")
		}
		if !reused {
			return nil, err
		}
		// a kept connection the server closed meanwhile: once more, on a
		// new one
	}
}

// pooledDatagram: a query over a kept UDP association of the listener
func (r Resolver) pooledDatagram(d Dialer, q []byte) ([]byte, error) {
	v, _ := datagramPools.LoadOrStore(r.poolKey(d), &pool[*udpConn]{})
	p := v.(*pool[*udpConn])
	for {
		u, reused := p.get()
		if !reused {
			var err error
			if u, err = d.DialUDP(); err != nil {
				return nil, err
			}
		}
		resp, err := r.datagramOn(u, d, q)
		var tc truncated
		if err == nil || errors.As(err, &tc) {
			// the association is good, whatever the answer
			p.put(u)
		} else {
			u.Close()
		}
		if errors.As(err, &tc) {
			return r.pooledStream(d, q)
		}
		if err == nil || !reused {
			return resp, err
		}
	}
}

// truncated: a UDP answer with TC set, to be asked again over TCP
type truncated struct{}

func (truncated) Error() string { return "truncated" }

// datagramOn: a query over the association u, sent again every udpResend
// until the dialer's timeout; ID, question and sender of the answer checked
func (r Resolver) datagramOn(u *udpConn, d Dialer, q []byte) ([]byte, error) {
	ip := net.ParseIP(r.Host)
	if ip == nil {
		return nil, fmt.Errorf("%s: not an address", r.Host)
	}
	to := &net.UDPAddr{IP: ip, Port: r.Port}
	id := binary.BigEndian.Uint16(q)
	// the question, without what may follow it (EDNS)
	qend, ok := skipName(q, 12)
	if !ok || qend+4 > len(q) {
		return nil, errors.New("malformed DNS query")
	}
	qend += 4
	deadline := time.Now().Add(d.Timeout)
	buf := make([]byte, 64<<10)
	for {
		if _, err := u.WriteTo(q, to); err != nil {
			return nil, err
		}
		_ = u.SetReadDeadline(minTime(time.Now().Add(udpResend), deadline))
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
			// alone let any datagram that guessed it pass for one. One to a
			// query given up on earlier is passed over the same way.
			if fa, ok := from.(*net.UDPAddr); !ok || !fa.IP.Equal(to.IP) || fa.Port != to.Port ||
				len(m) < qend || binary.BigEndian.Uint16(m) != id || m[2]&0x80 == 0 ||
				!bytes.EqualFold(m[12:qend], q[12:qend]) {
				continue
			}
			if m[2]&0x02 != 0 {
				return nil, truncated{}
			}
			_ = u.SetReadDeadline(time.Time{})
			return append([]byte(nil), m...), nil
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("udp: no answer in %s", d.Timeout)
		}
	}
}
