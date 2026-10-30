package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type doh3Client struct {
	client     *http.Client
	mu         sync.Mutex
	retryAfter time.Time
}

var doh3Clients sync.Map

// Leave most of the request deadline for TCP fallback when UDP is dropped.
// A failed path is retried later, not on every DNS query.
func doh3Budget(timeout time.Duration) time.Duration { return min(timeout/3, 1200*time.Millisecond) }

func (r Resolver) doh3Client(d Dialer) *doh3Client {
	key := r.poolKey(d) + "|" + d.Pass + "|" + d.Timeout.String() + "|" + r.Path
	if c, ok := doh3Clients.Load(key); ok {
		return c.(*doh3Client)
	}
	c, _ := doh3Clients.LoadOrStore(key, &doh3Client{client: r.newDoH3HTTPClient(d)})
	return c.(*doh3Client)
}

func (r Resolver) newDoH3HTTPClient(d Dialer) *http.Client {
	tlsConf := r.tlsConf()
	tlsConf.NextProtos = []string{"h3"}
	tr := &http3.Transport{
		TLSClientConfig: tlsConf,
		QUICConfig:      &quic.Config{MaxIdleTimeout: dohIdle},
		Dial: func(ctx context.Context, _ string, tc *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, doh3Budget(d.Timeout))
			defer cancel()
			return r.dialDNSQUIC(ctx, d, tc, cfg)
		},
	}
	return &http.Client{Transport: tr}
}

func (r Resolver) dohProtocol(d Dialer, q []byte) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()
	c := r.doh3Client(d)
	c.mu.Lock()
	try := !time.Now().Before(c.retryAfter)
	client := c.client
	c.mu.Unlock()
	if try {
		h3ctx, stop := context.WithTimeout(ctx, doh3Budget(d.Timeout))
		b, err := r.askDoH3(h3ctx, client, q)
		stop()
		c.mu.Lock()
		if c.client == client {
			if err == nil {
				c.retryAfter = time.Time{}
			} else {
				c.retryAfter = time.Now().Add(30 * time.Second)
				// A cancelled handshake may still occupy the HTTP/3 pool.
				// Start the next capability check with a fresh transport.
				c.client = r.newDoH3HTTPClient(d)
			}
		}
		c.mu.Unlock()
		if err == nil {
			return b, "DoH3", nil
		}
		client.Transport.(*http3.Transport).Close()
	}
	b, err := r.dohTCP(ctx, d, q)
	return b, "DoH", err
}

func (r Resolver) askDoH3(ctx context.Context, client *http.Client, q []byte) ([]byte, error) {
	u := "https://" + net.JoinHostPort(r.Host, strconv.Itoa(r.Port)) + r.Path
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err == nil && (resp.ProtoMajor != 3 || len(b) < 12 || len(q) < 2 || !bytes.Equal(b[:2], q[:2]) || b[2]&0x80 == 0) {
		err = fmt.Errorf("invalid DoH3 response")
	}
	return b, err
}

func (r Resolver) pingDoH(d Dialer, name string) ([]string, time.Duration, string, error) {
	ask := func() ([]string, string, error) {
		q, _ := buildQuery(name, typeA)
		b, kind, err := r.dohProtocol(d, q)
		if err != nil {
			return nil, kind, err
		}
		ips, err := parseAnswer(b, q, typeA)
		return ips, kind, err
	}
	if _, kind, err := ask(); err != nil {
		return nil, 0, kind, err
	}
	t := time.Now()
	ips, kind, err := ask()
	return ips, time.Since(t), kind, err
}
