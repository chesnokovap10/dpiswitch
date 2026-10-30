package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/quic-go/quic-go"
)

type doqClient struct {
	mu   sync.Mutex
	conn *quic.Conn
}

var doqClients sync.Map

var errDoQProtocol = errors.New("invalid DoQ response")

func (r Resolver) doqClient(d Dialer) *doqClient {
	key := r.poolKey(d) + "|" + d.Pass + "|" + d.Timeout.String()
	c, _ := doqClients.LoadOrStore(key, &doqClient{})
	return c.(*doqClient)
}

func (c *doqClient) connection(ctx context.Context, r Resolver, d Dialer) (*quic.Conn, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if c.conn != nil && c.conn.Context().Err() == nil {
		return c.conn, true, nil
	}
	tc := r.tlsConf()
	tc.NextProtos = []string{"doq"}
	conn, err := r.dialDNSQUIC(ctx, d, tc, &quic.Config{MaxIdleTimeout: dohIdle})
	if err != nil {
		return nil, false, err
	}
	c.conn = conn
	return conn, false, nil
}

func (c *doqClient) discard(conn *quic.Conn, err error) {
	c.mu.Lock()
	if c.conn == conn {
		c.conn = nil
	}
	c.mu.Unlock()
	code := quic.ApplicationErrorCode(0)
	if errors.Is(err, errDoQProtocol) || errors.Is(err, io.ErrUnexpectedEOF) {
		code = 2
	}
	conn.CloseWithError(code, "")
}

// RFC 9250: each query has its own bidirectional stream, a two-byte length
// prefix, ID zero on the wire, and a FIN after the one message on each side.
// Restore the caller's ID for the cache and ordinary DNS response validation.
func (r Resolver) doq(d Dialer, q []byte) ([]byte, error) {
	if len(q) < 12 || len(q) > 65535 {
		return nil, errors.New("invalid DoQ query size")
	}
	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()
	c := r.doqClient(d)
	for attempt := 0; ; attempt++ {
		conn, reused, err := c.connection(ctx, r, d)
		if err != nil {
			return nil, err
		}
		resp, err := exchangeDoQ(ctx, conn, q)
		if err == nil {
			return resp, nil
		}
		c.discard(conn, err)
		if !reused || attempt > 0 || ctx.Err() != nil {
			return nil, err
		}
	}
}

func exchangeDoQ(ctx context.Context, conn *quic.Conn, q []byte) ([]byte, error) {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(3); stream.CancelWrite(3) })
	defer stop()
	complete := false
	defer func() {
		if !complete {
			stream.CancelRead(3)
			stream.CancelWrite(3)
		}
	}()
	if end, ok := ctx.Deadline(); ok {
		stream.SetDeadline(end)
	}
	wire := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(wire, uint16(len(q)))
	copy(wire[2:], q)
	wire[2], wire[3] = 0, 0
	if _, err = io.Copy(stream, bytes.NewReader(wire)); err != nil {
		return nil, err
	}
	if err = stream.Close(); err != nil {
		return nil, err
	}
	var prefix [2]byte
	if _, err = io.ReadFull(stream, prefix[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(prefix[:]))
	if n < 12 {
		return nil, fmt.Errorf("%w: short message", errDoQProtocol)
	}
	b := make([]byte, n)
	if _, err = io.ReadFull(stream, b); err != nil {
		return nil, err
	}
	var extra [1]byte
	if n, err := stream.Read(extra[:]); n != 0 || err != io.EOF {
		return nil, fmt.Errorf("%w: expected FIN", errDoQProtocol)
	}
	if b[0] != 0 || b[1] != 0 {
		return nil, fmt.Errorf("%w: ID must be zero", errDoQProtocol)
	}
	if b[2]&0x80 == 0 {
		return nil, fmt.Errorf("%w: QR clear", errDoQProtocol)
	}
	copy(b[:2], q[:2])
	complete = true
	return b, nil
}
