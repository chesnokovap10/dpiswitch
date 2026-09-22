package supervisor

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
)

// dedupWriter collapses repeated core log messages.
//
// While the network is down the core retries the tunnel endpoints and the
// DNS servers in a tight loop and logs 2-3 lines per attempt ("Auto detect
// interface for X get empty name", "dial ... interface not found"). A one-
// minute Wi-Fi drop produced ~1000 lines and the log grew to 6 MB. The
// messages themselves are useful -- they show when the network was gone --
// only their repetition is noise.
//
// The first occurrence of every message is written as is; identical
// messages within the window are counted and summarised with a single line
// when the window ends. Messages are compared without their timestamp and
// with local source ports masked, so the same event from different sockets
// counts as a repeat.
type dedupWriter struct {
	mu     sync.Mutex
	out    io.Writer
	window time.Duration
	now    func() time.Time
	buf    []byte
	seen   map[string]*dedupEntry
	stop   chan struct{}
}

type dedupEntry struct {
	first      time.Time
	suppressed int
	sample     string // the message text, for the summary line
}

var (
	// time="2026-09-22T17:39:26.123+03:00" at the start of a mihomo line
	timeField = regexp.MustCompile(`^time="[^"]*" `)
	// local endpoints: 127.0.0.1:51234, 198.18.0.1:51234, [fdfe:...]:51234, [2001:2::...]:51234
	srcPort = regexp.MustCompile(`((?:127\.0\.0\.1|198\.18\.\d+\.\d+|\[[0-9a-f:]+\]):)\d+`)
)

func newDedupWriter(out io.Writer, window time.Duration) *dedupWriter {
	d := &dedupWriter{out: out, window: window, now: time.Now,
		seen: map[string]*dedupEntry{}, stop: make(chan struct{})}
	go d.ticker()
	return d
}

func (d *dedupWriter) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.buf = append(d.buf, p...)
	for {
		i := bytes.IndexByte(d.buf, '\n')
		if i < 0 {
			break
		}
		line := string(d.buf[:i+1])
		d.buf = d.buf[i+1:]
		d.line(line)
	}
	return len(p), nil
}

func (d *dedupWriter) line(line string) {
	d.expire()
	// only warnings and errors are collapsed: info lines are the per-connection
	// record (which host, which rule, when) and are needed verbatim when
	// investigating a problem
	if !strings.Contains(line, "level=warning") && !strings.Contains(line, "level=error") {
		io.WriteString(d.out, line)
		return
	}
	key := srcPort.ReplaceAllString(timeField.ReplaceAllString(line, ""), "${1}N")
	if e, ok := d.seen[key]; ok {
		e.suppressed++
		return
	}
	d.seen[key] = &dedupEntry{first: d.now(), sample: key}
	io.WriteString(d.out, line)
}

// expire flushes summaries of windows that have ended. Caller holds mu.
func (d *dedupWriter) expire() {
	now := d.now()
	for k, e := range d.seen {
		if now.Sub(e.first) < d.window {
			continue
		}
		if e.suppressed > 0 {
			fmt.Fprintf(d.out, "time=%q level=info msg=\"[dpiswitch] previous message repeated %d more times in %s: %s\"\n",
				now.Format(time.RFC3339Nano), e.suppressed, d.window, trimMsg(e.sample))
		}
		delete(d.seen, k)
	}
}

// trimMsg keeps the message text of a mihomo line for the summary
func trimMsg(s string) string {
	s = string(bytes.TrimSpace([]byte(s)))
	if i := bytes.Index([]byte(s), []byte(`msg="`)); i >= 0 {
		s = s[i+5:]
	}
	s = string(bytes.TrimSuffix([]byte(s), []byte(`"`)))
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

// ticker flushes summaries even when the core has gone quiet
func (d *dedupWriter) ticker() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			d.mu.Lock()
			d.expire()
			d.mu.Unlock()
		case <-d.stop:
			return
		}
	}
}

// Close writes the pending summaries and stops the ticker.
func (d *dedupWriter) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.buf) > 0 {
		d.line(string(d.buf) + "\n")
		d.buf = nil
	}
	for k, e := range d.seen {
		if e.suppressed > 0 {
			fmt.Fprintf(d.out, "time=%q level=info msg=\"[dpiswitch] previous message repeated %d more times: %s\"\n",
				d.now().Format(time.RFC3339Nano), e.suppressed, trimMsg(e.sample))
		}
		delete(d.seen, k)
	}
	close(d.stop)
	return nil
}
