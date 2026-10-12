package webui

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
	"time"

	"dpiswitch/internal/paths"
)

// A tunnel that answers its check is not a tunnel that works well. 12.10
// awg1 lost 4% of the small packets on the way to the laptop and a quarter
// of the full-size ones: downloads through it ran at 1-2 Mbit/s, and the
// state said "responding, 61 ms" all evening -- the check is one small
// request.
//
// The detector already times a TLS handshake through the first tunnel with
// every check it makes, and writes it to the probe journal. A lost packet
// costs a handshake a retransmission, so the share of handshakes far slower
// than this tunnel's usual one says how it carries -- with nothing measured
// anew and nothing sent through it. The second tunnel carries no checks and
// has no such figure.

type tunnelQuality struct {
	Median  int // ms, the handshakes of the last hour
	Usual   int // ms, of the journal before it
	SlowPct int
	Poor    bool
}

var (
	qualityWindow = time.Hour
	qualityMin    = 8  // handshakes in the window to say anything
	qualityUsual  = 30 // and before it, to know the usual
	// percent of slow ones that make a tunnel poor. Over the journal of
	// 22.09-12.10, 116 hours with enough handshakes: 97 under 10%, and the 8
	// at 20% and over all on the evenings the tunnel was known to be bad
	qualityPoor   = 20
	qualityTail   = int64(1 << 20)
	qualityEvery  = time.Minute
	qualityRebase = time.Hour
)

type shake struct {
	at time.Time
	ms int
}

// readShakes: the handshakes that got through the tunnel, from the last
// tail bytes of a probe journal; tail 0, the whole of it
func readShakes(path string, tail int64) []shake {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<16)
	if fi, err := f.Stat(); err == nil && tail > 0 && fi.Size() > tail {
		if _, err := f.Seek(fi.Size()-tail, io.SeekStart); err != nil {
			return nil
		}
		r.Reset(f)
		r.ReadString('\n') // the line the seek landed in
	}
	var out []shake
	for {
		line, err := r.ReadBytes('\n')
		var rep struct {
			Time   string `json:"time"`
			Proto  string `json:"proto"`
			Tunnel struct {
				TLSOk   bool          `json:"tls_ok"`
				TLSTime time.Duration `json:"tls_time_ns"`
			} `json:"tunnel"`
		}
		if json.Unmarshal(line, &rep) == nil && rep.Proto != "quic" && rep.Tunnel.TLSOk && rep.Tunnel.TLSTime > 0 {
			if at, perr := time.Parse(time.RFC3339, rep.Time); perr == nil {
				out = append(out, shake{at, int(rep.Tunnel.TLSTime / time.Millisecond)})
			}
		}
		if err != nil {
			return out
		}
	}
}

func medianMs(s []shake) int {
	ms := make([]int, len(s))
	for i, x := range s {
		ms[i] = x.ms
	}
	slices.Sort(ms)
	return ms[len(ms)/2]
}

// judgeQuality: the last hour's handshakes against the usual one. Slow is
// three times the usual and no less than 300 ms: a retransmission, not a
// far server.
func judgeQuality(recent []shake, usual int) (tunnelQuality, bool) {
	if len(recent) < qualityMin || usual <= 0 {
		return tunnelQuality{}, false
	}
	limit := max(3*usual, 300)
	slow := 0
	for _, x := range recent {
		if x.ms > limit {
			slow++
		}
	}
	q := tunnelQuality{Median: medianMs(recent), Usual: usual, SlowPct: 100 * slow / len(recent)}
	q.Poor = q.SlowPct >= qualityPoor
	return q, true
}

type qualityCache struct {
	mu      sync.Mutex
	at      time.Time
	q       tunnelQuality
	ok      bool
	usualAt time.Time
	usual   int
}

var awg1Quality qualityCache

// get: the first tunnel's quality, read from the journal once a minute; the
// usual handshake, from the whole journal and the one before it, once an hour
func (c *qualityCache) get(path string, now time.Time) (tunnelQuality, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() && now.Sub(c.at) < qualityEvery {
		return c.q, c.ok
	}
	c.at = now
	since := now.Add(-qualityWindow)
	if c.usualAt.IsZero() || now.Sub(c.usualAt) >= qualityRebase {
		c.usualAt, c.usual = now, 0
		old := slices.DeleteFunc(append(readShakes(path+".1", 0), readShakes(path, 0)...),
			func(x shake) bool { return x.at.After(since) })
		if len(old) >= qualityUsual {
			c.usual = medianMs(old)
		}
	}
	recent := slices.DeleteFunc(readShakes(path, qualityTail),
		func(x shake) bool { return !x.at.After(since) || x.at.After(now) })
	c.q, c.ok = judgeQuality(recent, c.usual)
	return c.q, c.ok
}

// quality: a tunnel's, for the pages; ok false when there is nothing to say
func quality(name string) (tunnelQuality, bool) {
	if name != "awg1" {
		return tunnelQuality{}, false
	}
	return awg1Quality.get(paths.Reports(), time.Now())
}

// qualityText: the line under a tunnel's state
func qualityText(lang string, q tunnelQuality) string {
	return fmt.Sprintf(tr(lang, "handshakes %d ms, usually %d · %d%% slow in the last hour"), q.Median, q.Usual, q.SlowPct)
}
