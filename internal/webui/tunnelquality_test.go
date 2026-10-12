package webui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The first tunnel's quality comes from the handshakes the detector timed
// through it: 12.10 a tunnel losing packets answered its check all evening.
func TestTunnelQuality(t *testing.T) {
	now := time.Date(2026, 10, 12, 18, 30, 0, 0, time.Local)
	path := filepath.Join(t.TempDir(), "reports.jsonl")
	var b strings.Builder
	line := func(at time.Time, proto string, ok bool, ms int) {
		fmt.Fprintf(&b, `{"domain":"a.example","time":%q,"proto":%q,"tunnel":{"tls_ok":%v,"tls_time_ns":%d}}`+"\n",
			at.Format(time.RFC3339), proto, ok, ms*int(time.Millisecond))
	}
	write := func() {
		t.Helper()
		if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 40 {
		line(now.Add(-30*time.Hour+time.Duration(i)*time.Minute), "tcp", true, 110+i%20)
	}
	write()
	// the usual is known, the last hour holds too little to say anything
	if q, ok := new(qualityCache).get(path, now); ok {
		t.Fatalf("a quality from no handshakes of the last hour: %+v", q)
	}
	// a good hour; what failed, and QUIC, are not handshakes through it
	for i := range 10 {
		line(now.Add(-time.Duration(i+1)*time.Minute), "tcp", true, 125)
	}
	line(now.Add(-time.Minute), "tcp", false, 0)
	line(now.Add(-time.Minute), "quic", true, 4000)
	write()
	q, ok := new(qualityCache).get(path, now)
	if !ok || q.Poor || q.SlowPct != 0 || q.Median != 125 || q.Usual != 120 {
		t.Fatalf("a good hour: %+v %v", q, ok)
	}
	// 5 of 15 took a retransmission
	for i := range 5 {
		line(now.Add(-time.Duration(i+1)*time.Minute), "tcp", true, 1200)
	}
	write()
	c := new(qualityCache)
	q, ok = c.get(path, now)
	if !ok || !q.Poor || q.SlowPct != 33 {
		t.Fatalf("a poor hour: %+v %v", q, ok)
	}
	if s := qualityText("ru", q); s != fmt.Sprintf("отклик проб %d мс, обычно 120 · медленных %d%% за час", q.Median, q.SlowPct) {
		t.Errorf("said %q", s)
	}
	// read once a minute: the journal is megabytes
	os.Remove(path)
	if q2, ok := c.get(path, now.Add(30*time.Second)); !ok || q2 != q {
		t.Errorf("read again within the minute: %+v %v", q2, ok)
	}
	if _, ok := c.get(path, now.Add(2*time.Minute)); ok {
		t.Error("a quality kept with no journal")
	}
}
