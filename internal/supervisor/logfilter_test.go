package supervisor

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestDedupWriter(t *testing.T) {
	var out bytes.Buffer
	now := time.Date(2026, 9, 22, 17, 39, 0, 0, time.UTC)
	d := &dedupWriter{out: &out, window: time.Minute, now: func() time.Time { return now },
		seen: map[string]*dedupEntry{}, stop: make(chan struct{})}

	empty := `time="2026-09-22T17:39:26.1+03:00" level=warning msg="[TUN] Auto detect interface for 84.252.75.74 get empty name."` + "\n"
	dial := func(port string) string {
		return `time="2026-09-22T17:39:26.2+03:00" level=warning msg="[TCP] dial DIRECT 127.0.0.1:` + port +
			` --> 77.88.8.8:443 error: interface not found"` + "\n"
	}
	other := `time="2026-09-22T17:39:27+03:00" level=info msg="[TCP] 198.18.0.1:5000 --> ya.ru:443 using DIRECT"` + "\n"

	// a burst of interleaved repeats, split across writes at odd places
	burst := strings.Repeat(empty+dial("51000")+dial("51001"), 200)
	for i := 0; i < len(burst); i += 97 {
		end := i + 97
		if end > len(burst) {
			end = len(burst)
		}
		d.Write([]byte(burst[i:end]))
	}
	d.Write([]byte(other))

	// info lines are never collapsed
	d.Write([]byte(other))

	lines := strings.Count(out.String(), "\n")
	if lines != 4 {
		t.Fatalf("600 warnings (2 distinct once ports are masked) should collapse to 2 lines plus 2 verbatim info lines, got %d:\n%s", lines, out.String())
	}

	// the window ends -- summaries appear, then a new occurrence is written again
	now = now.Add(61 * time.Second)
	d.Write([]byte(empty))
	s := out.String()
	if !strings.Contains(s, "repeated 199 more times") || !strings.Contains(s, "repeated 399 more times") {
		t.Fatalf("expected summaries for 199 and 399 repeats:\n%s", s)
	}
	if !strings.HasSuffix(s, empty) {
		t.Fatalf("after the window a message must be written again:\n%s", s)
	}
	d.Close()
}
