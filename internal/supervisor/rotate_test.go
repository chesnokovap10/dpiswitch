package supervisor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotatingFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "core.log")
	// an existing oversized log is rotated right away on open
	os.WriteFile(p, []byte(strings.Repeat("x", 150)), 0o644)
	r, err := openRotating(p, 100)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p + ".1"); len(b) != 150 {
		t.Fatalf("old log not rotated on open: .1 has %d bytes", len(b))
	}
	line := strings.Repeat("y", 39) + "\n" // 40 bytes
	for i := 0; i < 5; i++ {               // 200 bytes through a 100-byte limit
		if _, err := r.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	r.Close()
	cur, _ := os.ReadFile(p)
	old, _ := os.ReadFile(p + ".1")
	if len(cur) > 100 || len(old) > 100 {
		t.Fatalf("limit exceeded: current %d, previous %d", len(cur), len(old))
	}
	// 40-byte lines, 100-byte limit: a file holds two lines; with one backup
	// the newest three lines survive (80 in .1, 40 current), the oldest two go
	if len(cur) != 40 || len(old) != 80 || strings.Contains(string(old), "x") {
		t.Fatalf("expected 40 current and 80 previous bytes of new data: current %d, previous %d", len(cur), len(old))
	}
}
