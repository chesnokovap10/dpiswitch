package supervisor

import (
	"bytes"
	"log"
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

// A write that fails -- a full disk -- is no error to the copying either:
// the line is dropped, and the file opened anew for the next.
func TestRotatingFileWriteFails(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	p := filepath.Join(t.TempDir(), "core.log")
	r, err := openRotating(p, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.f.Close() // every write to it fails from here on
	if n, err := r.Write([]byte("lost\n")); n != 5 || err != nil {
		t.Fatalf("the failed write: %d, %v", n, err)
	}
	if n, err := r.Write([]byte("kept\n")); n != 5 || err != nil {
		t.Fatalf("the next write: %d, %v", n, err)
	}
	if b, _ := os.ReadFile(p); string(b) != "kept\n" {
		t.Fatalf("the log holds %q", b)
	}
	if got := strings.Count(buf.String(), "unavailable"); got != 1 {
		t.Fatalf("said %d times: %q", got, buf.String())
	}
}

// A core log that cannot be opened still takes the core's output -- an
// error would stop the copying and hang the core -- and says so once.
func TestRotatingFileLost(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	r := &rotatingFile{path: filepath.Join(t.TempDir(), "no-such-dir", "mihomo.log"), max: 1 << 20}
	for i := 0; i < 3; i++ {
		if n, err := r.Write([]byte("line\n")); n != 5 || err != nil {
			t.Fatalf("write %d: %d, %v", i, n, err)
		}
	}
	if got := strings.Count(buf.String(), "unavailable"); got != 1 {
		t.Fatalf("said %d times: %q", got, buf.String())
	}
}
