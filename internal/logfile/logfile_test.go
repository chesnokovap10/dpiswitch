package logfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRotateIfOver(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "reports.jsonl")
	read := func(name string) string {
		b, _ := os.ReadFile(name)
		return string(b)
	}

	os.WriteFile(p, []byte("small"), 0o644)
	if err := RotateIfOver(p, 10); err != nil || read(p) != "small" {
		t.Fatalf("under the limit: err %v, file %q", err, read(p))
	}

	os.WriteFile(p+".1", []byte("older"), 0o644)
	os.WriteFile(p, []byte("big enough"), 0o644)
	if err := RotateIfOver(p, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("the full file is still in place")
	}
	if read(p+".1") != "big enough" {
		t.Errorf(".1 holds %q, want the rotated file", read(p+".1"))
	}

	if err := RotateIfOver(filepath.Join(dir, "missing"), 10); err != nil {
		t.Errorf("a missing file: %v", err)
	}
}
