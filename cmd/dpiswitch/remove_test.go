package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The cleanup deletes every folder given, one held open until later too,
// and a name with spaces, quotes' neighbours and a percent sign is only a
// name to it.
func TestCleanupLater(t *testing.T) {
	root := t.TempDir()
	free := filepath.Join(root, "DPI Switch & 100%x")
	held := filepath.Join(root, "dpiswitch")
	for _, d := range []string{free, held} {
		if err := os.MkdirAll(filepath.Join(d, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "sub", "f.txt"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// a sibling that must stay
	keep := filepath.Join(root, "keep")
	if err := os.Mkdir(keep, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(held, "sub", "f.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanupLater([]string{free, held}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(free); !os.IsNotExist(err) {
		t.Errorf("%s is still there: %v", free, err)
	}
	if _, err := os.Stat(held); err != nil {
		t.Errorf("the held folder went while held: %v", err)
	}
	f.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(held); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s is still there once let go", held)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("a folder not given was deleted: %v", err)
	}
}
