package core

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A junction in the core directory's place is removed as a link: what it
// points at keeps its files and its owner.
func TestSecureDirJunction(t *testing.T) {
	victim := t.TempDir()
	os.WriteFile(filepath.Join(victim, "precious"), []byte("x"), 0o644)
	dir := filepath.Join(t.TempDir(), "core")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", dir, victim).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v %s", err, out)
	}
	_ = secureDir(dir) // making it anew for SYSTEM may fail here, unelevated
	if fi, err := os.Lstat(dir); err == nil && fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		t.Fatal("the junction is still there")
	}
	if _, err := os.Stat(filepath.Join(victim, "precious")); err != nil {
		t.Fatalf("the junction's target was touched: %v", err)
	}
}
