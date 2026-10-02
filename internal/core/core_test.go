package core

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"dpiswitch/internal/paths"
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

// The core is extracted outside its home, the data directory: what its
// config names is made there, and the binary SYSTEM runs must not be
// among it.
func TestDirOutsideHome(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	rel, err := filepath.Rel(paths.DataDir(), Dir())
	if err == nil && filepath.IsLocal(rel) {
		t.Fatalf("the core is extracted into the data directory: %s", Dir())
	}
	if !slices.Contains(Paths(), filepath.Join(paths.DataDir(), "core", "mihomo.exe")) {
		t.Fatalf("a core left running from the old place is not looked for: %v", Paths())
	}
}

// The core an older version extracted into the data directory goes; a
// junction in it goes as the link, its target untouched.
func TestRemoveLegacy(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	old := filepath.Join(paths.DataDir(), "core")
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(old, "mihomo.exe"), []byte("MZ"), 0o644)
	victim := t.TempDir()
	os.WriteFile(filepath.Join(victim, "precious"), []byte("x"), 0o644)
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(old, "link"), victim).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v %s", err, out)
	}
	RemoveLegacy()
	if _, err := os.Lstat(old); !os.IsNotExist(err) {
		t.Fatalf("the old core directory is still there: %v", err)
	}
	if _, err := os.Stat(filepath.Join(victim, "precious")); err != nil {
		t.Fatalf("the junction's target was touched: %v", err)
	}
	RemoveLegacy() // nothing there: nothing done, nothing said
}
