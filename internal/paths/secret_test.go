package paths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func sddl(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

// a directory that grants every user modify, inherited -- as the data
// directory does
func openDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := GrantUsersModify(dir); err != nil {
		t.Fatal(err)
	}
	if s := sddl(t, dir); !strings.Contains(s, ";;;BU)") {
		t.Fatalf("setup: the directory does not grant users: %s", s)
	}
	return dir
}

func leftovers(t *testing.T, dir string) {
	t.Helper()
	if m, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(m) != 0 {
		t.Fatalf("temporary files left: %v", m)
	}
}

// A key file is born locked down in a directory open to every user, and
// nothing else gets a handle to it on the way.
func TestWriteSecret(t *testing.T) {
	dir := openDir(t)
	p := filepath.Join(dir, "source.conf")
	if err := WriteSecret(p, []byte("PrivateKey = one")); err != nil {
		t.Fatal(err)
	}
	s := sddl(t, p)
	if !strings.HasPrefix(s, "D:P") || strings.Contains(s, "BU)") || !strings.Contains(s, ";;;SY)") {
		t.Fatalf("permissions %s: want protected, SYSTEM, no users", s)
	}
	// and again over the existing one
	if err := WriteSecret(p, []byte("PrivateKey = two")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "PrivateKey = two" {
		t.Fatalf("content %q", b)
	}
	leftovers(t, dir)
}

// Rewriting keeps the file's own permissions -- the user's access the tray
// needs -- and replaces the content whole.
func TestReplaceSecret(t *testing.T) {
	dir := openDir(t)
	p := filepath.Join(dir, "config.yaml")
	if err := WriteSecret(p, []byte("old")); err != nil {
		t.Fatal(err)
	}
	before := sddl(t, p)
	if err := ReplaceSecret(p, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if after := sddl(t, p); after != before {
		t.Fatalf("permissions changed:\n%s\n%s", before, after)
	}
	if b, _ := os.ReadFile(p); string(b) != "new" {
		t.Fatalf("content %q", b)
	}
	leftovers(t, dir)

	// no file to take permissions from: nothing is created
	missing := filepath.Join(dir, "missing.yaml")
	if err := ReplaceSecret(missing, []byte("x")); err == nil {
		t.Fatal("a missing file was written")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("a missing file was created")
	}
	leftovers(t, dir)
}

// A write that cannot finish leaves the old file whole.
func TestReplaceSecretKeepsOld(t *testing.T) {
	dir := openDir(t)
	p := filepath.Join(dir, "config.yaml")
	if err := WriteSecret(p, []byte("old")); err != nil {
		t.Fatal(err)
	}
	// held open without delete sharing: it cannot be replaced
	name, _ := windows.UTF16PtrFromString(p)
	h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = ReplaceSecret(p, []byte("new"))
	windows.CloseHandle(h)
	if err == nil {
		t.Fatal("replaced a file held open")
	}
	if b, _ := os.ReadFile(p); string(b) != "old" {
		t.Fatalf("the old file was damaged: %q", b)
	}
	leftovers(t, dir)
}
