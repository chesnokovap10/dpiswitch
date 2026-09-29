package paths

import (
	"os"
	"os/exec"
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

// sddlName: an account as Windows writes it in SDDL -- a well-known one by
// its alias, not its SID: the built-in Administrator, which CI builds as,
// is "LA", and looking for its SID failed on an ACL that was right.
func sddlName(t *testing.T, sid string) string {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("D:(A;;FA;;;" + sid + ")")
	if err != nil {
		t.Fatal(err)
	}
	s := strings.TrimSuffix(sd.String(), ")")
	return s[strings.LastIndex(s, ";")+1:]
}

// a directory that grants every user modify, inherited -- as the data
// directory does
func openDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if out, err := exec.Command("icacls", dir, "/grant", "*S-1-5-32-545:(OI)(CI)(M)").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v %s", err, out)
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

// A service's key file is readable by the owner, writable by no one else.
func TestWriteServiceSecret(t *testing.T) {
	asUser(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	owner := "S-1-5-21-1-2-3-1001"
	if err := WriteServiceSecret(p, []byte("secret"), owner); err != nil {
		t.Fatal(err)
	}
	s := sddl(t, p)
	if !strings.HasPrefix(s, "D:P") || strings.Contains(s, "BU)") || !strings.Contains(s, "(A;;FR;;;"+owner+")") {
		t.Fatalf("permissions %s: want protected, the owner reading, no users", s)
	}
	leftovers(t, dir)
}

// sddlName gives the alias Windows writes for a well-known account and the
// SID itself for any other.
func TestSDDLName(t *testing.T) {
	for sid, want := range map[string]string{
		"S-1-5-18":     "SY",
		"S-1-5-32-544": "BA",
		"S-1-5-32-545": "BU",
		"S-1-5-21-1004336348-1177238915-682003330-1001": "S-1-5-21-1004336348-1177238915-682003330-1001",
	} {
		if got := sddlName(t, sid); got != want {
			t.Errorf("%s: %s, want %s", sid, got, want)
		}
	}
}
