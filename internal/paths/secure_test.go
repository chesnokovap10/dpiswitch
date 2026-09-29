package paths

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// asUser: the locks are taken for the test's own account -- setting SYSTEM
// as an owner needs rights a test does not have.
func asUser(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	old := svcSID
	svcSID = u.Uid
	t.Cleanup(func() { svcSID = old })
	return u.Uid
}

func junction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v %s", err, out)
	}
}

// An older installation, with the tricks the Users-modify it granted
// allowed, is taken over: links go (and what they pointed at stays as it
// was), the user's files move to UserDir, and nobody but the owner may
// write anywhere.
func TestSecureDataDir(t *testing.T) {
	me := asUser(t)
	t.Setenv("ProgramData", t.TempDir())
	root := DataDir()
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("icacls", root, "/grant", "*S-1-5-32-545:(OI)(CI)(M)").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v %s", err, out)
	}
	victim := t.TempDir()
	os.WriteFile(filepath.Join(victim, "precious"), []byte("x"), 0o644)
	junction(t, LogDir(), victim)
	junction(t, filepath.Join(root, "core"), victim)
	if err := WriteSecret(Data("source.conf"), []byte("[Interface]\nPrivateKey = k\n")); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(Data("settings.json"), []byte(`{"slow_pct":30}`), 0o644)
	os.WriteFile(Data(DirectList), []byte("example.com\n"), 0o644)
	os.WriteFile(Data("controller-state.json"), []byte("{}"), 0o644)

	if err := SecureDataDir(me); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(victim, "precious")); err != nil {
		t.Fatalf("the junction's target was touched: %v", err)
	}
	if s := sddl(t, victim); strings.HasPrefix(s, "D:P") {
		t.Fatalf("the junction's target got the data directory's permissions: %s", s)
	}
	if fi, err := os.Lstat(LogDir()); err != nil || !fi.IsDir() || fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		t.Fatalf("logs is not a plain directory: %v %v", fi, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "core")); !os.IsNotExist(err) {
		t.Fatalf("the core junction is still there: %v", err)
	}
	for _, n := range []string{"source.conf", "settings.json"} {
		if _, err := os.Stat(Data(n)); !os.IsNotExist(err) {
			t.Fatalf("%s left in the data directory", n)
		}
		if _, err := os.Stat(User(n)); err != nil {
			t.Fatalf("%s not moved: %v", n, err)
		}
	}
	if b, _ := os.ReadFile(User(DirectList)); string(b) != "example.com\n" {
		t.Fatalf("the list was not copied: %q", b)
	}
	if b, _ := os.ReadFile(Data(DirectList)); string(b) != "example.com\n" {
		t.Fatalf("the service's copy of the list is gone: %q", b)
	}
	for _, p := range []string{root, Data("controller-state.json"), LogDir()} {
		if s := sddl(t, p); !strings.HasPrefix(s, "D:P") || strings.Contains(s, "0x1301bf;;;BU") ||
			strings.Contains(s, ";FA;;;BU") || !strings.Contains(s, "BU)") {
			t.Fatalf("%s: %s -- want protected, Users read only", p, s)
		}
	}
	if s := sddl(t, User("source.conf")); strings.Contains(s, "BU)") {
		t.Fatalf("the moved key is readable by users: %s", s)
	}
	if s := sddl(t, UserDir()); strings.Contains(s, "BU)") || !strings.Contains(s, "(A;OIIO;0x1301bf;;;"+sddlName(t, me)+")") {
		t.Fatalf("user directory: %s", s)
	}

	// a second run changes nothing and fails on nothing
	if err := SecureDataDir(me); err != nil {
		t.Fatal(err)
	}
}

// A file the user may have swapped for a link is not read through it.
func TestReadUserFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "settings.json")
	os.WriteFile(p, []byte("{}"), 0o644)
	if b, err := ReadUserFile(p, 100); err != nil || string(b) != "{}" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := ReadUserFile(p, 1); err == nil {
		t.Fatal("a file over the limit was read")
	}
	if _, err := ReadUserFile(filepath.Join(dir, "missing"), 100); !os.IsNotExist(err) {
		t.Fatalf("missing: %v", err)
	}
	link := filepath.Join(dir, "link")
	junction(t, link, t.TempDir())
	if _, err := ReadUserFile(link, 100); err == nil {
		t.Fatal("read through a junction")
	}
	hard := filepath.Join(dir, "hard")
	if err := os.Link(p, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadUserFile(hard, 100); err == nil {
		t.Fatal("read a file with a second hard link")
	}
}

func TestValidSID(t *testing.T) {
	for s, want := range map[string]bool{
		"S-1-5-21-1-2-3-1001": true, "S-1-5-18": false, "S-1-5-21-1-2-3-1001)(A;;FA;;;WD": false, "": false,
	} {
		if ValidSID(s) != want {
			t.Errorf("%q: want %v", s, want)
		}
	}
}
