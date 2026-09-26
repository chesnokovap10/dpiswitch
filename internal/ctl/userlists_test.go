package ctl

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
)

// The core gets from a user list only what the UI would have written: a
// line that is neither a comment nor a rule of the list's kind is dropped.
func TestCleanList(t *testing.T) {
	in := "# mine\nexample.com\n+.example.org\n\nDOMAIN-SUFFIX,evil.com\nbad host\nMATCH,DIRECT\n"
	got := string(CleanList(paths.DirectList, []byte(in)))
	if got != "# mine\nexample.com\n+.example.org\n" {
		t.Fatalf("domain list: %q", got)
	}
	apps := "PROCESS-NAME,telegram.exe\nPROCESS-PATH,C:/a b/x.exe\nMATCH,DIRECT\nPROCESS-NAME,a,b.exe\nDOMAIN,x.com\n"
	if got := string(CleanList(paths.AppsList, []byte(apps))); got != "PROCESS-NAME,telegram.exe\nPROCESS-PATH,C:/a b/x.exe\n" {
		t.Fatalf("apps: %q", got)
	}
	if got := string(CleanList(paths.TunnelList, nil)); got != "# empty\n" {
		t.Fatalf("empty: %q", got)
	}
}

// The service copies what the user changed, says which providers changed,
// writes the presets the settings ask for, and reads no list through a link.
func TestSyncUserFiles(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(paths.Data(paths.DirectList), []byte("# empty\n"), 0o644)
	os.WriteFile(paths.User(paths.DirectList), []byte("example.com\n"), 0o644)
	got := SyncUserFiles()
	if !contains(got, "force-direct") || !Synced(paths.DirectList) {
		t.Fatalf("changed %v, synced %v", got, Synced(paths.DirectList))
	}
	for _, p := range presets.All {
		if !contains(got, "preset-"+p.ID) {
			t.Fatalf("preset %s not written: %v", p.ID, got)
		}
	}
	if again := SyncUserFiles(); len(again) != 0 {
		t.Fatalf("nothing changed, yet %v", again)
	}
	// a user list that is a link is not followed
	os.Remove(paths.User(paths.TunnelList))
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", paths.User(paths.TunnelList), t.TempDir()).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v %s", err, out)
	}
	if got := SyncUserFiles(); contains(got, "force-tunnel") {
		t.Fatalf("a junction was taken as a list: %v", got)
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// An unreadable memory is set aside, not overwritten by the empty one.
func TestLoadStateBad(t *testing.T) {
	p := t.TempDir() + `\state.json`
	os.WriteFile(p, []byte(`{"networks": {"AS1": `), 0o644)
	st := loadState(p)
	if len(st.Networks) != 0 {
		t.Fatalf("%v", st.Networks)
	}
	if b, err := os.ReadFile(p + ".bad"); err != nil || !strings.Contains(string(b), "AS1") {
		t.Fatalf("not set aside: %q %v", b, err)
	}
	if err := st.save(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p + ".bad"); !strings.Contains(string(b), "AS1") {
		t.Fatal("the saved copy was overwritten")
	}
}
