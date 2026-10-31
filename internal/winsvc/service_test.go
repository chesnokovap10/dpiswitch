package winsvc

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

func TestUpdateCopy(t *testing.T) {
	dir := t.TempDir()
	source, target := filepath.Join(dir, "desktop.exe"), filepath.Join(dir, "installed.exe")
	if err := os.WriteFile(target, []byte("previous"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(source, target); err == nil {
		t.Fatal("missing update accepted")
	}
	if b, _ := os.ReadFile(target); string(b) != "previous" {
		t.Fatal("failed update damaged installed binary")
	}
	if err := os.WriteFile(source, []byte("new build"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(source, target); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "new build" {
		t.Fatal("installed binary not replaced")
	}
	if _, err := os.Stat(target + ".new"); !os.IsNotExist(err) {
		t.Fatal("temporary binary left behind")
	}
}

// The registration matches this binary only when it runs this very path:
// not one it is a prefix of, not one merely spelled with other case.
func TestSamePath(t *testing.T) {
	exe := `D:\2\mihomo\bin\dpiswitch.exe`
	for _, tc := range []struct {
		cmdline, exe string
		want         bool
	}{
		{`D:\2\mihomo\bin\dpiswitch.exe service`, exe, true},
		{`d:\2\MIHOMO\bin\DPISWITCH.EXE service`, exe, true},
		{`"C:\Program Files\DPI Switch\dpiswitch.exe" service`, `C:\Program Files\DPI Switch\dpiswitch.exe`, true},
		{`D:\2\mihomo\bin\dpiswitch.exe.bak service`, exe, false},
		{`D:\2\mihomo\bin2\dpiswitch.exe service`, exe, false},
		{`C:\foo2\dpiswitch.exe service`, `C:\foo\dpiswitch.exe`, false},
		{``, exe, false},
	} {
		if got := samePath(tc.cmdline, tc.exe); got != tc.want {
			t.Errorf("%q vs %q: %v, want %v", tc.cmdline, tc.exe, got, tc.want)
		}
	}
}

// Only the owner may start and stop the service; every other signed-in
// user may only look at it.
func TestSDDL(t *testing.T) {
	owner := "S-1-5-21-1-2-3-1001"
	s := sddl(owner)
	if !strings.Contains(s, "(A;;CCLCSWRPWPDTLOCRRC;;;"+owner+")") {
		t.Fatalf("the owner cannot start and stop: %s", s)
	}
	for _, ace := range strings.SplitAfter(s, ")") {
		if strings.HasSuffix(ace, ";;;IU)") && strings.Contains(ace, "RP") {
			t.Fatalf("interactive users may start or stop: %s", ace)
		}
	}
	if _, err := windows.SecurityDescriptorFromString(s); err != nil {
		t.Fatal(err)
	}
}

// Start and Stop report a service that never got there, and one whose state
// cannot be read, instead of success.
func TestWaitState(t *testing.T) {
	seq := func(states ...svc.State) func() (svc.State, error) {
		i := 0
		return func() (svc.State, error) {
			s := states[min(i, len(states)-1)]
			i++
			return s, nil
		}
	}
	if err := waitState(seq(svc.StartPending, svc.StartPending, svc.Running), svc.Running,
		time.Second, time.Millisecond); err != nil {
		t.Fatalf("reached Running: %v", err)
	}
	err := waitState(seq(svc.StartPending, svc.Stopped), svc.Running, 20*time.Millisecond, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "still stopped") {
		t.Fatalf("never running: %v", err)
	}
	broken := func() (svc.State, error) { return svc.Stopped, errors.New("access denied") }
	if err := waitState(broken, svc.Stopped, time.Second, time.Millisecond); err == nil {
		t.Fatal("an unreadable state passed for success")
	}
}
