package webui

import (
	"os"
	"testing"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
)

// Two saves within the clock's tick, of the same size, look the same to a
// look at the file: the second is read all the same (see settle).
func TestMemoSameSizeWrites(t *testing.T) {
	testServer(t)
	for _, pct := range []int{20, 30, 40, 50} {
		if _, err := ctl.UpdateSettings(paths.Settings(), func(s *ctl.Settings) error {
			s.SlowPct = pct
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if got := loadSettings().SlowPct; got != pct {
			t.Fatalf("slow_pct %d read as %d", pct, got)
		}
	}
}

// What a caller does with its copy stays in its copy.
func TestMemoCopies(t *testing.T) {
	testServer(t)
	if _, err := ctl.UpdateSettings(paths.Settings(), func(s *ctl.Settings) error {
		s.DirectDNS = []string{"1.1.1.1"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a := loadSettings()
	a.DirectDNS[0] = "changed"
	if b := loadSettings(); b.DirectDNS[0] != "1.1.1.1" {
		t.Fatalf("the kept settings changed through a copy: %v", b.DirectDNS)
	}
	if err := writeEntries(paths.DirectList, []string{"a.example", "b.example"}); err != nil {
		t.Fatal(err)
	}
	e := readEntries(paths.DirectList)
	e[0] = "changed"
	if f := readEntries(paths.DirectList); f[0] != "a.example" {
		t.Fatalf("the kept list changed through a copy: %v", f)
	}
}

// A file gone is a change too: the list deleted by hand reads empty.
func TestMemoFileGone(t *testing.T) {
	testServer(t)
	if err := writeEntries(paths.TunnelList, []string{"a.example"}); err != nil {
		t.Fatal(err)
	}
	if got := readEntries(paths.TunnelList); len(got) != 1 {
		t.Fatalf("list read as %v", got)
	}
	if err := os.Remove(paths.User(paths.TunnelList)); err != nil {
		t.Fatal(err)
	}
	if got := readEntries(paths.TunnelList); len(got) != 0 {
		t.Fatalf("a list deleted still read as %v", got)
	}
}
