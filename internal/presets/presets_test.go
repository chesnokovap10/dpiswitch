package presets

import (
	"os"
	"testing"

	"dpiswitch/internal/paths"
)

// Until the user changes a preset the shipped ones are used; after, the
// user's file holds the whole set -- a shipped one deleted stays deleted.
func TestLoadUpdate(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	got := Load()
	if len(got) != len(shipped) || got[0].ID != "youtube" || len(got[0].Lines) == 0 {
		t.Fatalf("not the shipped ones: %+v", got)
	}
	// what Load gives is the caller's to edit
	got[0].Lines[0] = "changed.example"
	if Load()[0].Lines[0] == "changed.example" {
		t.Fatal("the shipped presets were changed through a copy")
	}

	err := Update(func(ps []Preset) ([]Preset, error) {
		ps = ps[1:]
		return append(ps, Preset{ID: NewID(ps), Title: "Mine", Lines: []string{"my.example"}}), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got = Load()
	if len(got) != len(shipped) || got[0].ID != "telegram" || got[len(got)-1].Title != "Mine" ||
		!ValidID(got[len(got)-1].ID) {
		t.Fatalf("after a change: %+v", got)
	}
	if k := Known(); k["youtube"] || !k["telegram"] || !k[got[len(got)-1].ID] {
		t.Fatalf("known %v", k)
	}

	// an ID twice, or a bad one, is refused, and nothing is written
	if Update(func(ps []Preset) ([]Preset, error) { return append(ps, ps[0]), nil }) == nil {
		t.Fatal("an ID twice was saved")
	}
	if Update(func(ps []Preset) ([]Preset, error) { return append(ps, Preset{ID: "Bad ID"}), nil }) == nil {
		t.Fatal("a bad ID was saved")
	}
	big := Preset{ID: "big", Title: "Big", Lines: make([]string, fileMax/10)}
	for i := range big.Lines {
		big.Lines[i] = "a.example"
	}
	if err := Update(func(ps []Preset) ([]Preset, error) { return append(ps, big), nil }); err != ErrTooLarge {
		t.Fatalf("a file too large to read back was written: %v", err)
	}
	if len(Load()) != len(got) {
		t.Fatal("a refused change was written")
	}

	// a broken file gives the shipped ones: the service must keep working
	os.WriteFile(paths.UserPresets(), []byte("{"), 0o644)
	if got := Load(); len(got) != len(shipped) || got[0].ID != "youtube" {
		t.Fatalf("a broken file: %+v", got)
	}
	// no presets at all is a set of its own, not the shipped ones
	if err := Update(func([]Preset) ([]Preset, error) { return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if got := Load(); len(got) != 0 {
		t.Fatalf("every preset deleted, yet %+v", got)
	}
}
