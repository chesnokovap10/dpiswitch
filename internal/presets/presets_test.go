package presets

import (
	"os"
	"slices"
	"strings"
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

// The shipped presets come back as shipped, the deleted ones in their
// places, and the user's own stay after them. With none of the user's own
// the user's file goes, and the program's presets are followed again.
func TestRestore(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	if Restorable(Load()) {
		t.Fatal("the shipped presets as they are: nothing to restore")
	}
	mine := Preset{ID: "mine", Title: "Mine", Lines: []string{"my.example"}}
	err := Update(func(ps []Preset) ([]Preset, error) {
		ps[0].Lines = []string{"edited.example"} // youtube
		ps = slices.DeleteFunc(ps, func(p Preset) bool { return p.ID == "ai" })
		return append(ps, mine), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !Restorable(Load()) {
		t.Fatal("a shipped preset edited and one deleted: nothing to restore?")
	}
	was, err := Restore()
	if err != nil {
		t.Fatal(err)
	}
	if len(was) != len(shipped) || was[0].Lines[0] != "edited.example" {
		t.Fatalf("not the presets as they were: %+v", was)
	}
	got := Load()
	var ids []string
	for _, p := range got {
		ids = append(ids, p.ID)
	}
	if strings.Join(ids, ",") != "youtube,telegram,discord,ai,social,mine" {
		t.Fatalf("restored %v", ids)
	}
	if yt, _ := Shipped("youtube"); !slices.Equal(got[0].Lines, yt.Lines) || Restorable(got) {
		t.Fatalf("youtube not as shipped: %v", got[0].Lines)
	}

	// the user's own gone, a restore leaves no file of the user's at all
	if err := Update(func(ps []Preset) ([]Preset, error) { return ps[:len(ps)-1], nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(paths.UserPresets()); err == nil {
		t.Fatal("the user's file is still there")
	}
	if got := Load(); len(got) != len(shipped) || Restorable(got) {
		t.Fatalf("after the file went: %+v", got)
	}
}

// A file from before a version is read as it meant -- a name with
// everything under it -- and written back with the version: a name written
// alone after that is the name alone.
func TestOldFile(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	old := `[{"id":"mine","title":"Mine","lines":["# c","example.com","+.example.org","*.example.net",".example.biz","1.2.3.4","10.0.0.0/8","app.exe"]}]`
	if err := os.WriteFile(paths.UserPresets(), []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	want := "# c,+.example.com,+.example.org,+.example.net,+.example.biz,1.2.3.4,10.0.0.0/8,app.exe"
	if got := strings.Join(Load()[0].Lines, ","); got != want {
		t.Fatalf("read as %s", got)
	}
	if err := Update(func(ps []Preset) ([]Preset, error) {
		ps[0].Lines = append(ps[0].Lines, "alone.example")
		return ps, nil
	}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(paths.UserPresets())
	if !strings.Contains(string(b), `"version": 2`) {
		t.Fatalf("written without the version:\n%s", b)
	}
	if got := strings.Join(Load()[0].Lines, ","); got != want+",alone.example" {
		t.Fatalf("read back as %s", got)
	}
}

// The user's file there and not read -- refused for what it is, held -- is
// not written over: a change made to the shipped presets, given in its
// place, took every preset the user had.
func TestUpdateKeepsWhatItCannotRead(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	if err := Update(func(ps []Preset) ([]Preset, error) {
		return append(ps, Preset{ID: "mine", Title: "Mine", Lines: []string{"my.example"}}), nil
	}); err != nil {
		t.Fatal(err)
	}
	was, err := os.ReadFile(paths.UserPresets())
	if err != nil {
		t.Fatal(err)
	}
	// another name of the file: the service refuses to read such a one
	if err := os.Link(paths.UserPresets(), paths.UserPresets()+".other"); err != nil {
		t.Skip("no hard links here: ", err)
	}
	if len(Load()) != len(shipped) {
		t.Fatal("setup: the file is read all the same")
	}
	change := func(ps []Preset) ([]Preset, error) { return ps[:1], nil }
	if err := Update(change); err == nil {
		t.Error("a change was written over presets that could not be read")
	}
	if _, err := Restore(); err == nil {
		t.Error("a restore was written over presets that could not be read")
	}
	if now, _ := os.ReadFile(paths.UserPresets()); string(now) != string(was) {
		t.Error("the user's file changed")
	}
	// the other name gone, it is read and changed again
	if err := os.Remove(paths.UserPresets() + ".other"); err != nil {
		t.Fatal(err)
	}
	if err := Update(change); err != nil {
		t.Errorf("readable again: %v", err)
	}
}
