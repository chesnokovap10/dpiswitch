package ctl

import (
	"os"
	"strings"
	"testing"

	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
)

// A preset's lines become core rules, a name as the lists take it: the name
// alone, "+." the domain with everything under it, "." everything under
// it, "*." one level under it; an address only by address, a program by
// its name or its path. Comments, lines of no kind and repeats are left
// out.
func TestPresetRules(t *testing.T) {
	p := presets.Preset{ID: "x", Lines: []string{
		"# a comment", "Example.com", "+.example.org", "*.example.net", ".example.biz", "https://sub.example.com/path",
		"1.2.3.4", "10.0.0.0/8", "2001:db8::/32", "telegram.exe", `C:\Apps\x.exe`, "bad host", "example.com"}}
	want := []string{
		"DOMAIN,example.com", "DOMAIN-SUFFIX,example.org", `DOMAIN-REGEX,^[^.]+\.example\.net$`,
		`DOMAIN-REGEX,^.+\.example\.biz$`, "DOMAIN,sub.example.com", "IP-CIDR,1.2.3.4/32,no-resolve", "IP-CIDR,10.0.0.0/8,no-resolve",
		"IP-CIDR6,2001:db8::/32,no-resolve", "PROCESS-NAME,telegram.exe", `PROCESS-PATH,C:\Apps\x.exe`}
	if got := PresetRules(p); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// every line the program ships is one the presets take
	for _, p := range presets.Builtin() {
		for _, l := range p.Lines {
			if strings.HasPrefix(l, "#") {
				continue
			}
			if _, _, err := ParseEntry(l); err != nil {
				t.Errorf("preset %s: %v", p.ID, err)
			}
		}
		if len(PresetRules(p)) == 0 {
			t.Errorf("preset %s: no rules", p.ID)
		}
	}
	// read back as the lists write them, and matched as a list's lines
	for _, r := range want[:5] {
		if PresetNameLine(r) == "" {
			t.Errorf("%s: not read back", r)
		}
	}
	for line, hosts := range map[string]map[string]bool{
		"example.com":   {"example.com": true, "a.example.com": false},
		"+.example.org": {"example.org": true, "a.b.example.org": true},
		"*.example.net": {"a.example.net": true, "example.net": false, "a.b.example.net": false},
		".example.biz":  {"a.b.example.biz": true, "example.biz": false},
	} {
		back := PresetNameLine(PresetRules(presets.Preset{Lines: []string{line}})[0])
		if back != line {
			t.Errorf("%s: read back as %s", line, back)
		}
		for h, want := range hosts {
			if got := MatchDomainRule(back, h); got != want {
				t.Errorf("%s on %s: %v", line, h, got)
			}
		}
	}
}

// The presets switched on reach the core in one file, a section to each:
// the UI finds its own there, whatever the others do meanwhile. A preset
// deleted is switched off with it.
func TestPresetsFile(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	// a second tunnel loaded: without one no preset is written
	if err := os.WriteFile(paths.SourceConf2(), []byte("[Interface]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := presets.Preset{ID: "a", Title: "A", Lines: []string{"a.example"}}
	b := presets.Preset{ID: "b", Title: "B", Lines: []string{"b.example", "10.0.0.0/8"}}
	if err := os.WriteFile(paths.Presets(), presetsBody([]presets.Preset{a, b}, []string{"b"}), 0o644); err != nil {
		t.Fatal(err)
	}
	if !PresetWritten(a, false) || PresetWritten(a, true) || !PresetWritten(b, true) || PresetWritten(b, false) {
		t.Fatal("a preset's section not found as written")
	}
	// an edit the service has not taken yet
	b2 := b
	b2.Lines = []string{"b.example"}
	if PresetWritten(b2, true) {
		t.Fatal("the old rules taken for the new ones")
	}

	// the service writes the user's presets the settings ask for
	if err := presets.Update(func([]presets.Preset) ([]presets.Preset, error) {
		return []presets.Preset{a, b2}, nil
	}); err != nil {
		t.Fatal(err)
	}
	set := DefaultSettings()
	set.Awg2Presets = []string{"a", "b"}
	if err := SaveSettings(paths.Settings(), set); err != nil {
		t.Fatal(err)
	}
	if got := SyncUserFiles(); !contains(got, PresetsProvider) {
		t.Fatalf("presets not written: %v", got)
	}
	if !PresetWritten(a, true) || !PresetWritten(b2, true) {
		t.Fatal("the presets switched on are not in the core's file")
	}
	if got := SyncUserFiles(); contains(got, PresetsProvider) {
		t.Fatal("written again with nothing changed")
	}

	if err := presets.Update(func(ps []presets.Preset) ([]presets.Preset, error) {
		return ps[1:], nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := LoadSettings(paths.Settings()).Awg2Presets; len(got) != 1 || got[0] != "b" {
		t.Fatalf("a deleted preset still on: %v", got)
	}
	SyncUserFiles()
	if !PresetWritten(a, false) || !PresetWritten(b2, true) {
		t.Fatal("a deleted preset still in the core's file")
	}
	// the settings refuse a preset that is not there
	set.Awg2Presets = []string{"a"}
	if SaveSettings(paths.Settings(), set) == nil {
		t.Fatal("an unknown preset was saved")
	}
}
