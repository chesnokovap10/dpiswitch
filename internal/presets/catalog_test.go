package presets

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestLegacyCatalogMigration(t *testing.T) {
	var old []Preset
	for _, s := range legacy {
		p := Preset{ID: s.id, Title: s.title, Note: s.note}
		for _, f := range s.files {
			b, err := lists.ReadFile("lists/" + f)
			if err != nil {
				t.Fatal(err)
			}
			for _, l := range strings.Split(string(b), "\n") {
				if l = strings.TrimSpace(l); l != "" {
					p.Lines = append(p.Lines, l)
				}
			}
		}
		old = append(old, p)
	}
	b, _ := json.Marshal(file{Version: 2, Presets: old})
	got, err := decode(b)
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, p := range got {
		known[p.ID] = true
	}
	if known["ai"] || known["telegram"] || known["social"] {
		t.Fatal("legacy groups did not split")
	}
	for _, id := range []string{"claude", "openai", "telegram-app", "whatsapp", "facebook", "instagram", "twitter", "github", "reddit"} {
		if !known[id] {
			t.Errorf("missing successor %s", id)
		}
	}
	on := ExpandSelection([]string{"ai", "telegram", "social", "youtube", "ai"}, known)
	if len(on) != len(got)-3 {
		t.Fatalf("selection lost or duplicated: %v", on)
	} // Discord, GitHub and Reddit were off.

	// A user's rules, description and title stay intact instead of becoming
	// a stock catalog. A deleted group is not resurrected by migration.
	old[3].Lines = []string{"+.my-ai.example", "MyAI.exe"}
	old = slices.DeleteFunc(old, func(p Preset) bool { return p.ID == "social" })
	b, _ = json.Marshal(file{Version: 2, Presets: old})
	got, err = decode(b)
	if err != nil {
		t.Fatal(err)
	}
	known = map[string]bool{}
	for _, p := range got {
		known[p.ID] = true
		if p.ID == "ai" && (!slices.Equal(p.Lines, old[3].Lines) || p.Category != "ai") {
			t.Fatalf("user edits changed: %+v", p)
		}
	}
	if !known["ai"] || known["facebook"] || known["instagram"] {
		t.Fatal("user edits/deletions lost")
	}
	if ids := ExpandSelection([]string{"ai"}, known); !slices.Equal(ids, []string{"ai"}) {
		t.Fatalf("edited group expanded: %v", ids)
	}
}

func TestSelectedAIPresets(t *testing.T) {
	want := map[string]bool{"openai": true, "claude": true, "google-ai": true, "grok": true, "meta-ai": true, "copilot": true, "ai-shared": true}
	for _, p := range Builtin() {
		if p.Category != "ai" {
			continue
		}
		if !want[p.ID] {
			t.Errorf("unexpected AI preset %s", p.ID)
		}
		delete(want, p.ID)
		for _, line := range p.Lines {
			if p.ID == "ai-shared" && strings.HasPrefix(line, "+.") {
				t.Errorf("shared dependency has broad mask: %s", line)
			}
		}
	}
	if len(want) != 0 {
		t.Errorf("missing AI presets: %v", want)
	}
}
