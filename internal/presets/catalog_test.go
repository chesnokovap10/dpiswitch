package presets

import (
	"strings"
	"testing"
)

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

func TestAllEmbeddedListsUsed(t *testing.T) {
	used := map[string]bool{}
	for _, p := range shipped {
		for _, file := range p.files {
			used[file] = true
		}
	}
	entries, err := lists.ReadDir("lists")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !used[entry.Name()] {
			t.Errorf("unused embedded list: %s", entry.Name())
		}
	}
}
