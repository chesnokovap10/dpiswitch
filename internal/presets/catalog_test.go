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

func TestBroadMasksCoverLegacyAIAndDesktopTraffic(t *testing.T) {
	all := Builtin()
	covered := func(host string) bool {
		for _, p := range all {
			for _, l := range p.Lines {
				if base, ok := strings.CutPrefix(l, "+."); ok && (host == base || strings.HasSuffix(host, "."+base)) {
					return true
				}
			}
		}
		return false
	}
	b, _ := lists.ReadFile("lists/ai.txt")
	for _, l := range strings.Fields(string(b)) {
		if host, ok := strings.CutPrefix(l, "+."); ok && !covered(host) {
			t.Errorf("old AI host no longer covered: %s", host)
		}
	}
	for _, host := range []string{"api.oaistatsig.com", "downloads.claude.ai", "bridge.claudeusercontent.com", "new.frame.claudeusercontent.com", "codex-cloud-environments.chatgpt.com", "sdmntprwestus.oaiusercontent.com", "gemini.gstatic.com"} {
		if !covered(host) {
			t.Errorf("logged desktop host not covered: %s", host)
		}
	}
	for _, p := range all {
		if !ValidCategory(p.Category) {
			t.Errorf("uncategorized %s", p.ID)
		}
		for _, a := range p.Lines {
			for _, b := range p.Lines {
				if a != b && strings.HasPrefix(a, "+.") && strings.HasPrefix(b, "+.") && strings.HasSuffix(a[2:], "."+b[2:]) {
					t.Errorf("redundant %s under %s in %s", a, b, p.ID)
				}
			}
		}
	}
}
