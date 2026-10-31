package presets

import (
	"slices"
	"strings"
)

// Stable category IDs; labels and ordering belong to the Go UI.
type Category struct{ ID, Title string }

var Categories = []Category{
	{"video", "Video hosting"}, {"ai", "AI"}, {"messengers", "Messengers"},
	{"other", "Other services"}, {"social", "Social networks"},
}

var shipped = []struct {
	id, title, category string
	files               []string
}{
	{"youtube", "YouTube", "video", []string{"youtube.txt"}},
	{"telegram-app", "Telegram", "messengers", []string{"telegram-domains.txt", "telegram-cidr.txt", "telegram-app.txt"}},
	{"whatsapp", "WhatsApp", "messengers", []string{"whatsapp-domains.txt", "whatsapp-cidr.txt", "whatsapp-app.txt"}},
	{"discord", "Discord", "messengers", []string{"discord.txt"}},
	{"openai", "ChatGPT / Codex / Sora", "ai", []string{"openai.txt"}},
	{"claude", "Claude", "ai", []string{"claude.txt"}},
	{"google-ai", "Google AI", "ai", []string{"google-ai.txt"}},
	{"grok", "Grok", "ai", []string{"grok.txt"}},
	{"meta-ai", "Meta AI", "ai", []string{"meta-ai.txt"}},
	{"copilot", "Microsoft Copilot / Designer", "ai", []string{"copilot.txt"}},
	{"ai-shared", "Shared AI sign-in", "ai", []string{"ai-shared.txt"}},
	{"facebook", "Facebook", "social", []string{"facebook.txt"}},
	{"instagram", "Instagram", "social", []string{"instagram.txt"}},
	{"twitter", "X / Twitter", "social", []string{"twitter.txt"}},
	{"github", "GitHub", "other", []string{"github.txt"}},
	{"reddit", "Reddit", "other", []string{"reddit.txt"}},
}

func ValidCategory(id string) bool {
	return slices.ContainsFunc(Categories, func(c Category) bool { return c.ID == id })
}

func CategoryOf(p Preset) string {
	if ValidCategory(p.Category) {
		return p.Category
	}
	for _, s := range shipped {
		if s.id == p.ID {
			return s.category
		}
	}
	switch p.ID {
	case "ai":
		return "ai"
	case "telegram":
		return "messengers"
	case "social":
		return "social"
	}
	return "other"
}

// Edited legacy groups keep their IDs and rules. Only retired IDs expand.
func Successors(id string) []string {
	switch id {
	case "telegram":
		return []string{"telegram-app", "whatsapp"}
	case "ai", "social":
		var ids []string
		for _, s := range shipped {
			if s.category == id {
				ids = append(ids, s.id)
			}
		}
		return ids
	}
	return nil
}

func ExpandSelection(ids []string, known map[string]bool) []string {
	out := []string{}
	for _, id := range ids {
		next := []string{id}
		if !known[id] {
			next = Successors(id)
		}
		for _, x := range next {
			if known[x] && !slices.Contains(out, x) {
				out = append(out, x)
			}
		}
	}
	return out
}

// Old files snapshot the whole catalog. Split unedited legacy groups,
// preserve user edits and deletions. No file is written during a read.
func migrate(ps []Preset) []Preset {
	out := []Preset{}
	seen := map[string]bool{}
	oldCatalog := false
	for _, p := range ps {
		seen[p.ID] = true
		for _, old := range legacy {
			if p.ID == old.id {
				oldCatalog = true
			}
		}
	}
	for _, p := range ps {
		ids := Successors(p.ID)
		if len(ids) == 0 {
			out = append(out, p)
			continue
		}
		stock := false
		for _, old := range legacy {
			if old.id != p.ID {
				continue
			}
			var lines []string
			for _, file := range old.files {
				b, _ := lists.ReadFile("lists/" + file)
				for _, l := range strings.Split(string(b), "\n") {
					if l = strings.TrimSpace(l); l != "" {
						lines = append(lines, l)
					}
				}
			}
			stock = p.Title == old.title && p.Note == old.note && slices.Equal(p.Lines, lines)
		}
		if !stock {
			p.Category = CategoryOf(p)
			out = append(out, p)
			continue
		}
		for _, id := range ids {
			if b, ok := Shipped(id); ok && !seen[id] {
				out = append(out, b)
				seen[id] = true
			}
		}
	}
	// These services did not exist in v2, so adding them switched off does
	// not resurrect a deleted preset. A deliberately empty catalog stays empty.
	if oldCatalog {
		for _, id := range []string{"github", "reddit"} {
			if p, ok := Shipped(id); ok && !seen[id] {
				out = append(out, p)
			}
		}
	}
	return out
}
