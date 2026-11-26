package presets

import (
	"slices"
)

// Stable category IDs; labels and ordering belong to the Go UI.
type Category struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Custom bool   `json:"-"`
}

var builtinCategories = []Category{
	{ID: "video", Title: "Video hosting"}, {ID: "ai", Title: "AI"}, {ID: "messengers", Title: "Messengers"},
	{ID: "other", Title: "Other services"}, {ID: "social", Title: "Social networks"},
}

func BuiltinCategories() []Category { return slices.Clone(builtinCategories) }

func BuiltinCategory(id string) bool {
	return slices.ContainsFunc(builtinCategories, func(c Category) bool { return c.ID == id })
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
	{"grok", "Grok / Cursor", "ai", []string{"grok.txt"}},
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
	return slices.ContainsFunc(Categories(), func(c Category) bool { return c.ID == id })
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
	return "other"
}
