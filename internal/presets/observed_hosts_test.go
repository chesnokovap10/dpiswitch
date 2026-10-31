package presets

import (
	"strings"
	"testing"
)

// The six selected services and their shared sign-in endpoints remain routed.
func TestSelectedAIHosts(t *testing.T) {
	for _, c := range []struct{ preset, host string }{
		{"openai", "desktop.chat.openai.com"},
		{"openai", "setup.auth.openai.com"},
		{"openai", "cdn.openaimerge.com"},
		{"claude", "assets.claude.ai"},
		{"google-ai", "gemini.gstatic.com"},
		{"grok", "api.x.ai"},
		{"meta-ai", "meta.ai"},
		{"copilot", "copilot.cloud.microsoft"},
		{"ai-shared", "cdn.workos.com"},
		{"ai-shared", "challenges.cloudflare.com"},
	} {
		p, ok := Shipped(c.preset)
		if !ok {
			t.Fatal(c.preset)
		}
		covered := false
		for _, rule := range p.Lines {
			if rule == c.host {
				covered = true
			}
			if root, ok := strings.CutPrefix(rule, "+."); ok && (c.host == root || strings.HasSuffix(c.host, "."+root)) {
				covered = true
			}
		}
		if !covered {
			t.Errorf("%s misses %s", c.preset, c.host)
		}
	}
	p, _ := Shipped("openai")
	for _, rule := range p.Lines {
		if strings.Contains(rule, "sentry.io") {
			t.Fatalf("diagnostic endpoint still routed: %s", rule)
		}
	}
}
