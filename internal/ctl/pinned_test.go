package ctl

import (
	"os"
	"path/filepath"
	"testing"
)

// Both list formats the config uses, read the way the core matches them.
func TestPinnedLists(t *testing.T) {
	dir := t.TempDir()
	preset := filepath.Join(dir, "preset-ai.txt")
	force := filepath.Join(dir, "force-tunnel.txt")
	os.WriteFile(preset, []byte("# preset ai\nDOMAIN-SUFFIX,Claude.ai\nIP-CIDR,149.154.160.0/20,no-resolve\nDOMAIN,exact.example\n"), 0o644)
	os.WriteFile(force, []byte("# always tunnel\n+.whole.example\n.subs.example\n*.one.example\nplain.example\n"), 0o644)
	n := loadPinned([]string{preset, force, filepath.Join(dir, "missing.txt")})

	for dom, want := range map[string]bool{
		"claude.ai":         true, // DOMAIN-SUFFIX covers the name itself
		"api.claude.ai":     true,
		"notclaude.ai":      false,
		"exact.example":     true,
		"www.exact.example": false,
		"whole.example":     true,
		"a.b.whole.example": true,
		"subs.example":      false, // ".x" is subdomains only
		"a.subs.example":    true,
		"a.one.example":     true,
		"plain.example":     true,
		"www.plain.example": false,
		"149.154.160.1":     false,
		"unrelated.example": false,
	} {
		if got := n.has(dom); got != want {
			t.Errorf("%s: pinned=%v, want %v", dom, got, want)
		}
	}
}
