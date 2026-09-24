package session

import "testing"

// The candidates start at the session's port and stay in the dynamic range.
func TestCandidates(t *testing.T) {
	c := Candidates()
	if len(c) != 64 || c[0] != Port() {
		t.Fatalf("%d candidates, first %d, want 64 from %d", len(c), c[0], Port())
	}
	seen := map[int]bool{}
	for _, p := range c {
		if p < portBase || p >= portBase+portSpan || seen[p] {
			t.Fatalf("candidate %d out of range or repeated", p)
		}
		seen[p] = true
	}
}
