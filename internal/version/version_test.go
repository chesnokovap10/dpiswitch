package version

import (
	"runtime/debug"
	"testing"
)

// The commit as go build stamps it: seven digits, "+" for changes not
// committed, nothing for a build with no git.
func TestCommit(t *testing.T) {
	stamp := func(kv ...string) func() (*debug.BuildInfo, bool) {
		bi := &debug.BuildInfo{}
		for i := 0; i+1 < len(kv); i += 2 {
			bi.Settings = append(bi.Settings, debug.BuildSetting{Key: kv[i], Value: kv[i+1]})
		}
		return func() (*debug.BuildInfo, bool) { return bi, true }
	}
	for _, tc := range []struct {
		read func() (*debug.BuildInfo, bool)
		want string
	}{
		{stamp("vcs.revision", "15ff2526c3a1e0d4", "vcs.modified", "false"), "15ff252"},
		{stamp("vcs.revision", "15ff2526c3a1e0d4", "vcs.modified", "true"), "15ff252+"},
		{stamp(), ""},
		{func() (*debug.BuildInfo, bool) { return nil, false }, ""},
	} {
		if got := commit(tc.read); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
}
