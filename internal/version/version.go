// Program version. A variable rather than a constant so a build can
// override it with -ldflags "-X dpiswitch/internal/version.Version=...".
package version

import "runtime/debug"

var Version = "1.12.0"

// Commit: the commit the program was built from, its first seven digits, a
// "+" after them when the tree had changes not committed. go build stamps it
// from git by itself; a build with none -- go run, no git -- has "".
var Commit = commit(debug.ReadBuildInfo)

func commit(read func() (*debug.BuildInfo, bool)) string {
	bi, ok := read()
	if !ok {
		return ""
	}
	var rev string
	modified := false
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if len(rev) > 7 {
		rev = rev[:7]
	}
	if rev != "" && modified {
		rev += "+"
	}
	return rev
}

// Full: the version with its commit, "1.12.0 #15ff252" -- a build of the
// same version told from another
func Full() string {
	if Commit == "" {
		return Version
	}
	return Version + " #" + Commit
}
