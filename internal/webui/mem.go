package webui

import (
	"maps"
	"os"
	"slices"
	"sync"
	"time"

	"dpiswitch/internal/awgconf"
	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
)

// What the pages are drawn from is kept in memory: the settings, the
// tunnels' .conf files, the user's lists. One save of a setting read the
// settings file five times over -- the status, the form, the second
// tunnel's check -- and parsed the .conf twice. Now each is read once and
// again only when its file changes: a request looks at the files' size and
// time, not their content.

// fileKey: what a file is known by -- there or not, its size, its time
type fileKey struct {
	ok   bool
	size int64
	mod  int64
}

func keyOf(path string) fileKey {
	fi, err := os.Lstat(path)
	if err != nil {
		return fileKey{}
	}
	return fileKey{true, fi.Size(), fi.ModTime().UnixNano()}
}

// settle: a file changed this close to its reading may change again within
// the clock's tick -- Windows stamps files every 15 ms -- at the same size,
// and look the same. Such a file is read again until it is older than this
// (git's "racily clean" index entries are the same case).
const settle = 50 * time.Millisecond

// memo: one value read from a few files, kept until one of them changes
type memo[T any] struct {
	mu   sync.Mutex
	keys []fileKey
	at   time.Time // when it was read
	have bool
	val  T
}

func (m *memo[T]) get(load func() T, files ...string) T {
	keys := make([]fileKey, len(files))
	for i, f := range files {
		keys[i] = keyOf(f)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.have && slices.Equal(m.keys, keys) && settled(keys, m.at) {
		return m.val
	}
	m.at = time.Now()
	m.val, m.keys, m.have = load(), keys, true
	return m.val
}

func settled(keys []fileKey, at time.Time) bool {
	edge := at.Add(-settle).UnixNano()
	for _, k := range keys {
		if k.ok && k.mod >= edge {
			return false
		}
	}
	return true
}

var settingsMemo memo[ctl.Settings]

// loadSettings: ctl.LoadSettings from memory. Its slices and map are the
// caller's own copies: a caller changing them changes nothing kept.
func loadSettings() ctl.Settings {
	p := paths.Settings()
	// the second tunnel's .conf says whether an old file had it on (see
	// ctl.oldSecond)
	s := settingsMemo.get(func() ctl.Settings { return ctl.LoadSettings(p) }, p, paths.SourceConf2())
	s.Awg2Presets = slices.Clone(s.Awg2Presets)
	s.DirectDNS = slices.Clone(s.DirectDNS)
	s.TunnelDNS = slices.Clone(s.TunnelDNS)
	s.TunnelDNS2 = slices.Clone(s.TunnelDNS2)
	s.Awg2On = maps.Clone(s.Awg2On)
	return s
}

// confs: the two tunnels' .conf files, parsed. They are only read: callers
// must not change them.
type confs struct {
	First     *awgconf.Conf
	FirstErr  error
	Second    *awgconf.Conf // attached: present, usable and switched on
	SecondErr error
}

var confsMemo memo[confs]

func loadConfs() confs {
	return confsMemo.get(func() confs {
		var c confs
		c.First, c.FirstErr = awgconf.ParseFile(paths.SourceConf())
		// whether it is attached depends on the settings' switch too
		c.Second, c.SecondErr = awgconf.Second(c.First)
		return c
	}, paths.SourceConf(), paths.SourceConf2(), paths.Settings())
}

// the user's lists, by their file: the data directory differs from test to
// test
var entriesMemo sync.Map // path -> *memo[[]string]

// readEntries: a user list as the box shows it, from memory (see
// readEntriesFile). The slice is the caller's own.
func readEntries(name string) []string {
	p := paths.User(name)
	files := []string{p}
	if name == paths.DirectList {
		files = append(files, paths.User(paths.AppsList))
	}
	m, _ := entriesMemo.LoadOrStore(p, &memo[[]string]{})
	return slices.Clone(m.(*memo[[]string]).get(func() []string { return readEntriesFile(name) }, files...))
}
