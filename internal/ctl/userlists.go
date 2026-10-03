package ctl

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"strings"
	"sync"

	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
)

// The user edits the lists in paths.UserDir; the core reads the service's
// copies in the data directory, three to a list (see entries.go).
// SyncUserFiles brings the copies up to date and writes the presets the
// settings ask for.

// setAside: the body a user list's copies are written with when the
// settings set it aside, nil when they take it. The second tunnel not
// loaded, or switched off, routes nothing, its list included. (Tunnel only
// set the direct list aside up to 1.5: it is the way out past the tunnels
// in that mode now.)
func setAside(name string, s Settings) []byte {
	if name == paths.Awg2List && !s.Awg2Carries() {
		return awg2OffBody
	}
	return nil
}

var awg2OffBody = []byte("# second tunnel not loaded or switched off: set aside\n")

// observeAll: the catch-all file's content in a mode. NETWORK takes every
// connection and needs no address: MATCH is refused inside a rule-set.
func observeAll(mode string) []byte {
	if mode == ModeObserve {
		return []byte("# observe only: everything goes direct\nNETWORK,tcp\nNETWORK,udp\n")
	}
	return []byte("# empty\n")
}

// observeFiles: the catch-alls of observe only -- plain direct, and direct
// with the ClientHello cut. With the cut switched on everything goes the
// cut's way: a name not checked yet is cut at once rather than blocked
// until the detector gets to it, and the ones the cut harms go plain by
// the detector's direct list, which stands above.
func observeFiles(s Settings) (plain, cut []byte) {
	empty := []byte("# empty\n")
	all := observeAll(s.Mode())
	if s.Mode() == ModeObserve && s.SplitHello {
		return empty, all
	}
	return all, empty
}

// wantCopies: the service's copies of a user list, by file name, as the
// user's file and the mode make them; false when the user has no such list
// -- the copies are left as they are then.
func wantCopies(name string, s Settings) (map[string][]byte, bool, error) {
	if b := setAside(name, s); b != nil {
		return map[string][]byte{name: b, paths.IPList(name): b, paths.AppList(name): b}, true, nil
	}
	u, err := paths.ReadUserFile(paths.User(name), UserListMax)
	have := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, false, err
	}
	if name == paths.DirectList {
		// the programs bypassing the tunnel had a list of their own: it is
		// taken in until the direct list is next saved, which removes it
		a, err := paths.ReadUserFile(paths.User(paths.AppsList), UserListMax)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, false, err
		}
		if err == nil {
			u, have = append(append(u, '\n'), a...), true
		}
	}
	if !have {
		return nil, false, nil
	}
	return splitList(u).bodies(name), true, nil
}

// Synced: whether the service's copies of a user list are what the user's
// file says -- the UI waits for it before it moves open connections.
func Synced(name string) bool {
	want, ok, err := wantCopies(name, LoadSettings(paths.Settings()))
	if !ok || err != nil {
		return false
	}
	for f, b := range want {
		if d, err := os.ReadFile(paths.Data(f)); err != nil || !bytes.Equal(d, b) {
			return false
		}
	}
	return true
}

// UserListMax: the most of a user's list the service reads; the UI writes
// none larger
const UserListMax = 4 << 20

// providerOf: the rule-provider a list file is -- its name without .txt
func providerOf(name string) string { return strings.TrimSuffix(name, ".txt") }

// ListProviders: the core's rule-providers of a user list
func ListProviders(name string) []string {
	return []string{providerOf(name), providerOf(paths.IPList(name)), providerOf(paths.AppList(name))}
}

// SyncUserFiles copies what changed and returns the rule-providers whose
// file it wrote. A user list that is not there leaves the copies as they
// are. The auto-switch mode is followed here too: observe only writes the
// catch-all; and the second tunnel not loaded or switched off sets its
// list and the presets aside.
func SyncUserFiles() []string {
	// the service syncs before every core start, the controller every
	// second: one at a time
	syncMu.Lock()
	defer syncMu.Unlock()
	set := LoadSettings(paths.Settings())
	var changed []string
	for _, name := range paths.UserLists {
		want, ok, err := wantCopies(name, set)
		if err != nil {
			logOnce(name, "list %s not taken: %v", name, err)
			continue
		}
		logOnce(name, "")
		if !ok {
			continue
		}
		for _, f := range []string{name, paths.IPList(name), paths.AppList(name)} {
			if replaced(paths.Data(f), want[f], "list "+f) {
				changed = append(changed, providerOf(f))
			}
		}
	}
	plain, cut := observeFiles(set)
	if replaced(paths.ObserveAll(), plain, "observe only list") {
		changed = append(changed, ObserveProvider)
	}
	if replaced(paths.ObserveSplit(), cut, "observe only list, cut") {
		changed = append(changed, ObserveSplitProvider)
	}
	if replaced(paths.Presets(), wantPresets(set), "presets") {
		changed = append(changed, PresetsProvider)
	}
	return changed
}

// wantPresets: the core's presets file as the settings make it -- the ones
// switched on, none while the second tunnel is not loaded or switched off
func wantPresets(s Settings) []byte {
	if !s.Awg2Carries() {
		return awg2OffBody
	}
	return presetsBody(presets.Load(), s.Awg2Presets)
}

// Awg2Synced: whether the core's files of the second tunnel -- its list
// and the presets -- are as the settings now ask; the UI waits for it
// before it moves open connections.
func Awg2Synced() bool {
	set := LoadSettings(paths.Settings())
	if d, err := os.ReadFile(paths.Presets()); err != nil || !bytes.Equal(d, wantPresets(set)) {
		return false
	}
	// no list of the user's: the copies are left as they are, nothing to wait for
	if _, ok, err := wantCopies(paths.Awg2List, set); err == nil && !ok {
		return true
	}
	return Synced(paths.Awg2List)
}

// ObserveProvider: the rule-provider of paths.ObserveAll
const ObserveProvider = "observe-all"

// ObserveSplitProvider: the rule-provider of paths.ObserveSplit
const ObserveSplitProvider = "observe-split"

// replaced: whether the file had to be written to hold want; syncMu held
func replaced(path string, want []byte, what string) bool {
	if d, err := os.ReadFile(path); err == nil && bytes.Equal(d, want) {
		return false
	}
	if err := paths.ReplaceFile(path, want); err != nil {
		log.Printf("%s not written: %v", what, err)
		return false
	}
	return true
}

var syncMu sync.Mutex

// logOnce: a list that cannot be taken would be said every second; syncMu held
var lastSaid = map[string]string{}

func logOnce(key, format string, args ...any) {
	if format == "" {
		delete(lastSaid, key)
		return
	}
	msg := fmt.Sprintf(format, args...)
	if lastSaid[key] != msg {
		lastSaid[key] = msg
		log.Print(msg)
	}
}

// syncUserFiles: SyncUserFiles with the core told; listMu held
func syncUserFiles(a *api) {
	for _, p := range SyncUserFiles() {
		if err := a.reloadProvider(p); err != nil {
			reloadPending[p] = true
			continue
		}
		delete(reloadPending, p)
	}
}
