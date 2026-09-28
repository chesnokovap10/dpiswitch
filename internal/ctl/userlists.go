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

// setAside: tunnel only sends everything through the tunnels, what the
// direct list names included -- its copies are written empty.
func setAside(name, mode string) bool { return mode == ModeTunnel && name == paths.DirectList }

var setAsideBody = []byte("# tunnel only: set aside, everything goes through the tunnels\n")

// observeAll: the catch-all file's content in a mode. NETWORK takes every
// connection and needs no address: MATCH is refused inside a rule-set.
func observeAll(mode string) []byte {
	if mode == ModeObserve {
		return []byte("# observe only: everything goes direct\nNETWORK,tcp\nNETWORK,udp\n")
	}
	return []byte("# empty\n")
}

// wantCopies: the service's copies of a user list, by file name, as the
// user's file and the mode make them; false when the user has no such list
// -- the copies are left as they are then.
func wantCopies(name, mode string) (map[string][]byte, bool, error) {
	if setAside(name, mode) {
		return map[string][]byte{name: setAsideBody, paths.IPList(name): setAsideBody,
			paths.AppList(name): setAsideBody}, true, nil
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
	want, ok, err := wantCopies(name, LoadSettings(paths.Settings()).Mode())
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
// are. The auto-switch mode is followed here too: tunnel only sets the
// direct list aside, observe only writes the catch-all.
func SyncUserFiles() []string {
	// the service syncs before every core start, the controller every
	// second: one at a time
	syncMu.Lock()
	defer syncMu.Unlock()
	set := LoadSettings(paths.Settings())
	mode := set.Mode()
	var changed []string
	for _, name := range paths.UserLists {
		want, ok, err := wantCopies(name, mode)
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
	if replaced(paths.ObserveAll(), observeAll(mode), "observe only list") {
		changed = append(changed, ObserveProvider)
	}
	if replaced(paths.Presets(), presetsBody(presets.Load(), set.Awg2Presets), "presets") {
		changed = append(changed, PresetsProvider)
	}
	return changed
}

// ObserveProvider: the rule-provider of paths.ObserveAll
const ObserveProvider = "observe-all"

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
