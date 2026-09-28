package ctl

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"

	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
)

// The user edits the lists in paths.UserDir; the core reads the service's
// copies in the data directory. SyncUserFiles brings the copies up to date
// and writes the presets the settings ask for. What the core gets is only
// what it would take from the UI: a line that is neither a comment nor a
// rule of the list's kind is left out, so a hand-edited file cannot slip
// other rules in, nor break the core's parse of it.

// ruleRe: what each list may hold, per line
var ruleRe = map[string]*regexp.Regexp{
	paths.DirectList: domainRule,
	paths.TunnelList: domainRule,
	paths.Awg2List:   domainRule,
	paths.AppsList:   regexp.MustCompile(`(?i)^PROCESS-(NAME|PATH),[^,]+\.exe$`),
}

// domainRule: a name, "+." / "." / "*." before one allowed
var domainRule = regexp.MustCompile(`^(\+\.|\.|\*\.)?[a-z0-9_]([a-z0-9_.-]*[a-z0-9])?$`)

// CleanList: the service's copy of a user list with content b
func CleanList(name string, b []byte) []byte {
	re := ruleRe[name]
	var out bytes.Buffer
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "":
		case strings.HasPrefix(l, "#"), re != nil && re.MatchString(l):
			out.WriteString(l + "\n")
		}
	}
	if out.Len() == 0 {
		return []byte("# empty\n")
	}
	return out.Bytes()
}

// setAside: tunnel only sends everything through the tunnels, what the
// direct lists name included -- their copies are written empty.
func setAside(name, mode string) bool {
	return mode == ModeTunnel && (name == paths.DirectList || name == paths.AppsList)
}

var setAsideBody = []byte("# tunnel only: set aside, everything goes through the tunnels\n")

// observeAll: the catch-all file's content in a mode. NETWORK takes every
// connection and needs no address: MATCH is refused inside a rule-set.
func observeAll(mode string) []byte {
	if mode == ModeObserve {
		return []byte("# observe only: everything goes direct\nNETWORK,tcp\nNETWORK,udp\n")
	}
	return []byte("# empty\n")
}

// Synced: whether the service's copy of a user list is what the user's
// file says -- the UI waits for it before it moves open connections.
func Synced(name string) bool {
	d, err := os.ReadFile(paths.Data(name))
	if err != nil {
		return false
	}
	if setAside(name, LoadSettings(paths.Settings()).Mode()) {
		return bytes.Equal(d, setAsideBody)
	}
	u, err := paths.ReadUserFile(paths.User(name), userListMax)
	return err == nil && bytes.Equal(d, CleanList(name, u))
}

const userListMax = 4 << 20

// providerOf: the rule-provider a list file is -- its name without .txt
func providerOf(name string) string { return strings.TrimSuffix(name, ".txt") }

// SyncUserFiles copies what changed and returns the rule-providers whose
// file it wrote. A user list that is not there leaves the copy as it is.
// The auto-switch mode is followed here too: tunnel only sets the direct
// lists aside, observe only writes the catch-all.
func SyncUserFiles() []string {
	// the service syncs before every core start, the controller every
	// second: one at a time
	syncMu.Lock()
	defer syncMu.Unlock()
	set := LoadSettings(paths.Settings())
	mode := set.Mode()
	var changed []string
	for _, name := range paths.UserLists {
		want := setAsideBody
		if !setAside(name, mode) {
			u, err := paths.ReadUserFile(paths.User(name), userListMax)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				logOnce(name, "list %s not taken: %v", name, err)
				continue
			}
			logOnce(name, "")
			want = CleanList(name, u)
		}
		if replaced(paths.Data(name), want, "list "+name) {
			changed = append(changed, providerOf(name))
		}
	}
	if replaced(paths.ObserveAll(), observeAll(mode), "observe only list") {
		changed = append(changed, ObserveProvider)
	}
	ids, err := presets.Write(set.Awg2Presets)
	if err != nil {
		log.Printf("presets not written: %v", err)
	}
	for _, id := range ids {
		changed = append(changed, "preset-"+id)
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
