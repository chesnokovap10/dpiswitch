// Second-tunnel presets: sets of services that always go through awg2,
// bypassing the detector.
//
// The program ships a few, taken from server-side setups solving the same
// task:
//   - AI: an nginx SNI allow-list plus the Google AI zones;
//   - Telegram and WhatsApp: the ranges from core.telegram.org/resources/cidr.txt
//     and Meta's (WhatsApp's calls go by address), plus domains -- one
//     preset under Telegram's old ID, so one switched on stays on;
//   - Discord: domains, its voice servers' network and the desktop app;
//   - YouTube: domains (the server relays all of Google via goog.json;
//     the client only needs YouTube).
//
// The user edits them, deletes them and adds their own on the second
// tunnel's page. Until the first such change the shipped ones are used; from
// then on the user's file holds the whole set, what is left of the shipped
// ones included -- until the user puts the shipped ones back (see Restore).
// The service turns the ones switched on into core rules, all in one file
// (see ctl.SyncUserFiles): a preset added or deleted needs neither a
// restart nor a config.yaml change.
package presets

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"

	"dpiswitch/internal/paths"
)

//go:embed lists/*.txt
var lists embed.FS

// Preset: a named set of lines as the user's lists take them -- sites,
// addresses and programs -- with the # comments kept.
type Preset struct {
	ID    string   `json:"id"`
	Title string   `json:"title"`
	Note  string   `json:"note,omitempty"`
	Lines []string `json:"lines"`
}

// shipped: the presets the program comes with, their lines in lists/
var shipped = []struct {
	id, title, note string
	files           []string
}{
	{"youtube", "YouTube", "site, video, thumbnails, apps", []string{"youtube.txt"}},
	{"telegram", "Telegram, WhatsApp", "their domains and networks -- the apps and calls connect by IP",
		[]string{"telegram-domains.txt", "telegram-cidr.txt", "whatsapp-domains.txt", "whatsapp-cidr.txt"}},
	{"discord", "Discord", "site, apps, voice and video",
		[]string{"discord.txt"}},
	{"ai", "AI services", "ChatGPT, Claude, Gemini, Grok, Copilot, DeepL and more",
		[]string{"ai-sni.txt", "ai-google.txt"}},
	{"social", "Instagram, Facebook, X", "their media CDNs too -- without those the page loads but photos and video do not",
		[]string{"social-meta.txt", "social-x.txt"}},
}

// builtin: the shipped presets, read once -- Load gives them every second
// while the user has changed none
var builtin = sync.OnceValue(func() []Preset {
	out := make([]Preset, 0, len(shipped))
	for _, s := range shipped {
		p := Preset{ID: s.id, Title: s.title, Note: s.note, Lines: []string{}}
		for _, f := range s.files {
			b, err := lists.ReadFile("lists/" + f)
			if err != nil {
				continue
			}
			for _, l := range strings.Split(string(b), "\n") {
				if l = strings.TrimSpace(l); l != "" {
					p.Lines = append(p.Lines, l)
				}
			}
		}
		out = append(out, p)
	}
	return out
})

// Builtin: the presets as the program ships them
func Builtin() []Preset { return clone(builtin()) }

// Shipped: the preset the program ships under id, as it ships it
func Shipped(id string) (Preset, bool) {
	for _, p := range builtin() {
		if p.ID == id {
			return clone([]Preset{p})[0], true
		}
	}
	return Preset{}, false
}

// Restorable: whether Restore would change ps -- a shipped preset is
// deleted, or is not as the program ships it: edited, or shipped anew by a
// later version
func Restorable(ps []Preset) bool {
	have := map[string]Preset{}
	for _, p := range ps {
		have[p.ID] = p
	}
	for _, b := range builtin() {
		p, ok := have[b.ID]
		if !ok || p.Title != b.Title || p.Note != b.Note || !slices.Equal(p.Lines, b.Lines) {
			return true
		}
	}
	return false
}

// clone: callers edit what they get; the shipped set is shared
func clone(ps []Preset) []Preset {
	out := make([]Preset, len(ps))
	for i, p := range ps {
		p.Lines = append([]string{}, p.Lines...)
		out[i] = p
	}
	return out
}

// fileMax: the most of the user's file read
const fileMax = 4 << 20

// Load: the presets as the user left them; the shipped ones while the user
// has changed none. A file that cannot be read or makes no sense gives the
// shipped ones too: the service must not stop over a hand edit. A preset
// with no usable ID, or with one a preset before it already has, is left
// out.
func Load() []Preset {
	ps, err := read()
	if err != nil {
		return Builtin()
	}
	return ps
}

// read: Load, and the error when the user's file is there and could not be
// read -- held, refused for what it is. Load gives the shipped presets then;
// a change made to those and written (see Update) put them in the place of
// every preset the user had.
func read() ([]Preset, error) {
	// the user's file, read by the service as SYSTEM: not through a link
	b, err := paths.ReadUserFile(paths.UserPresets(), fileMax)
	if errors.Is(err, fs.ErrNotExist) {
		return Builtin(), nil
	}
	if err != nil {
		return nil, err
	}
	ps, err := decode(b)
	if err != nil {
		return Builtin(), nil
	}
	out := []Preset{}
	seen := map[string]bool{}
	for _, p := range ps {
		if !ValidID(p.ID) || seen[p.ID] {
			continue
		}
		seen[p.ID] = true
		if p.Lines == nil {
			p.Lines = []string{}
		}
		out = append(out, p)
	}
	return out, nil
}

// errNotRead: the user's presets could not be read: none is written over them
var errNotRead = errors.New("The presets could not be read: nothing saved, try again")

// fileVersion: the file's format. Up to 1.6.1 it was the bare list of
// presets, where a name took everything under it; since, a name is what it
// is in the lists -- "example.com" that name alone, "+.example.com" the
// domain -- and the file says so.
const fileVersion = 2

// file: the user's file as it is written
type file struct {
	Version int      `json:"version"`
	Presets []Preset `json:"presets"`
}

// decode reads the user's file, one from before a version included: its
// names are read as they meant, each with everything under it.
func decode(b []byte) ([]Preset, error) {
	var f file
	if err := json.Unmarshal(b, &f); err == nil && f.Version > 0 {
		return f.Presets, nil
	}
	var ps []Preset
	if err := json.Unmarshal(b, &ps); err != nil {
		return nil, err
	}
	for i := range ps {
		for j, l := range ps[i].Lines {
			ps[i].Lines[j] = wholeDomain(l)
		}
	}
	return ps, nil
}

// oldName: a name as the lists write it, with the prefix it may carry --
// not an address, not a program
var oldName = regexp.MustCompile(`^(\+\.|\.|\*\.)?[a-z0-9_]([a-z0-9_.-]*[a-z0-9])?$`)

// wholeDomain: a line of a preset from before, as the lists write what it
// meant -- a name with everything under it: "+.example.com". Addresses,
// programs and comments stay as they are.
func wholeDomain(l string) string {
	t := strings.TrimSpace(l)
	if t == "" || strings.HasPrefix(t, "#") || !oldName.MatchString(t) ||
		strings.Trim(t, "0123456789.") == "" || strings.HasSuffix(t, ".exe") {
		return l
	}
	return "+." + strings.TrimLeft(t, "+.*")
}

// Known: the IDs of the presets there are
func Known() map[string]bool {
	ids := map[string]bool{}
	for _, p := range Load() {
		ids[p.ID] = true
	}
	return ids
}

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)

// ValidID: an ID the settings and the core's file can carry as it is
func ValidID(id string) bool { return idRe.MatchString(id) }

// NewID: an ID none of ps has, for a preset the user adds
func NewID(ps []Preset) string {
	have := map[string]bool{}
	for _, p := range ps {
		have[p.ID] = true
	}
	for {
		var b [4]byte
		rand.Read(b[:])
		if id := "u" + hex.EncodeToString(b[:]); !have[id] {
			return id
		}
	}
}

// ErrTooLarge: the presets would not fit in what Load reads
var ErrTooLarge = errors.New("The presets are too large: 4 MB at most, all of them together")

// mu makes a change -- read the file, edit, write -- one step: two windows
// saving at once must not lose one another's change
var mu sync.Mutex

// Update reads the presets, lets change edit them and writes the result
// into the user's file, with no other change in between. Nothing is written
// if change fails. The service takes the file within a second.
func Update(change func([]Preset) ([]Preset, error)) error {
	mu.Lock()
	defer mu.Unlock()
	was, err := read()
	if err != nil {
		return fmt.Errorf("%w (%v)", errNotRead, err)
	}
	ps, err := change(was)
	if err != nil {
		return err
	}
	return write(ps)
}

// Restore puts the shipped presets back as the program ships them -- the
// deleted ones too, in their places -- and keeps the user's own after them.
// It returns the presets as they were. With none of the user's own the
// user's file goes: the program's presets are followed again, the lists of
// a later version included.
func Restore() ([]Preset, error) {
	mu.Lock()
	defer mu.Unlock()
	was, err := read()
	if err != nil {
		// the user's own presets are kept through a restore: not read, they
		// would go with it
		return Load(), fmt.Errorf("%w (%v)", errNotRead, err)
	}
	ps := Builtin()
	for _, p := range was {
		if _, ok := Shipped(p.ID); !ok {
			ps = append(ps, p)
		}
	}
	if len(ps) > len(builtin()) {
		return was, write(ps)
	}
	if err := os.Remove(paths.UserPresets()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return was, err
	}
	return was, nil
}

// write: the whole set into the user's file; mu held
func write(ps []Preset) error {
	seen := map[string]bool{}
	for _, p := range ps {
		if !ValidID(p.ID) || seen[p.ID] {
			return errors.New("a preset without an ID of its own")
		}
		seen[p.ID] = true
	}
	if ps == nil {
		ps = []Preset{}
	}
	b, err := json.MarshalIndent(file{Version: fileVersion, Presets: ps}, "", "  ")
	if err != nil {
		return err
	}
	// a file Load would not read gives the shipped presets in its place
	if len(b) >= fileMax {
		return ErrTooLarge
	}
	return paths.ReplaceFile(paths.UserPresets(), append(b, '\n'))
}
