// Second-tunnel presets: sets of services that always go through awg2,
// bypassing the detector.
//
// The program ships a few, taken from server-side setups solving the same
// task:
//   - AI: an nginx SNI allow-list plus the Google AI zones;
//   - Telegram: the ranges from core.telegram.org/resources/cidr.txt plus
//     domains;
//   - YouTube: domains (the server relays all of Google via goog.json;
//     the client only needs YouTube).
//
// The user edits them, deletes them and adds their own on the second
// tunnel's page. Until the first such change the shipped ones are used; from
// then on the user's file holds the whole set, what is left of the shipped
// ones included. The service turns the ones switched on into core rules, all
// in one file (see ctl.SyncUserFiles): a preset added or deleted needs
// neither a restart nor a config.yaml change.
package presets

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
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
	{"telegram", "Telegram", "Telegram domains and networks -- the apps connect by IP",
		[]string{"telegram-domains.txt", "telegram-cidr.txt"}},
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
	// the user's file, read by the service as SYSTEM: not through a link
	b, err := paths.ReadUserFile(paths.UserPresets(), fileMax)
	if err != nil {
		return Builtin()
	}
	var ps []Preset
	if err := json.Unmarshal(b, &ps); err != nil {
		return Builtin()
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
	return out
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
	ps, err := change(Load())
	if err != nil {
		return err
	}
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
	b, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return err
	}
	// a file Load would not read gives the shipped presets in its place
	if len(b) >= fileMax {
		return ErrTooLarge
	}
	return paths.ReplaceFile(paths.UserPresets(), append(b, '\n'))
}
