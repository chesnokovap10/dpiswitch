// Second-tunnel presets: sets of services that always go through awg2,
// bypassing the detector.
//
// catalog.go defines individual services in five built-in categories. The embedded
// lists contain broad service domains, desktop process names and, for calls
// made by address, the Telegram, WhatsApp and Discord networks.
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
	"io/fs"
	"log"
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
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Note     string   `json:"note,omitempty"`
	Category string   `json:"category,omitempty"`
	Lines    []string `json:"lines"`
}

// Catalog is the complete user-editable preset tree. Categories contains
// only custom roots; the built-in roots are supplied by the program.
type Catalog struct {
	Categories []Category
	Presets    []Preset
}

// builtin: the shipped presets, read once -- Load gives them every second
// while the user has changed none
var builtin = sync.OnceValue(func() []Preset {
	out := make([]Preset, 0, len(shipped))
	for _, s := range shipped {
		p := Preset{ID: s.id, Title: s.title, Category: s.category, Lines: []string{}}
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
		if !ok || p.Title != b.Title || p.Note != b.Note || CategoryOf(p) != b.Category || !slices.Equal(p.Lines, b.Lines) {
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
	c, err := readCatalog()
	if err != nil {
		return Builtin()
	}
	return c.Presets
}

// LoadCatalog returns presets together with custom root categories.
func LoadCatalog() Catalog {
	c, err := readCatalog()
	if err != nil {
		return Catalog{Presets: Builtin()}
	}
	return c
}

// Categories returns every root category, built-in first and custom after.
// The UI applies its language-specific sorting and keeps Other last.
func Categories() []Category {
	out := BuiltinCategories()
	for _, c := range LoadCatalog().Categories {
		c.Custom = true
		out = append(out, c)
	}
	return out
}

// readCatalog returns the effective tree and an error when the user's file
// is present but cannot be read safely.
func readCatalog() (Catalog, error) {
	// the user's file, read by the service as SYSTEM: not through a link
	b, err := paths.ReadUserFile(paths.UserPresets(), fileMax)
	if errors.Is(err, fs.ErrNotExist) {
		return Catalog{Presets: Builtin()}, nil
	}
	if err != nil {
		return Catalog{}, err
	}
	c, err := decodeCatalog(b)
	if err != nil {
		return Catalog{Presets: Builtin()}, nil
	}
	validCategories := map[string]bool{}
	for _, x := range builtinCategories {
		validCategories[x.ID] = true
	}
	custom := make([]Category, 0, len(c.Categories))
	for _, x := range c.Categories {
		x.ID, x.Title = strings.TrimSpace(x.ID), strings.TrimSpace(x.Title)
		if !ValidID(x.ID) || x.Title == "" || validCategories[x.ID] {
			continue
		}
		validCategories[x.ID] = true
		x.Custom = true
		custom = append(custom, x)
	}
	out := []Preset{}
	seen := map[string]bool{}
	for _, p := range c.Presets {
		if !ValidID(p.ID) || seen[p.ID] {
			continue
		}
		seen[p.ID] = true
		if !validCategories[p.Category] {
			if shipped, ok := Shipped(p.ID); ok {
				p.Category = shipped.Category
			} else {
				p.Category = "other"
			}
		}
		if p.Lines == nil {
			p.Lines = []string{}
		}
		out = append(out, p)
	}
	return Catalog{Categories: custom, Presets: out}, nil
}

// errNotRead: the user's presets could not be read: none is written over them
var errNotRead = errors.New("The presets could not be read: nothing saved, try again")

// fileVersion is the format written now; version 3 is accepted for upgrade.
const fileVersion = 4

// file: the user's file as it is written
type file struct {
	Version    int        `json:"version"`
	Categories []Category `json:"categories,omitempty"`
	Presets    []Preset   `json:"presets"`
}

// decodeCatalog accepts the current format and version 3, which had presets
// only. The next successful write upgrades it without touching the rules.
func decodeCatalog(b []byte) (Catalog, error) {
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return Catalog{}, err
	}
	if f.Version != 3 && f.Version != fileVersion {
		return Catalog{}, errors.New("unsupported preset file version")
	}
	return Catalog{Categories: f.Categories, Presets: f.Presets}, nil
}

// DecodeFile validates a presets.json selected for import. Unlike Load, a
// bad file is reported instead of silently falling back to the shipped set.
func DecodeFile(b []byte) ([]Preset, error) {
	c, err := DecodeCatalogFile(b)
	return c.Presets, err
}

// DecodeCatalogFile validates a complete presets.json, custom roots included.
func DecodeCatalogFile(b []byte) (Catalog, error) {
	if len(b) >= fileMax {
		return Catalog{}, ErrTooLarge
	}
	c, err := decodeCatalog(b)
	if err != nil {
		return Catalog{}, err
	}
	categoryIDs := map[string]bool{}
	for _, x := range builtinCategories {
		categoryIDs[x.ID] = true
	}
	for i := range c.Categories {
		x := &c.Categories[i]
		x.ID, x.Title = strings.TrimSpace(x.ID), strings.TrimSpace(x.Title)
		if !ValidID(x.ID) || x.Title == "" || categoryIDs[x.ID] {
			return Catalog{}, errors.New("a category without a name or ID of its own")
		}
		categoryIDs[x.ID], x.Custom = true, true
	}
	seen := map[string]bool{}
	for i := range c.Presets {
		if !ValidID(c.Presets[i].ID) || seen[c.Presets[i].ID] {
			return Catalog{}, errors.New("a preset without an ID of its own")
		}
		seen[c.Presets[i].ID] = true
		if !categoryIDs[c.Presets[i].Category] {
			if shipped, ok := Shipped(c.Presets[i].ID); ok {
				c.Presets[i].Category = shipped.Category
			} else {
				c.Presets[i].Category = "other"
			}
		}
		if c.Presets[i].Lines == nil {
			c.Presets[i].Lines = []string{}
		}
	}
	return c, nil
}

// EncodeFile is the complete effective preset set in presets.json format.
func EncodeFile(ps []Preset) ([]byte, error) {
	return EncodeCatalogFile(Catalog{Presets: ps})
}

// EncodeCatalogFile is the complete effective preset tree in presets.json.
func EncodeCatalogFile(c Catalog) ([]byte, error) {
	c.Categories = slices.Clone(c.Categories)
	c.Presets = clone(c.Presets)
	categoryIDs := map[string]bool{}
	for _, x := range builtinCategories {
		categoryIDs[x.ID] = true
	}
	for i, x := range c.Categories {
		c.Categories[i].Title = strings.TrimSpace(x.Title)
		if !ValidID(x.ID) || strings.TrimSpace(x.Title) == "" || categoryIDs[x.ID] {
			return nil, errors.New("a category without a name or ID of its own")
		}
		categoryIDs[x.ID] = true
	}
	seen := map[string]bool{}
	for i := range c.Presets {
		p := &c.Presets[i]
		if !ValidID(p.ID) || seen[p.ID] {
			return nil, errors.New("a preset without an ID of its own")
		}
		if !categoryIDs[p.Category] {
			if shipped, ok := Shipped(p.ID); ok {
				p.Category = shipped.Category
			} else {
				p.Category = "other"
			}
		}
		seen[p.ID] = true
	}
	if c.Presets == nil {
		c.Presets = []Preset{}
	}
	if c.Categories == nil {
		c.Categories = []Category{}
	}
	b, err := json.MarshalIndent(file{Version: fileVersion, Categories: c.Categories, Presets: c.Presets}, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(b) >= fileMax {
		return nil, ErrTooLarge
	}
	return append(b, '\n'), nil
}

// Replace replaces the whole user preset set in one write.
func Replace(ps []Preset) error {
	mu.Lock()
	defer mu.Unlock()
	c, err := readCatalog()
	if err != nil {
		return err
	}
	c.Presets = ps
	return writeCatalog(c)
}

// ReplaceCatalog replaces custom roots and presets in one write.
func ReplaceCatalog(c Catalog) error {
	mu.Lock()
	defer mu.Unlock()
	return writeCatalog(c)
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

// NewCategoryID returns an ID distinct from every built-in and custom root.
func NewCategoryID(categories []Category) string {
	have := map[string]bool{}
	for _, c := range builtinCategories {
		have[c.ID] = true
	}
	for _, c := range categories {
		have[c.ID] = true
	}
	for {
		var b [4]byte
		rand.Read(b[:])
		if id := "c" + hex.EncodeToString(b[:]); !have[id] {
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
	return UpdateCatalog(func(c Catalog) (Catalog, error) {
		ps, err := change(c.Presets)
		c.Presets = ps
		return c, err
	})
}

// UpdateCatalog atomically edits custom roots and presets together.
func UpdateCatalog(change func(Catalog) (Catalog, error)) error {
	mu.Lock()
	defer mu.Unlock()
	was, err := readCatalog()
	if err != nil {
		log.Printf("presets: %s not read, nothing written: %v", paths.UserPresets(), err)
		return errNotRead
	}
	c, err := change(was)
	if err != nil {
		return err
	}
	return writeCatalog(c)
}

// Restore puts the shipped presets back as the program ships them -- the
// deleted ones too, in their places -- and keeps the user's own after them.
// It returns the presets as they were. With none of the user's own the
// user's file goes: the program's presets are followed again, the lists of
// a later version included.
func Restore() ([]Preset, error) {
	mu.Lock()
	defer mu.Unlock()
	wasCatalog, err := readCatalog()
	if err != nil {
		// the user's own presets are kept through a restore: not read, they
		// would go with it
		log.Printf("presets: %s not read, nothing restored: %v", paths.UserPresets(), err)
		return Load(), errNotRead
	}
	was := wasCatalog.Presets
	ps := Builtin()
	for _, p := range was {
		if _, ok := Shipped(p.ID); !ok {
			ps = append(ps, p)
		}
	}
	if len(ps) > len(builtin()) || len(wasCatalog.Categories) > 0 {
		wasCatalog.Presets = ps
		return was, writeCatalog(wasCatalog)
	}
	if err := os.Remove(paths.UserPresets()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return was, err
	}
	return was, nil
}

func writeCatalog(c Catalog) error {
	b, err := EncodeCatalogFile(c)
	if err != nil {
		return err
	}
	return paths.ReplaceFile(paths.UserPresets(), b)
}
