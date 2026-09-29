package ctl

import (
	"os"
	"strings"
)

// Names the user's own lists route: second-tunnel presets, the awg2 list and
// force-tunnel. Their rules stand above the detector's, so a verdict for such
// a name changes nothing -- except that a CLEAN one counts towards a family,
// and the family then sends the name's unlisted siblings direct.
//
// Read from the very files the core uses. Recognising them by the rule a
// connection matched was not enough: a verdict made before a preset was
// enabled was re-checked for as long as the name had been in use, whether or
// not a connection happened to show the preset in the meantime.
type nameSet struct {
	exact  map[string]bool
	suffix map[string]bool // the name and everything under it
	sub    map[string]bool // everything under the name, not the name itself
}

// loadPinned reads rule-provider files in either format the config uses:
// classical ("DOMAIN-SUFFIX,x", "DOMAIN,x") and domain ("x", "+.x", ".x",
// "*.x"). A missing file pins nothing.
func loadPinned(files []string) nameSet {
	n := nameSet{exact: map[string]bool{}, suffix: map[string]bool{}, sub: map[string]bool{}}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(b), "\n") {
			n.add(l)
		}
	}
	return n
}

func (n nameSet) add(line string) {
	l := strings.ToLower(strings.TrimSpace(line))
	if l == "" || strings.HasPrefix(l, "#") {
		return
	}
	if kind, val, ok := strings.Cut(l, ","); ok {
		if strings.TrimSpace(kind) == "domain-regex" {
			// a preset's ".x" or "*.x": read as the lists write it
			if line := PresetNameLine(l); line != "" {
				n.add(line)
			}
			return
		}
		val, _, _ = strings.Cut(val, ",")
		switch strings.TrimSpace(kind) {
		case "domain-suffix":
			n.suffix[strings.TrimSpace(val)] = true
		case "domain":
			n.exact[strings.TrimSpace(val)] = true
		}
		return // IP ranges and other rules name no host
	}
	switch {
	case strings.HasPrefix(l, "+."):
		n.suffix[l[2:]] = true
	case strings.HasPrefix(l, "."):
		n.sub[l[1:]] = true
	case strings.HasPrefix(l, "*."):
		// one level in the core; any depth here -- leaving a deeper name
		// unprobed only keeps it in the tunnel
		n.sub[l[2:]] = true
	default:
		n.exact[l] = true
	}
}

func (n nameSet) has(dom string) bool {
	if n.exact[dom] || n.suffix[dom] {
		return true
	}
	for p := dom; ; {
		_, rest, ok := strings.Cut(p, ".")
		if !ok || rest == "" {
			return false
		}
		if n.suffix[rest] || n.sub[rest] {
			return true
		}
		p = rest
	}
}
