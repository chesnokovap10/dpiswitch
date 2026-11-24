package ctl

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/net/idna"

	"dpiswitch/internal/paths"
)

// A user list holds sites, addresses and programs, one per line, in any mix.
// The core takes each kind from a rule-provider of its own: the names from a
// domain one (the core matches those fastest), the addresses from an ipcidr
// one, the programs from a classical one.

// the kinds of a user list's lines
const (
	EntryName = iota // a site: example.com, +.example.com
	EntryIP          // an address or a network: 1.2.3.4, 10.0.0.0/8, 2001:db8::/32
	EntryApp         // a program: telegram.exe, or C:\Games\x.exe for that copy only
)

// ListPolicy is the small part of a list's grammar that depends on the
// block it belongs to. All six user lists otherwise use exactly the same
// parser. The strict Tunnel2 list alone accepts awg2_rule.
type ListPolicy struct {
	AllowAwg2Rule bool
}

// ListEntry is one parsed and canonical line of a user list. Raw and Line
// let the UI explain normalization without making the routing code parse the
// text again.
type ListEntry struct {
	Kind     int
	Value    string
	Raw      string
	Line     int
	Awg2Rule bool
}

// ListIssue is one line the document parser could not understand. A whole
// document is parsed so the UI can report every bad line at once.
type ListIssue struct {
	Line int
	Raw  string
	Err  error
}

type ListChange struct {
	Line       int
	Raw, Value string
}

type ListDuplicate struct {
	Line, FirstLine int
	Value           string
}

// ListDocument is the normalized meaning of a list. Entries are unique and
// sorted in the same order the UI stores them: the macro, domains, addresses,
// programs. Comments and blank lines do not become entries.
type ListDocument struct {
	Entries    []ListEntry
	Issues     []ListIssue
	Normalized []ListChange
	Duplicates []ListDuplicate
}

// Values returns the canonical lines suitable for the user file.
func (d ListDocument) Values() []string {
	out := make([]string, len(d.Entries))
	for i, e := range d.Entries {
		out[i] = e.Value
	}
	return out
}

// ParseList parses a complete user list. Beside the native syntax it accepts
// safe, unambiguous lines commonly pasted from hosts and Mihomo lists:
// DOMAIN, DOMAIN-SUFFIX, IP-CIDR/IP-CIDR6, PROCESS-NAME/PROCESS-PATH,
// 0.0.0.0/127.0.0.1 hosts entries, and ||example.com^ AdBlock domains.
func ParseList(text string, policy ListPolicy) ListDocument {
	var d ListDocument
	seen := map[string]int{}
	for i, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		e, err := parseListEntry(line, i+1, policy)
		if err != nil {
			d.Issues = append(d.Issues, ListIssue{Line: i + 1, Raw: line, Err: err})
			continue
		}
		if e.Raw != e.Value {
			d.Normalized = append(d.Normalized, ListChange{Line: e.Line, Raw: e.Raw, Value: e.Value})
		}
		key := strings.ToLower(e.Value)
		if first := seen[key]; first != 0 {
			d.Duplicates = append(d.Duplicates, ListDuplicate{Line: e.Line, FirstLine: first, Value: e.Value})
		} else {
			seen[key] = e.Line
			d.Entries = append(d.Entries, e)
		}
	}
	sort.SliceStable(d.Entries, func(i, j int) bool {
		a, b := d.Entries[i], d.Entries[j]
		ak, bk := a.Kind, b.Kind
		if a.Awg2Rule {
			ak = -1
		}
		if b.Awg2Rule {
			bk = -1
		}
		if ak != bk {
			return ak < bk
		}
		return strings.ToLower(a.Value) < strings.ToLower(b.Value)
	})
	return d
}

func parseListEntry(line string, number int, policy ListPolicy) (ListEntry, error) {
	e := ListEntry{Raw: line, Line: number}
	if strings.EqualFold(line, Awg2Rule) {
		if !policy.AllowAwg2Rule {
			return e, fmt.Errorf("%s is allowed only in Tunnel2", Awg2Rule)
		}
		e.Value, e.Awg2Rule = Awg2Rule, true
		return e, nil
	}
	converted := line
	if fields := strings.Split(line, ","); len(fields) >= 2 {
		kind, value := strings.ToUpper(strings.TrimSpace(fields[0])), strings.TrimSpace(fields[1])
		switch kind {
		case "DOMAIN":
			if len(fields) != 2 {
				return e, fmt.Errorf("%q: DOMAIN takes one value", line)
			}
			converted = value
		case "DOMAIN-SUFFIX":
			if len(fields) != 2 {
				return e, fmt.Errorf("%q: DOMAIN-SUFFIX takes one value", line)
			}
			converted = "+." + strings.TrimPrefix(value, "+.")
		case "IP-CIDR", "IP-CIDR6":
			if len(fields) > 3 || len(fields) == 3 && !strings.EqualFold(strings.TrimSpace(fields[2]), "no-resolve") {
				return e, fmt.Errorf("%q: unsupported IP rule option", line)
			}
			converted = value
		case "PROCESS-NAME", "PROCESS-PATH":
			if len(fields) != 2 {
				return e, fmt.Errorf("%q: commas in a program's name are not supported", line)
			}
			converted = value
		}
	} else if strings.HasPrefix(line, "||") && strings.HasSuffix(line, "^") {
		converted = "+." + strings.TrimSuffix(strings.TrimPrefix(line, "||"), "^")
	} else if fields := strings.Fields(line); len(fields) == 2 {
		if a, err := netip.ParseAddr(fields[0]); err == nil && (a.IsUnspecified() || a.IsLoopback()) {
			converted = fields[1]
		}
	}
	kind, value, err := ParseEntry(converted)
	if err != nil {
		return e, err
	}
	e.Kind, e.Value = kind, value
	return e, nil
}

// domainRule: a name, "+." / "." / "*." before one allowed -- a "*" in
// another place is checked as a letter, see ParseEntry
var domainRule = regexp.MustCompile(`^(\+\.|\.|\*\.)?[a-z0-9_]([a-z0-9_.-]*[a-z0-9])?$`)

// ParseEntry reads one line of a user list, as the UI takes it and the
// service reads it back: a site pasted as a link loses its scheme, path and
// port; an address is written the one way the core would.
func ParseEntry(s string) (kind int, v string, err error) {
	s = strings.Trim(strings.TrimSpace(s), `"`)
	if s == "" {
		return 0, "", errors.New("empty")
	}
	if strings.HasSuffix(strings.ToLower(s), ".exe") && !strings.Contains(s, "://") {
		// a comma is the field separator in a core rule
		if strings.Contains(s, ",") {
			return 0, "", fmt.Errorf("%q: commas in a program's name are not supported", s)
		}
		if strings.ContainsAny(s, `\/`) {
			return EntryApp, filepath.Clean(s), nil
		}
		return EntryApp, s, nil
	}
	if ip, ok := parseIP(s); ok {
		return EntryIP, ip, nil
	}
	h := strings.ToLower(s)
	for _, p := range []string{"http://", "https://"} {
		h = strings.TrimPrefix(h, p)
	}
	// the path, a query or a fragment: "https://example.com?ref=1" has no "/"
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if ip, ok := parseIP(h); ok {
		return EntryIP, ip, nil
	}
	// an IPv6 address in brackets, a port after it or none: the port was cut
	// at the address's own last colon
	if strings.HasPrefix(h, "[") {
		if end := strings.IndexByte(h, ']'); end > 0 {
			if ip, ok := parseIP(h[1:end]); ok {
				return EntryIP, ip, nil
			}
		}
	}
	// a port after the name is cut: a port, nothing else -- "example.com:abc"
	// was cut to example.com, a typo taken for another entry
	if i := strings.LastIndexByte(h, ':'); i > 0 {
		if p, err := strconv.Atoi(h[i+1:]); err != nil || p < 1 || p > 65535 {
			return 0, "", fmt.Errorf("%q: neither a site, an address nor a program", s)
		}
		h = h[:i]
	}
	if ip, ok := parseIP(h); ok {
		return EntryIP, ip, nil
	}
	// a name as DNS writes it, with the root's dot
	h = strings.TrimSuffix(h, ".")
	// The core's own forms of a name: "+." the name and all under it, "."
	// all under it, and "*" one whole label anywhere -- "*.example.com",
	// "+.example.*" (example.com, a.example.net, not example.co.uk). A
	// label in its own letters -- пример.рф -- goes as DNS and the traffic
	// carry it, in punycode: the core sees nothing else, and the rule never
	// fired.
	pre := ""
	for _, p := range []string{"+.", "."} {
		if strings.HasPrefix(h, p) {
			pre, h = p, h[len(p):]
			break
		}
	}
	labels := strings.Split(h, ".")
	// checked with a letter for each "*", and without them for the digits
	check := make([]string, len(labels))
	var own []string
	for i, l := range labels {
		// "site..com": no name, and no rule the core reads as one
		if l == "" {
			return 0, "", fmt.Errorf("%q: neither a site, an address nor a program", s)
		}
		if l == "*" {
			check[i] = "x"
			continue
		}
		if strings.IndexFunc(l, func(r rune) bool { return r > unicode.MaxASCII }) >= 0 {
			a, err := idna.Lookup.ToASCII(l)
			if err != nil {
				return 0, "", fmt.Errorf("%q: neither a site, an address nor a program", s)
			}
			labels[i] = a
		}
		if len(labels[i]) > 63 {
			return 0, "", fmt.Errorf("%q: a domain label is longer than 63 bytes", s)
		}
		check[i] = labels[i]
		own = append(own, labels[i])
	}
	if len(strings.Join(labels, ".")) > 253 {
		return 0, "", fmt.Errorf("%q: a domain name is longer than 253 bytes", s)
	}
	// a name of wildcards alone would take every site; digits and dots
	// alone are an address gone wrong, not a name
	if len(own) > 0 && domainRule.MatchString(pre+strings.Join(check, ".")) &&
		strings.Trim(strings.Join(own, "."), "0123456789.") != "" {
		return EntryName, pre + strings.Join(labels, "."), nil
	}
	return 0, "", fmt.Errorf("%q: neither a site, an address nor a program", s)
}

type domainPattern struct {
	labels         []string
	minLen, maxLen int // maxLen -1 means no upper bound
}

func parseDomainPattern(rule string) domainPattern {
	rule = strings.ToLower(strings.TrimSpace(rule))
	minExtra, maxExtra := 0, 0
	switch {
	case strings.HasPrefix(rule, "+."):
		rule, maxExtra = rule[2:], -1
	case strings.HasPrefix(rule, "."):
		rule, minExtra, maxExtra = rule[1:], 1, -1
	}
	labels := strings.Split(rule, ".")
	minLen := len(labels) + minExtra
	maxLen := len(labels) + maxExtra
	if maxExtra < 0 {
		maxLen = -1
	}
	return domainPattern{labels: labels, minLen: minLen, maxLen: maxLen}
}

// DomainRuleRelation compares the exact language of two domain rules.
// overlap says at least one host matches both. within says every host matched
// by rule is also matched by container. It handles +., ., and a one-label *
// in any position without enumerating example hosts.
func DomainRuleRelation(rule, container string) (overlap, within bool) {
	a, b := parseDomainPattern(rule), parseDomainPattern(container)
	maxMin := max(a.minLen, b.minLen)
	minMax := func(x, y int) int {
		if x < 0 {
			return y
		}
		if y < 0 {
			return x
		}
		return min(x, y)
	}
	upper := minMax(a.maxLen, b.maxLen)
	overlap = upper < 0 || maxMin <= upper
	if overlap {
		for i := 1; i <= min(len(a.labels), len(b.labels)); i++ {
			x, y := a.labels[len(a.labels)-i], b.labels[len(b.labels)-i]
			if x != "*" && y != "*" && x != y {
				overlap = false
				break
			}
		}
	}
	within = a.minLen >= b.minLen && (b.maxLen < 0 || a.maxLen >= 0 && a.maxLen <= b.maxLen)
	if within {
		for i := 1; i <= len(b.labels); i++ {
			y := b.labels[len(b.labels)-i]
			if y == "*" {
				continue
			}
			if i > len(a.labels) || a.labels[len(a.labels)-i] != y {
				within = false
				break
			}
		}
	}
	return overlap, within
}

// parseIP: an address or a network, written the one way: a network by its
// first address, an address without its /32
func parseIP(s string) (string, bool) {
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		return a.Unmap().String(), true
	}
	if p, err := netip.ParsePrefix(s); err == nil && !p.Addr().Is4In6() {
		p = p.Masked()
		if p.Bits() == p.Addr().BitLen() {
			return p.Addr().String(), true
		}
		return p.String(), true
	}
	return "", false
}

// listFiles: a user list as the core's three providers read it, by kind.
// A line that is none of the kinds is left out: a hand-edited file cannot
// slip other rules in, nor break the core's parse of the list.
type listFiles struct{ names, ips, apps []string }

func splitList(b []byte) listFiles {
	return listFilesFrom(ParseList(string(b), ListPolicy{}))
}

func listFilesFrom(d ListDocument) listFiles {
	var f listFiles
	for _, e := range d.Entries {
		if e.Awg2Rule {
			continue
		}
		switch e.Kind {
		case EntryName:
			f.names = append(f.names, e.Value)
		case EntryIP:
			f.ips = append(f.ips, e.Value)
		case EntryApp:
			f.apps = append(f.apps, e.Value)
		}
	}
	return f
}

// bodies: the three files' contents, by the file names of list
func (f listFiles) bodies(list string) map[string][]byte {
	body := func(lines []string) []byte {
		if len(lines) == 0 {
			return []byte("# empty\n")
		}
		return []byte(strings.Join(lines, "\n") + "\n")
	}
	var cidrs, rules []string
	for _, ip := range f.ips {
		if !strings.Contains(ip, "/") {
			a := netip.MustParseAddr(ip)
			ip = netip.PrefixFrom(a, a.BitLen()).String()
		}
		cidrs = append(cidrs, ip)
	}
	for _, a := range f.apps {
		kind := "PROCESS-NAME"
		if strings.ContainsAny(a, `\/`) {
			kind = "PROCESS-PATH"
		}
		rules = append(rules, kind+","+a)
	}
	return map[string][]byte{list: body(f.names), paths.IPList(list): body(cidrs), paths.AppList(list): body(rules)}
}

// rules is the same list as one classical rule-provider. It is used by
// awg2_rule, which joins the second tunnel's enabled presets and own list in
// one provider routed strictly through awg2.
func (f listFiles) rules() []string {
	var out []string
	for _, n := range f.names {
		out = append(out, nameRule(n))
	}
	for _, ip := range f.ips {
		if !strings.Contains(ip, "/") {
			a := netip.MustParseAddr(ip)
			ip = netip.PrefixFrom(a, a.BitLen()).String()
		}
		kind := "IP-CIDR"
		if netip.MustParsePrefix(ip).Addr().Is6() {
			kind = "IP-CIDR6"
		}
		out = append(out, kind+","+ip+",no-resolve")
	}
	for _, a := range f.apps {
		kind := "PROCESS-NAME"
		if strings.ContainsAny(a, `\\/`) {
			kind = "PROCESS-PATH"
		}
		out = append(out, kind+","+a)
	}
	return out
}
