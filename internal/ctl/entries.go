package ctl

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
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

// domainRule: a name, "+." / "." / "*." before one allowed
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
	h, _, _ = strings.Cut(h, "/")
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
	if i := strings.LastIndexByte(h, ':'); i > 0 {
		h = h[:i]
	}
	if ip, ok := parseIP(h); ok {
		return EntryIP, ip, nil
	}
	// a name as DNS writes it, with the root's dot
	h = strings.TrimSuffix(h, ".")
	// A name in its own letters -- пример.рф -- goes as DNS and the traffic
	// carry it, in punycode: the core sees nothing else, and the rule never
	// fired. The "+." before it stays as it is.
	if strings.IndexFunc(h, func(r rune) bool { return r > unicode.MaxASCII }) >= 0 {
		pre := h[:len(h)-len(strings.TrimLeft(h, "+.*"))]
		a, err := idna.Lookup.ToASCII(h[len(pre):])
		if err != nil {
			return 0, "", fmt.Errorf("%q: neither a site, an address nor a program", s)
		}
		h = pre + a
	}
	// digits and dots alone are an address gone wrong, not a name
	if domainRule.MatchString(h) && strings.Trim(h, "0123456789.") != "" {
		return EntryName, h, nil
	}
	return 0, "", fmt.Errorf("%q: neither a site, an address nor a program", s)
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
	var f listFiles
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		// a line of the program list from before: "PROCESS-NAME,x.exe"
		if k, v, ok := strings.Cut(l, ","); ok && (strings.EqualFold(k, "PROCESS-NAME") || strings.EqualFold(k, "PROCESS-PATH")) {
			l = v
		}
		kind, v, err := ParseEntry(l)
		if err != nil {
			continue
		}
		switch kind {
		case EntryName:
			f.names = append(f.names, v)
		case EntryIP:
			f.ips = append(f.ips, v)
		case EntryApp:
			f.apps = append(f.apps, v)
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
