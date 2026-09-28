package ctl

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"dpiswitch/internal/probe"
)

// A connection the core could not make never reaches its open ones: the
// dial fails before the core tracks it. All there is of it is a warning in
// the core's log, and the live page reads that log while it is open.

// DialErr: one connection the core failed to make.
type DialErr struct {
	Network     string // tcp, udp
	Proxy       string // the outbound or the group the rules sent it to
	Rule        string
	RulePayload string
	Process     string
	Probe       bool   // the prober's own: from loopback, by a listener bound to an outbound
	Host        string // "" for a bare address
	IP          string // the address, when the error names it
	Port        int
	Err         string
}

// dialErrRe: the core's warning (tunnel.logMetadataErr):
//
//	[TCP] dial tunnel (match RuleSet/direct-verified) 198.18.0.1:50427(chrome.exe) --> example.com:443 error: ...
//
// The rule part is missing for a listener bound to an outbound (the
// prober's), the program's part when it is not known.
var dialErrRe = regexp.MustCompile(`(?s)^\[(TCP|UDP)\] dial (\S+) (?:\(match ([^/)]*)/(.*?)\) )?(\S+?)(?:\(([^)]*)\))? --> (\S+) error: (.*)$`)

// the remote address of each dial in an error: "dial tcp 1.2.3.4:443: ..."
// direct, "dial tcp [fd7a::3]:54895->[2a09::6ab]:443: ..." inside a tunnel,
// where the first is the tunnel's own end. A name with both families dialled
// has one such line for each.
const dialAddr = `(\[[0-9a-fA-F:.]+\]|[0-9]+(?:\.[0-9]+){3}):[0-9]+`

var dialAddrRe = regexp.MustCompile(`dial (?:tcp|udp)[46]? ` + dialAddr + `(?:->` + dialAddr + `)?`)

// ParseDialErr reads one warning of the core's log; false for any other.
func ParseDialErr(line string) (DialErr, bool) {
	m := dialErrRe.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return DialErr{}, false
	}
	e := DialErr{Network: strings.ToLower(m[1]), Proxy: m[2], Rule: m[3], RulePayload: m[4]}
	// The prober's listeners are on loopback and send straight to an
	// outbound, past the rules: the warning names no rule. A local client
	// going through the rules would.
	if src, _, err := net.SplitHostPort(m[5]); err == nil && m[3] == "" {
		ip := net.ParseIP(src)
		e.Probe = ip != nil && ip.IsLoopback()
	}
	e.Process, _, _ = strings.Cut(m[6], ",") // "chrome.exe, uid=0"
	host, port, err := net.SplitHostPort(m[7])
	if err != nil {
		return DialErr{}, false
	}
	e.Port, _ = strconv.Atoi(port)
	if net.ParseIP(host) != nil {
		e.IP = host
	} else {
		e.Host = strings.TrimSuffix(strings.ToLower(host), ".")
		// the first address dialled; the error in full names every one
		if a := dialAddrRe.FindStringSubmatch(m[8]); a != nil {
			e.IP = a[1]
			if a[2] != "" {
				e.IP = a[2]
			}
			e.IP = strings.Trim(e.IP, "[]")
		}
	}
	// errors joined by the core come one to a line, often the same again
	var parts []string
	for _, l := range strings.Split(m[8], "\n") {
		if l = strings.TrimSpace(l); l != "" && !slices.Contains(parts, l) {
			parts = append(parts, l)
		}
	}
	e.Err = probe.Truncate(strings.Join(parts, "; "), 300)
	return e, true
}

// rejectRe: the core's line for a connection a rule refused
// (tunnel.logMetadata), at the info level:
//
//	[TCP] 198.18.0.1:50427(chrome.exe) --> example.com:443 match RuleSet(force-block) using REJECT
var rejectRe = regexp.MustCompile(`^\[(TCP|UDP)\] (\S+?)(?:\(([^)]*)\))? --> (\S+) match (\w+)\(([^)]*)\) using REJECT`)

// Forbidden: what a connection refused by the user's forbidden list failed
// with, see FailKind
const Forbidden = "forbidden by the list"

// ParseReject reads one line of the core's log for a connection the user's
// forbidden list refused; false for any other. The core makes it without an
// error -- a refused one is closed at once, never an open one to be seen.
func ParseReject(line string) (DialErr, bool) {
	m := rejectRe.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil || !strings.HasPrefix(m[6], "force-block") {
		return DialErr{}, false
	}
	e := DialErr{Network: strings.ToLower(m[1]), Proxy: "REJECT", Rule: m[5], RulePayload: m[6], Err: Forbidden}
	e.Process, _, _ = strings.Cut(m[3], ",")
	host, port, err := net.SplitHostPort(m[4])
	if err != nil {
		return DialErr{}, false
	}
	e.Port, _ = strconv.Atoi(port)
	if net.ParseIP(host) != nil {
		e.IP = host
	} else {
		e.Host = strings.TrimSuffix(strings.ToLower(host), ".")
	}
	return e, true
}

// failKinds: what a dial error comes down to, by the words in it -- the
// first that matches. Go's own words and Windows' (WSAECONNRESET is "an
// existing connection was forcibly closed"), and the core's resolver's.
var failKinds = []struct {
	kind  string
	words []string
}{
	{"nonet", []string{"interface not found"}},
	{"dns", []string{"dns resolve failed", "no such host", "couldn't find ip", "no ip address",
		"ip version error", "ipv6 disabled"}},
	{"timeout", []string{"timeout", "deadline exceeded", "timed out", "did not properly respond"}},
	{"refused", []string{"refused"}},
	{"reset", []string{"reset", "forcibly closed", "aborted", "broken pipe"}},
	{"unreach", []string{"unreachable", "no route"}},
	{"canceled", []string{"context canceled", "operation was canceled"}},
}

// eofRe: the other side closed before the connection was made
var eofRe = regexp.MustCompile(`\b(unexpected )?eof\b`)

// FailKind: what a dial error comes down to, for the page to say in words.
// Checked against the 2,174 dial warnings in the core's logs of the machine
// it was written on (September 2026): all but one fell into a kind.
func FailKind(err string) string {
	if err == Forbidden {
		return "forbidden"
	}
	e := strings.ToLower(err)
	for _, k := range failKinds {
		for _, w := range k.words {
			if strings.Contains(e, w) {
				return k.kind
			}
		}
	}
	if eofRe.MatchString(e) {
		return "eof"
	}
	return "other"
}

// Groups: the choice each proxy group has made now, by the group's name.
// A failed dial names the group it was sent to; what it went through is the
// group's choice -- a tunnel group that fell back sends direct.
func (l *LiveClient) Groups() (map[string]string, error) {
	b, err := l.a.do("GET", "/proxies", nil)
	if err != nil {
		return nil, err
	}
	var p struct {
		Proxies map[string]struct {
			Now string `json:"now"`
		} `json:"proxies"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for name, x := range p.Proxies {
		if x.Now != "" {
			out[name] = x.Now
		}
	}
	return out, nil
}

// DialErrors reads the core's log as it comes and hands on the failed
// dials, until ctx ends or the core closes the stream -- it restarted.
func (l *LiveClient) DialErrors(ctx context.Context, each func(DialErr)) error {
	// info, not warning: a connection the forbidden list refused is only
	// an info line, "using REJECT"
	req, err := http.NewRequestWithContext(ctx, "GET", l.a.base+"/logs?level=info", nil)
	if err != nil {
		return err
	}
	if l.a.secret != "" {
		req.Header.Set("Authorization", "Bearer "+l.a.secret)
	}
	resp, err := l.stream.Do(req)
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return ErrCoreDown
	}
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET /logs: %s", resp.Status)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var ev struct {
			Payload string `json:"payload"`
		}
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		var e DialErr
		var ok bool
		if strings.Contains(ev.Payload, " using REJECT") {
			e, ok = ParseReject(ev.Payload)
		} else if strings.Contains(ev.Payload, " error: ") {
			e, ok = ParseDialErr(ev.Payload)
		}
		if ok {
			each(e)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return errors.New("the core closed its log")
}
