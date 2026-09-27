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
	Probe       bool   // the prober's own, from loopback
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

// the remote address in a dial error: "dial tcp 1.2.3.4:443: ..." direct,
// "dial tcp [fd7a::3]:54895->[2a09::6ab]:443: ..." inside a tunnel
var dialAddrRe = regexp.MustCompile(`(?:dial (?:tcp|udp)[46]? |->)(\[[0-9a-fA-F:.]+\]|[0-9]+(?:\.[0-9]+){3}):[0-9]+`)

// ParseDialErr reads one warning of the core's log; false for any other.
func ParseDialErr(line string) (DialErr, bool) {
	m := dialErrRe.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return DialErr{}, false
	}
	e := DialErr{Network: strings.ToLower(m[1]), Proxy: m[2], Rule: m[3], RulePayload: m[4]}
	if src, _, err := net.SplitHostPort(m[5]); err == nil {
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
		if a := dialAddrRe.FindAllStringSubmatch(m[8], -1); a != nil {
			e.IP = strings.Trim(a[len(a)-1][1], "[]")
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

// FailKind: what a dial error comes down to, for the page to say in words.
func FailKind(err string) string {
	e := strings.ToLower(err)
	switch {
	case strings.Contains(e, "interface not found"):
		return "nonet"
	case strings.Contains(e, "dns resolve failed") || strings.Contains(e, "no such host") ||
		strings.Contains(e, "couldn't find ip"):
		return "dns"
	case strings.Contains(e, "timeout") || strings.Contains(e, "deadline exceeded") ||
		strings.Contains(e, "timed out"):
		return "timeout"
	case strings.Contains(e, "refused"):
		return "refused"
	case strings.Contains(e, "reset"):
		return "reset"
	case strings.Contains(e, "unreachable") || strings.Contains(e, "no route"):
		return "unreach"
	}
	return "other"
}

// DialErrors reads the core's warnings as they come and hands on the failed
// dials, until ctx ends or the core closes the stream -- it restarted.
func (l *LiveClient) DialErrors(ctx context.Context, each func(DialErr)) error {
	req, err := http.NewRequestWithContext(ctx, "GET", l.a.base+"/logs?level=warning", nil)
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
		if e, ok := ParseDialErr(ev.Payload); ok {
			each(e)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return errors.New("the core closed its log")
}
