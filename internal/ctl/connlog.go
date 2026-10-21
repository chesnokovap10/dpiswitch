package ctl

import (
	"net"
	"regexp"
	"strings"
	"sync/atomic"
)

// The core's log, line by line: every connection it routes it logs the
// moment it is made -- "[TCP] 198.18.0.1:54040(chrome.exe) --> www.rbc.ru:443
// match RuleSet(direct-verified) using DIRECT". The watcher looks at the
// connection table once a second, and a connection that lives less than
// that is never in it: meduza.io and www.linkedin.com, asked by curl on
// 21.10, were not checked in two minutes, nor ever -- their one connection
// each was gone before the next look. Lines the service hands over here are
// taken in as the table's rows are.

// logFeed: the watcher the core's lines go to while the controller runs
type logFeed struct {
	w   *watcher
	cfg Config
}

var feed atomic.Pointer[logFeed]

// connLine: a connection the core routed. The source may carry the program
// in brackets, with spaces in its name; the rule, its payload in brackets;
// the chain, a group with the proxy it took in square ones.
var connLine = regexp.MustCompile(`msg="\[(TCP|UDP)\] (.+?) --> (\S+) (?:match (.+) using (\S+)|doesn't match any rule using (\S+)|using (\S+))"`)

// CoreLogLine takes one line of the core's log: a connection in it goes to
// the watcher. The service calls it for every line, from the core's output.
func CoreLogLine(line string) {
	f := feed.Load()
	if f == nil || !strings.Contains(line, " --> ") {
		return
	}
	if c, ok := parseConnLine(line); ok {
		f.w.observe(f.cfg, []connection{c})
	}
}

// parseConnLine: the connection a line of the core's log tells of, as the
// connection table would show it
func parseConnLine(line string) (connection, bool) {
	m := connLine.FindStringSubmatch(line)
	if m == nil {
		return connection{}, false
	}
	var c connection
	c.Metadata.Network = strings.ToLower(m[1])
	src := m[2]
	if i := strings.IndexByte(src, '('); i > 0 && strings.HasSuffix(src, ")") {
		c.Metadata.Process = src[i+1 : len(src)-1]
		src = src[:i]
	}
	host, port, err := net.SplitHostPort(src)
	if err != nil {
		return connection{}, false // the core's own: "mihomo --> 10.8.1.0:53"
	}
	c.Metadata.SourceIP, c.Metadata.SourcePort = host, port
	host, port, err = net.SplitHostPort(m[3])
	if err != nil {
		return connection{}, false
	}
	c.Metadata.DestinationPort = port
	if net.ParseIP(host) != nil {
		c.Metadata.DestinationIP = host
	} else {
		c.Metadata.Host = host
	}
	chain := m[5] + m[6] + m[7]
	switch {
	case m[4] != "":
		c.Rule, c.RulePayload = splitRule(m[4])
	case m[6] != "":
		c.Rule = "Match"
	}
	// "tunnel-rest[awg1]": the group, and the proxy it took -- the table
	// lists the proxy first
	if i := strings.IndexByte(chain, '['); i > 0 && strings.HasSuffix(chain, "]") {
		c.Chains = []string{chain[i+1 : len(chain)-1], chain[:i]}
	} else {
		c.Chains = []string{chain}
	}
	return c, true
}

// splitRule: "RuleSet(direct-verified)" as the table has it, the rule's type
// and its payload; "AND(((DomainRegex,.+) && (RuleSet,inherit-ip)))" keeps
// the brackets inside
func splitRule(r string) (rule, payload string) {
	i := strings.IndexByte(r, '(')
	if i <= 0 || !strings.HasSuffix(r, ")") {
		return r, ""
	}
	return r[:i], r[i+1 : len(r)-1]
}
