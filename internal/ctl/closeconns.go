package ctl

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// Conn: what the UI needs of an open connection to tell whether a change to
// one of the user's lists moves it. The core routes a connection once, when
// it opens: a site added to "always via tunnel" kept going direct over the
// connections a browser already held, for minutes.
type Conn struct {
	Host        string // the name, "" for a bare address
	IP          string // the destination address
	Process     string // the program's file name
	ProcessPath string
	RulePayload string // the rule-provider that routed it, for RuleSet rules
}

// CloseConns closes the open connections match picks and says how many.
// The clients reconnect, and the core routes the new connections by the
// rules as they are now. A core that is not listening has nothing open:
// that is no error. Any other failure is, a connection not closed included:
// it keeps its old route.
func CloseConns(apiAddr, secret string, match func(Conn) bool) (int, error) {
	a := newAPI(apiAddr, secret)
	conns, err := a.connections()
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n, failed := 0, 0
	var lastErr error
	for _, c := range conns {
		v := Conn{Host: c.domain(), IP: c.Metadata.DestinationIP,
			Process: c.Metadata.Process, ProcessPath: c.Metadata.ProcessPath}
		if c.Rule == "RuleSet" {
			v.RulePayload = c.RulePayload
		}
		// the prober's own connections are routed by their listener, not by
		// any list: closing one only broke a probe running at the time
		if c.ID == "" || c.fromProbe() || !match(v) {
			continue
		}
		if err := a.closeConnection(c.ID); err != nil {
			failed, lastErr = failed+1, err
			continue
		}
		n++
	}
	if failed > 0 {
		return n, fmt.Errorf("%d connections not closed: %w", failed, lastErr)
	}
	return n, nil
}

// ReloadProviders has the core read these rule-providers now. It watches
// their files by itself, but when it gets to it is its own affair: a list
// written and its connections closed at once, the client reconnected before
// the core had the new rules -- and the new connection took the old route,
// to keep it. A core that is not listening reads the files when it starts:
// no error.
func ReloadProviders(apiAddr, secret string, names ...string) error {
	a := newAPI(apiAddr, secret)
	for _, n := range names {
		err := a.reloadProvider(n)
		var op *net.OpError
		if errors.As(err, &op) && op.Op == "dial" {
			return nil
		}
		if err != nil {
			return fmt.Errorf("provider %s not reloaded: %w", n, err)
		}
	}
	return nil
}

// MatchDomainRule: whether host matches one line of a domain rule-provider,
// as the core reads it -- "+.example.com" is the domain and every name under
// it, ".example.com" only the names under it, "*.example.com" one level
// down, anything else that exact name.
func MatchDomainRule(rule, host string) bool {
	rule = strings.ToLower(strings.TrimSpace(rule))
	host = strings.ToLower(host)
	if rule == "" || host == "" {
		return false
	}
	switch {
	case strings.HasPrefix(rule, "+."):
		d := rule[2:]
		return host == d || strings.HasSuffix(host, "."+d)
	case strings.HasPrefix(rule, "."):
		return strings.HasSuffix(host, rule)
	case strings.HasPrefix(rule, "*."):
		d := rule[1:]
		return strings.HasSuffix(host, d) && !strings.Contains(strings.TrimSuffix(host, d), ".")
	}
	return host == rule
}
