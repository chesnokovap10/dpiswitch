package ctl

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"dpiswitch/internal/probe"
)

type api struct {
	base   string
	secret string
	c      *http.Client
}

func newAPI(base, secret string) *api {
	return &api{base: "http://" + base, secret: secret, c: &http.Client{Timeout: 10 * time.Second}}
}

func (a *api) do(method, path string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequest(method, a.base+path, body)
	if err != nil {
		return nil, err
	}
	if a.secret != "" {
		req.Header.Set("Authorization", "Bearer "+a.secret)
	}
	resp, err := a.c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return b, fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	return b, nil
}

type connection struct {
	ID          string   `json:"id"`
	Chains      []string `json:"chains"`
	Download    int64    `json:"download"`
	Upload      int64    `json:"upload"`
	Start       string   `json:"start"`
	Rule        string   `json:"rule"`
	RulePayload string   `json:"rulePayload"`
	Metadata    struct {
		SourceIP        string `json:"sourceIP"`
		SourcePort      string `json:"sourcePort"`
		Host            string `json:"host"`
		SniffHost       string `json:"sniffHost"`
		DestinationIP   string `json:"destinationIP"`
		DestinationPort string `json:"destinationPort"`
		Type            string `json:"type"`
		Network         string `json:"network"`
		Process         string `json:"process"`
		ProcessPath     string `json:"processPath"`
		InboundName     string `json:"inboundName"`
		RemoteDst       string `json:"remoteDestination"`
	} `json:"metadata"`
}

// fromProbe: a connection the prober made through its own listeners (see
// the listeners in awgconf). The TUN brings nothing from loopback, so a
// loopback source is the prober too, on a core that names no inbound.
// Such a connection is no use of the name: counting it renewed LastSeen with
// every re-check, and a name nothing went to was never forgotten.
func (c connection) fromProbe() bool {
	switch c.Metadata.InboundName {
	case "probe-direct", "probe-tunnel":
		return true
	}
	ip := net.ParseIP(c.Metadata.SourceIP)
	return ip != nil && ip.IsLoopback()
}

func (a *api) connections() ([]connection, error) {
	b, err := a.do("GET", "/connections", nil)
	if err != nil {
		return nil, err
	}
	var wrap struct {
		Connections []connection `json:"connections"`
	}
	if err := json.Unmarshal(b, &wrap); err != nil {
		return nil, err
	}
	return wrap.Connections, nil
}

// established: whether the core holds a live connection for a client coming
// from 127.0.0.1:port. The core tracks a connection only once its outbound
// dial has succeeded, so this is the one honest answer to "did the dial go
// through" -- the SOCKS reply is sent before the dial even starts.
func (a *api) established(port int) (bool, error) {
	conns, err := a.connections()
	if err != nil {
		return false, err
	}
	p := strconv.Itoa(port)
	for _, c := range conns {
		if c.Metadata.SourcePort == p && c.Metadata.SourceIP == "127.0.0.1" {
			return true, nil
		}
	}
	return false, nil
}

// closeConnection: the core drops one open connection; the client reconnects,
// and the new connection is routed by the rules as they are now
func (a *api) closeConnection(id string) error {
	_, err := a.do("DELETE", "/connections/"+url.PathEscape(id), nil)
	return err
}

// reload a rule-provider from disk
func (a *api) reloadProvider(name string) error {
	_, err := a.do("PUT", "/providers/rules/"+name, nil)
	return err
}

// HealthURL: what the tunnels are checked against -- by the core's proxy
// groups, and by the supervisor's own liveness check
const HealthURL = "http://cp.cloudflare.com/generate_204"

// healthStale: a last check older than this is no answer. The groups check
// every 30 seconds whether anything uses them or not.
const healthStale = 3 * time.Minute

type delayHistory []struct {
	Time  time.Time `json:"time"`
	Delay int       `json:"delay"`
}

// TunnelCheck: the core's last check of a proxy against HealthURL.
type TunnelCheck struct {
	OK    bool
	At    time.Time // zero: none yet -- a core just started, which counts as up
	Stale bool      // older than healthStale: the core stopped checking
	Note  string
}

// tunnelHealth: lastCheck, in short.
func (a *api) tunnelHealth(proxy string) (bool, string, error) {
	c, err := a.lastCheck(proxy)
	return c.OK, c.Note, err
}

// LastTunnelCheck: lastCheck for the supervisor, which restarts the core on
// what it says.
func LastTunnelCheck(apiAddr, secret, proxy string) (TunnelCheck, error) {
	return newAPI(apiAddr, secret).lastCheck(proxy)
}

// lastCheck reads what the core's own health checks last found for a proxy,
// without making one more: the proxy groups check their members every 30
// seconds.
func (a *api) lastCheck(proxy string) (TunnelCheck, error) {
	b, err := a.do("GET", "/proxies/"+url.PathEscape(proxy), nil)
	if err != nil {
		return TunnelCheck{}, err
	}
	var p struct {
		History delayHistory `json:"history"`
		// by test URL. The plain history holds every check, the supervisor's
		// IPv6 one too -- which fails on a tunnel with no IPv6, and would
		// read as the tunnel being down
		Extra map[string]struct {
			History delayHistory `json:"history"`
		} `json:"extra"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return TunnelCheck{}, err
	}
	h := p.History
	if x, ok := p.Extra[HealthURL]; ok {
		h = x.History
	}
	if len(h) == 0 {
		return TunnelCheck{OK: true, Note: "not checked yet"}, nil
	}
	last := h[len(h)-1]
	c := TunnelCheck{At: last.Time}
	switch {
	case time.Since(last.Time) > healthStale:
		c.Stale, c.Note = true, "no check since "+last.Time.Format("15:04:05")
	case last.Delay <= 0:
		c.Note = "no answer at " + last.Time.Format("15:04:05")
	default:
		c.OK, c.Note = true, fmt.Sprintf("%d ms", last.Delay)
	}
	return c, nil
}

// TunnelHealth: tunnelHealth for the tray and the UI. They used to test the
// tunnel themselves, the tray every ten seconds: some 8,600 requests a day
// through it for an icon, on top of the checks the core makes anyway.
func TunnelHealth(apiAddr, secret, proxy string) (bool, string) {
	ok, note, err := newAPI(apiAddr, secret).tunnelHealth(proxy)
	if err != nil {
		return false, "core API not responding: " + probe.Truncate(err.Error(), 90)
	}
	return ok, note
}

// domain name of a connection. sniffHost is filled when the domain was
// recovered from the ClientHello -- for software with its own DoH it is
// the only source of the name.
func (c connection) domain() string {
	h := c.Metadata.SniffHost
	if h == "" {
		h = c.Metadata.Host
	}
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	if h == "" || net.ParseIP(h) != nil {
		return "" // bare IP -- no name, nothing to decide on
	}
	return h
}

// Any TCP port is probeable, not just 443: speedtest measurement servers
// live on 20000 and used to be locked into the tunnel forever. For UDP only
// 443 (QUIC) is probed: STUN, DNS and other UDP cannot be judged by a QUIC
// probe.
func (c connection) probeable() bool {
	if c.port() <= 0 {
		return false
	}
	if c.isUDP() {
		return c.port() == 443
	}
	return strings.EqualFold(c.Metadata.Network, "tcp")
}

func (c connection) isUDP() bool {
	return strings.EqualFold(c.Metadata.Network, "udp")
}

func (c connection) port() int {
	n, err := strconv.Atoi(c.Metadata.DestinationPort)
	if err != nil || n <= 0 || n > 65535 {
		return 0
	}
	return n
}

func (c connection) viaTunnel(proxyName string) bool {
	for _, ch := range c.Chains {
		if ch == proxyName {
			return true
		}
	}
	return false
}

// byProvider: the connection matched a rule from this rule-provider
func (c connection) byProvider(name string) bool {
	return c.Rule == "RuleSet" && c.RulePayload == name
}

// pinned: the connection was routed by a list the detector does not write --
// a second-tunnel preset, or the user's names and addresses for awg2, for the
// tunnel or forbidden. Those rules stand above the detector's, so its verdict
// changes nothing. A program's list is not: it says nothing of the name, and
// other programs reach that name by the detector's rules. (Direct connections
// never reach the watcher's filter.)
func (c connection) pinned() bool {
	if c.Rule != "RuleSet" {
		return false
	}
	switch c.RulePayload {
	case PresetsProvider, "awg2-hosts", "awg2-hosts-ip", "force-tunnel", "force-tunnel-ip", "force-block", "force-block-ip":
		return true
	}
	return false
}

func (c connection) viaDirect() bool {
	for _, ch := range c.Chains {
		if ch == "DIRECT" {
			return true
		}
	}
	return false
}

var secretRe = regexp.MustCompile(`(?m)^secret:\s*'?"?([^'"\r\n]+)'?"?\s*$`)

// SecretFromConfig reads the API secret from the config mihomo runs with,
// so it never has to be duplicated; the supervisor needs it for health checks too
func SecretFromConfig(path string) string { return secretFromConfig(path) }

func secretFromConfig(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if m := secretRe.FindSubmatch(b); m != nil {
		return strings.Trim(string(m[1]), `'"`)
	}
	return ""
}
