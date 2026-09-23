package ctl

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
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
	} `json:"metadata"`
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

// reload a rule-provider from disk
func (a *api) reloadProvider(name string) error {
	_, err := a.do("PUT", "/providers/rules/"+name, nil)
	return err
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
