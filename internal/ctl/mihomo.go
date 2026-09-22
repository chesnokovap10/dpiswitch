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

// перечитать rule-provider с диска
func (a *api) reloadProvider(name string) error {
	_, err := a.do("PUT", "/providers/rules/"+name, nil)
	return err
}

// имя домена из соединения. sniffHost заполняется, когда домен
// восстановлен из ClientHello -- для софта со своим DoH это
// единственный источник имени.
func (c connection) domain() string {
	h := c.Metadata.SniffHost
	if h == "" {
		h = c.Metadata.Host
	}
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	if h == "" || net.ParseIP(h) != nil {
		return "" // голый IP -- имени нет, решать не по чему
	}
	return h
}

// берём любой TCP-порт, не только 443: на 20000 живут замерочные
// серверы speedtest, и раньше они были заперты в туннеле навсегда.
// UDP по-прежнему пропускаем -- STUN по TCP-пробе судить нельзя.
// по TCP проверяем любой порт; по UDP -- только 443, то есть QUIC.
// STUN, DNS и прочий UDP пробой QUIC судить нельзя.
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

// byProvider: соединение пошло по правилу из этого rule-provider'а
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

// секрет берём из того же конфига, которым запущен mihomo,
// чтобы его не приходилось дублировать в двух местах
// SecretFromConfig: секрет нужен и супервизору для проверки здоровья
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
