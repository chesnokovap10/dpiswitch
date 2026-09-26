package awgconf

import (
	"os"
	"strings"
	"testing"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
)

// A quote in a value stays inside its scalar, and a line break never
// reaches the config: a resolver with a quote in its query used to end the
// scalar early, and the core refused the whole config.
func TestYQ(t *testing.T) {
	for in, want := range map[string]string{
		"https://1.1.1.1/dns-query": "'https://1.1.1.1/dns-query'",
		"https://x/q?a='b":          "'https://x/q?a=''b'",
		"a\nsecret: 'x'":            "'asecret: ''x'''",
		"":                          "''",
	} {
		if got := yq(in); got != want {
			t.Errorf("yq(%q) = %q, want %q", in, got, want)
		}
	}
}

// What goes into the config bare is refused unless it is what it says.
func TestConfCheck(t *testing.T) {
	good := func() *Conf {
		return &Conf{
			Interface: Section{"PrivateKey": "k", "Address": "10.8.1.3/32", "MTU": "1380", "Jc": "4"},
			Peer:      Section{"PublicKey": "p", "Endpoint": "vpn.example.org:51820"},
		}
	}
	if err := good().check(); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*Conf){
		"host with a comma": func(c *Conf) { c.Peer["Endpoint"] = "a,DIRECT:51820" },
		"host with a quote": func(c *Conf) { c.Peer["Endpoint"] = "a'b:51820" },
		"port not a number": func(c *Conf) { c.Peer["Endpoint"] = "1.2.3.4:5x" },
		"MTU not a number":  func(c *Conf) { c.Interface["MTU"] = "1380 # {x: y}" },
		"Jc not a number":   func(c *Conf) { c.Interface["Jc"] = "{}" },
	} {
		c := good()
		mod(c)
		if err := c.check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A resolver from the settings -- a file the user writes -- comes out as
// one quoted scalar however it is spelled.
func TestRenderQuotesResolvers(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	if _, err := ctl.UpdateSettings(paths.Settings(), func(s *ctl.Settings) error {
		s.DirectDNS = []string{"https://77.88.8.8/dns-query?x='y"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	c, err := Parse("[Interface]\nPrivateKey = k\nAddress = 10.8.1.3/32\n[Peer]\nPublicKey = p\nEndpoint = 198.51.100.7:51820\n")
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.Render()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "    - 'https://77.88.8.8/dns-query?x=''y'\n") || strings.Contains(out, "x='y'") {
		t.Fatalf("resolver not quoted:\n%s", out)
	}
}

// A second address of the same family is refused, not dropped in silence.
func TestAddrs(t *testing.T) {
	for addr, ok := range map[string]bool{
		"10.8.1.3/32":                           true,
		"10.8.1.3/32, fd7a:a1c3:8b42::3/128":    true,
		"10.0.0.2/24, 10.0.0.3/24":              false,
		"10.8.1.3/32, fd7a::3/128, fd7a::4/128": false,
		"10.8.1.x/32":                           false,
		"fd7a::3/128":                           false, // no IPv4
	} {
		c := &Conf{Interface: Section{"Address": addr}}
		if _, _, err := c.addrs(); (err == nil) != ok {
			t.Errorf("%q: err %v, want ok=%v", addr, err, ok)
		}
	}
}

// A second tunnel with the first one's key -- saved before the UI refused
// it, or put there by hand -- is left out: both would keep dropping.
func TestRenderSkipsSameKey(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	conf := func(key string) string {
		return "[Interface]\nPrivateKey = " + key + "\nAddress = 10.8.1.3/32\n[Peer]\nPublicKey = p\nEndpoint = 198.51.100.8:51820\n"
	}
	c, err := Parse(conf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		key  string
		awg2 bool
	}{{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", false}, {"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", true}} {
		if err := os.WriteFile(paths.SourceConf2(), []byte(conf(tc.key)), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := c.Render()
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(out, "name: awg2"); got != tc.awg2 {
			t.Errorf("key %s: awg2 attached = %v, want %v", tc.key, got, tc.awg2)
		}
	}
}
