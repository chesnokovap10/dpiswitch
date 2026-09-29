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

// Second: the second tunnel's .conf as the config takes it -- none, one the
// core could not use, one with the first tunnel's key, one it takes.
func TestSecond(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	conf := func(key, addr string) string {
		return "[Interface]\nPrivateKey = " + key + "\nAddress = " + addr + "\n[Peer]\nPublicKey = p\nEndpoint = 198.51.100.8:51820\n"
	}
	k1, k2 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	first, err := Parse(conf(k1, "10.8.1.3/32"))
	if err != nil {
		t.Fatal(err)
	}
	if c, err := Second(first); c != nil || err != nil {
		t.Fatalf("none loaded: %v, %v", c, err)
	}
	for _, tc := range []struct {
		text string
		ok   bool
		err  error
	}{
		{conf(k2, "fd00::2/128"), false, nil},
		{conf(k1, "10.8.1.4/32"), false, ErrSameKey},
		{conf(k2, "10.8.1.4/32"), true, nil},
	} {
		if err := os.WriteFile(paths.SourceConf2(), []byte(tc.text), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := Second(first)
		if (c != nil) != tc.ok || tc.err != nil && err != tc.err || !tc.ok && err == nil {
			t.Errorf("%q: %v, %v", tc.text, c, err)
		}
	}
	// with no first tunnel to tell by, the key is not asked
	if c, _ := Second(nil); c == nil {
		t.Error("no first tunnel: the second left out")
	}
}

// Observe only goes direct below the lists that name a tunnel, so they route
// in it too; those lists never fall back to direct, and what no list names
// still does, through the first tunnel's group.
func TestRenderRuleOrder(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
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
	at := func(line string) int {
		i := strings.Index(out, "  - "+line+"\n")
		if i < 0 {
			t.Fatalf("no rule %q in:\n%s", line, out)
		}
		return i
	}
	for _, above := range []string{"RULE-SET,force-block,REJECT", "RULE-SET,force-direct-apps,DIRECT",
		"RULE-SET,presets,tunnel2", "RULE-SET,awg2-hosts,tunnel2", "RULE-SET,force-tunnel,tunnel-lists"} {
		if at(above) > at("RULE-SET,observe-all,DIRECT") {
			t.Errorf("%s below the observe only catch-all", above)
		}
	}
	for _, below := range []string{"RULE-SET,force-direct,DIRECT", "RULE-SET,direct-verified,DIRECT", "MATCH,tunnel"} {
		if at(below) < at("RULE-SET,observe-all,DIRECT") {
			t.Errorf("%s above the observe only catch-all", below)
		}
	}
	group := func(name string) string {
		i := strings.Index(out, "  - name: "+name+"\n")
		if i < 0 {
			t.Fatalf("no group %s", name)
		}
		g := out[i+1:]
		if j := strings.Index(g, "\n  - "); j >= 0 {
			g = g[:j]
		}
		if j := strings.Index(g, "\n\n"); j >= 0 {
			g = g[:j]
		}
		return g + "\n"
	}
	if !strings.Contains(group("tunnel"), "- DIRECT") {
		t.Error("the first tunnel's group lost its fallback to direct")
	}
	if strings.Contains(group("tunnel2"), "- DIRECT") {
		t.Error("the second tunnel's group falls back to direct")
	}
	// no second tunnel: the always-tunnel list has awg alone either way
	if g := group("tunnel-one"); !strings.Contains(g, "proxies:\n      - awg\n    url") {
		t.Errorf("the always-tunnel list's tunnel:\n%s", g)
	}
	if g := group("tunnel-any"); strings.Contains(g, "DIRECT") || strings.Contains(g, "awg2") {
		t.Errorf("the always-tunnel list's fallback with no second tunnel:\n%s", g)
	}

	// a second tunnel: awg, then awg2, listed first while switched on
	conf2 := "[Interface]\nPrivateKey = AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.9.1.3/32\n[Peer]\nPublicKey = p\nEndpoint = 198.51.100.8:51820\n"
	if err := os.WriteFile(paths.SourceConf2(), []byte(conf2), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, on := range []bool{true, false} {
		if _, err := ctl.UpdateSettings(paths.Settings(), func(s *ctl.Settings) error { s.SetAwg2(on); return nil }); err != nil {
			t.Fatal(err)
		}
		if out, err = c.Render(); err != nil {
			t.Fatal(err)
		}
		if g := group("tunnel-any"); !strings.Contains(g, "- awg\n      - awg2\n") || strings.Contains(g, "DIRECT") {
			t.Errorf("awg2 %v: the fallback of the always-tunnel list:\n%s", on, g)
		}
		first := "tunnel-one"
		if on {
			first = "tunnel-any"
		}
		if g := group("tunnel-lists"); !strings.Contains(g, "proxies:\n      - "+first+"\n") {
			t.Errorf("awg2 %v: %s is not chosen at start:\n%s", on, first, g)
		}
	}
}

// With no first tunnel the core runs all the same: what no list names goes
// direct, the second tunnel takes its own lists -- and the always-tunnel
// list while switched on --, and a list named for a tunnel with none to
// take it is refused, never sent direct.
func TestRenderNoFirst(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	group := func(out, name string) string {
		i := strings.Index(out, "  - name: "+name+"\n")
		if i < 0 {
			t.Fatalf("no group %s", name)
		}
		g := out[i+1:]
		if j := strings.Index(g, "    url:"); j >= 0 {
			g = g[:j]
		}
		if j := strings.Index(g, "\n\n"); j >= 0 {
			g = g[:j]
		}
		return g
	}
	members := func(out, name string) string {
		g := group(out, name)
		var m []string
		for _, l := range strings.Split(g, "\n") {
			if strings.HasPrefix(l, "      - ") {
				l = strings.TrimSpace(l)
				m = append(m, strings.TrimPrefix(l, "- "))
			}
		}
		return strings.Join(m, " ")
	}
	for _, c := range []struct {
		name                      string
		awg2                      bool
		tunnel, tunnel2, one, any string
	}{
		{"no tunnel", false, "DIRECT", "REJECT", "REJECT", "REJECT"},
		{"the second alone", true, "DIRECT", "awg2", "REJECT", "awg2"},
	} {
		os.Remove(paths.SourceConf2())
		if c.awg2 {
			conf2 := "[Interface]\nPrivateKey = AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.9.1.3/32\n[Peer]\nPublicKey = p\nEndpoint = 198.51.100.8:51820\n"
			if err := os.WriteFile(paths.SourceConf2(), []byte(conf2), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		out, err := RenderNoFirst()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		for g, want := range map[string]string{"tunnel": c.tunnel, "tunnel2": c.tunnel2,
			"tunnel-one": c.one, "tunnel-any": c.any} {
			if got := members(out, g); got != want {
				t.Errorf("%s: group %s has %q, want %q", c.name, g, got, want)
			}
		}
		if strings.Contains(out, "name: awg\n") || strings.Contains(out, "probe-tunnel") {
			t.Errorf("%s: a first tunnel in the config:\n%s", c.name, out)
		}
		if got := strings.Contains(out, "name: awg2\n"); got != c.awg2 {
			t.Errorf("%s: awg2 in the config: %v", c.name, got)
		}
	}
}
