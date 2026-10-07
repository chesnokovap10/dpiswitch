package awgconf

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/probe"
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

// The core asks the program's DNS cache for the direct path when the
// settings have it and it answers -- the direct list otherwise, and for
// everything else always.
func TestRenderDNSCache(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	c, err := Parse("[Interface]\nPrivateKey = k\nAddress = 10.8.1.3/32\n[Peer]\nPublicKey = p\nEndpoint = 198.51.100.7:51820\n")
	if err != nil {
		t.Fatal(err)
	}
	old := cacheAddr
	defer func() { cacheAddr = old }()
	// the list under a key of the dns section
	list := func(out, key string) string {
		i := strings.Index(out, "\n  "+key+":\n")
		if i < 0 {
			t.Fatalf("no %s in\n%s", key, out)
		}
		var items []string
		for _, l := range strings.Split(out[i+len(key)+5:], "\n") {
			if !strings.HasPrefix(l, "    - ") {
				break
			}
			items = append(items, strings.TrimPrefix(l, "    - "))
		}
		return strings.Join(items, " ")
	}
	const direct = "'tls://8.8.8.8' 'tls://8.8.4.4'"
	for _, tc := range []struct {
		on      bool
		serving string
		want    string
	}{
		{false, "127.0.0.1:1054", direct},
		{true, "", direct},
		{true, "127.0.0.1:1054", "'udp://127.0.0.1:1054'"},
	} {
		if _, err := ctl.UpdateSettings(paths.Settings(), func(s *ctl.Settings) error {
			s.DNSCache = tc.on
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		cacheAddr = func() string { return tc.serving }
		out, err := c.Render()
		if err != nil {
			t.Fatal(err)
		}
		if got := list(out, "direct-nameserver"); got != tc.want {
			t.Errorf("on=%v serving=%q: direct-nameserver %s, want %s", tc.on, tc.serving, got, tc.want)
		}
		if got := list(out, "nameserver"); got != direct {
			t.Errorf("on=%v serving=%q: nameserver %s", tc.on, tc.serving, got)
		}
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

// The second tunnel resolves by its own DNS: the settings' if set, else its
// .conf's; and it has a listener of its own for the settings' DNS test.
func TestRenderSecondDNS(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	c, err := Parse("[Interface]\nPrivateKey = k\nAddress = 10.8.1.3/32\nDNS = 10.8.0.1\n[Peer]\nPublicKey = p\nEndpoint = 198.51.100.7:51820\n")
	if err != nil {
		t.Fatal(err)
	}
	two := "[Interface]\nPrivateKey = AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.9.1.3/32\nDNS = 10.9.0.1\n[Peer]\nPublicKey = p\nEndpoint = 198.51.100.8:51820\n"
	out, err := c.Render()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "probe-tunnel2") {
		t.Error("a listener for a second tunnel not loaded")
	}
	if err := os.WriteFile(paths.SourceConf2(), []byte(two), 0o600); err != nil {
		t.Fatal(err)
	}
	dnsOf := func(out, proxy string) string {
		i := strings.Index(out, "  - name: "+proxy+"\n    type: wireguard")
		if i < 0 {
			t.Fatalf("no proxy %s", proxy)
		}
		rest := out[i:]
		j := strings.Index(rest, "    dns: ")
		if j < 0 || strings.Contains(rest[:j], "\n  - name: ") {
			return ""
		}
		return strings.SplitN(rest[j+len("    dns: "):], "\n", 2)[0]
	}
	for _, c2dns := range [][]string{nil, {"10.9.9.9"}} {
		if _, err := ctl.UpdateSettings(paths.Settings(), func(s *ctl.Settings) error {
			s.TunnelDNS, s.TunnelDNS2 = []string{"10.8.8.8"}, c2dns
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if out, err = c.Render(); err != nil {
			t.Fatal(err)
		}
		want2 := "['10.9.0.1']"
		if c2dns != nil {
			want2 = "['10.9.9.9']"
		}
		if got := dnsOf(out, "awg2"); got != want2 {
			t.Errorf("settings %v: awg2 resolves by %s, want %s", c2dns, got, want2)
		}
		if got := dnsOf(out, "awg1"); got != "['10.8.8.8']" {
			t.Errorf("awg1 resolves by %s", got)
		}
		if !strings.Contains(out, "  - name: probe-tunnel2\n    type: socks\n    listen: 127.0.0.1\n    port: 7893\n    proxy: awg2\n") {
			t.Error("no listener through awg2")
		}
		// the prober's listeners take its user alone, the API's secret the
		// password: any program of any account took them
		secret := ctl.SecretFromConfig(writeTemp(t, out))
		users := "    users:\n      - username: " + probe.SocksUser + "\n        password: '" + secret + "'\n"
		if secret == "" || strings.Count(out, users) != 4 {
			t.Errorf("listeners without the prober's user: %d of 4", strings.Count(out, users))
		}
		// the detector's second try at a name blocked by its hello goes
		// out through the outbound that cuts it, and that outbound cuts
		if !strings.Contains(out, "  - name: probe-split\n    type: socks\n    listen: 127.0.0.1\n    port: 7894\n    proxy: direct-split\n") {
			t.Error("no listener through direct-split")
		}
		if !strings.Contains(out, "  - name: direct-split\n    type: direct\n    tls-split: true\n") {
			t.Error("no direct-split outbound")
		}
	}
}

// writeTemp: text in a file of its own, for what reads a file
func writeTemp(t *testing.T, text string) string {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// IPv6 found not reaching the TUN adapter: the programs get none -- no
// stand-in IPv6 addresses, no AAAA answers, the tunnels on IPv4 -- whatever
// the settings ask. The adapter keeps its IPv6 address, for the check at the
// next start to probe by.
func TestRenderIPv6Blocked(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	c, err := Parse("[Interface]\nPrivateKey = k\nAddress = 10.8.1.3/32\n[Peer]\nPublicKey = p\nEndpoint = 198.51.100.7:51820\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, blocked := range []bool{false, true} {
		st := ctl.TunnelIPv6{}
		if blocked {
			st[ctl.TunKey] = false
		}
		if err := st.Save(paths.TunnelIPv6()); err != nil {
			t.Fatal(err)
		}
		out, err := c.Render()
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range []string{"  fake-ip-range6:", "    ip-version: ipv4-prefer", "  ipv6: true"} {
			if got := strings.Contains(out, line+"\n") || strings.Contains(out, line+" "); got == blocked {
				t.Errorf("blocked %v: %q present %v", blocked, line, got)
			}
		}
		if got := strings.Contains(out, "  ipv6: false\n"); got != blocked {
			t.Errorf("blocked %v: the DNS without AAAA answers %v", blocked, got)
		}
		if !strings.Contains(out, "  inet6-address:\n") {
			t.Errorf("blocked %v: the adapter lost its IPv6 address", blocked)
		}
	}
}

// direct-split always sends the decoy, and QUIC to the cut's names goes
// there, refused only for the names the decoy does not get through: the
// decoy goes with the bypass's switch, and only the bypass's names take
// direct-split -- switching it needs no core restart
func TestRenderQUICFake(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	c, err := Parse("[Interface]\nPrivateKey = k\nAddress = 10.8.1.3/32\n[Peer]\nPublicKey = p\nEndpoint = 198.51.100.7:51820\n")
	if err != nil {
		t.Fatal(err)
	}
	reject := "  - AND,((NETWORK,UDP),(DST-PORT,443),(RULE-SET," + ctl.SplitProvider + ")),REJECT\n"
	noQUIC := "  - AND,((NETWORK,UDP),(DST-PORT,443),(RULE-SET," + ctl.NoQUICProvider + ")),REJECT\n"
	var outs []string
	for _, on := range []bool{false, true} {
		if _, err := ctl.UpdateSettings(paths.Settings(), func(s *ctl.Settings) error {
			s.SplitHello = on
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		out, err := c.Render()
		if err != nil {
			t.Fatal(err)
		}
		outs = append(outs, out)
		if !strings.Contains(out, "    tls-split: true\n    # and a decoy QUIC Initial") || !strings.Contains(out, "\n    quic-fake: true\n") {
			t.Errorf("on=%v: no decoy in direct-split", on)
		}
		if strings.Contains(out, reject) {
			t.Errorf("on=%v: QUIC to all the cut's names refused", on)
		}
		if !strings.Contains(out, noQUIC) {
			t.Errorf("on=%v: QUIC not refused to the decoy's failures", on)
		}
		if i, j := strings.Index(out, noQUIC), strings.Index(out, "  - RULE-SET,"+ctl.SplitProvider+","); i > j {
			t.Errorf("the refusal comes after the cut's rule")
		}
		if !strings.Contains(out, "  "+ctl.NoQUICProvider+":\n    type: file\n") {
			t.Errorf("on=%v: no %s provider", on, ctl.NoQUICProvider)
		}
		if !strings.Contains(out, "  - RULE-SET,"+ctl.SplitProvider+","+ctl.SplitOutbound+"\n") {
			t.Errorf("on=%v: the cut's names do not go through %s", on, ctl.SplitOutbound)
		}
	}
	// the core's config is the same either way: no restart for the switch.
	// Each render here makes a secret of its own: that is left out
	same := func(s string) string {
		return regexp.MustCompile(`(?m)^.*(secret|password): .*$`).ReplaceAllString(s, "")
	}
	if same(outs[0]) != same(outs[1]) {
		t.Error("the bypass's switch changes the core's config")
	}
	if !(ctl.Settings{SplitHello: true}).SameCore(ctl.Settings{}) {
		t.Error("the bypass's switch counts as a core setting")
	}
}
