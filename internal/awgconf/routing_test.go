//go:build routing

// The routing checks: every mode, every set of configs loaded, every list
// -- the tables of the help, cell by cell, with the tunnels going down one
// after the other. Routing is what this program is for; run these whenever
// the rules, the groups, the lists' files or the modes change:
//
//	go test -tags routing ./internal/awgconf
//
// (on Windows, or with GOOS=windows -exec wine elsewhere). A plain go test
// leaves them out.
//
// Each case goes the whole way: the service writes the lists' files from
// the user's lists and the settings, the config is rendered as the service
// renders it, and a connection is walked through its rules and groups the
// way the core walks it. The same tables run on the real core, the tunnels
// alive or dead for real, in core_tables_test.go; what it does with a group
// whose tunnels are all down, in core_routing_test.go.

package awgconf

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
)

// the names a connection is made to, one for each place in the tables
const (
	hostUnnamed = "u.example" // no list names it
	hostClean   = "c.example" // the detector found it clean
	hostPreset  = "p.example" // in a preset switched on
	hostAwg2    = "w.example" // in the awg2 list
	hostTunnel  = "t.example" // in Always via tunnel
	hostDirect  = "d.example" // in Always direct
	hostBlock   = "b.example" // in Forbidden
	hostSplit   = "s.example" // the detector found it blocked by name, clean with the ClientHello cut
)

// A route as the tables write it: the tunnels in the order they are tried,
// then what is left when all of them are down -- DIRECT or REJECT. "awg1 >
// awg2 > REJECT": awg1; if it is down, awg2; if both are down, refused. A
// tunnel down is refused as well: the core has nothing to send it by.
type route string

// want: where the route ends with the tunnels alive as given
func (r route) want(alive map[string]bool) string {
	for _, hop := range strings.Split(string(r), " > ") {
		switch hop {
		case "DIRECT", "REJECT", ctl.SplitOutbound:
			return hop
		case "awg1":
			if alive["awg1"] {
				return "awg1"
			}
		case "awg2":
			if alive["awg2"] {
				return "awg2"
			}
		default:
			panic("unknown hop " + hop)
		}
	}
	return "REJECT"
}

// row: one line of a mode's table -- the routes by column
type row struct {
	loaded                                              string // "none", "awg1", "awg2 on", "awg2 off", "both on", "both off"
	unnamed, clean, preset, awg2, tunnel, direct, block route
}

const (
	D = route("DIRECT")
	R = route("REJECT")
)

// the tables of the help
var routingTables = map[string][]row{
	ctl.ModeOn: {
		{"none", D, D, D, D, R, D, R},
		{"awg1", "awg1 > DIRECT", D, "awg1 > DIRECT", "awg1 > DIRECT", "awg1 > REJECT", D, R},
		{"awg2 on", D, D, "awg2 > DIRECT", "awg2 > DIRECT", "awg2 > REJECT", D, R},
		{"awg2 off", D, D, D, D, R, D, R},
		{"both on", "awg1 > awg2 > DIRECT", D, "awg2 > awg1 > DIRECT", "awg2 > awg1 > DIRECT", "awg1 > awg2 > REJECT", D, R},
		{"both off", "awg1 > DIRECT", D, "awg1 > DIRECT", "awg1 > DIRECT", "awg1 > REJECT", D, R},
	},
	ctl.ModeObserve: {
		{"none", D, D, D, D, R, D, R},
		{"awg1", D, D, D, D, "awg1 > REJECT", D, R},
		{"awg2 on", D, D, "awg2 > DIRECT", "awg2 > DIRECT", "awg2 > REJECT", D, R},
		{"awg2 off", D, D, D, D, R, D, R},
		{"both on", D, D, "awg2 > awg1 > DIRECT", "awg2 > awg1 > DIRECT", "awg1 > awg2 > REJECT", D, R},
		{"both off", D, D, D, D, "awg1 > REJECT", D, R},
	},
	ctl.ModeTunnel: {
		{"none", R, R, R, R, R, D, R},
		{"awg1", "awg1 > REJECT", "awg1 > REJECT", "awg1 > REJECT", "awg1 > REJECT", "awg1 > REJECT", D, R},
		{"awg2 on", "awg2 > REJECT", "awg2 > REJECT", "awg2 > REJECT", "awg2 > REJECT", "awg2 > REJECT", D, R},
		{"awg2 off", R, R, R, R, R, D, R},
		{"both on", "awg1 > awg2 > REJECT", "awg1 > awg2 > REJECT", "awg2 > awg1 > REJECT", "awg2 > awg1 > REJECT", "awg1 > awg2 > REJECT", D, R},
		{"both off", "awg1 > REJECT", "awg1 > REJECT", "awg1 > REJECT", "awg1 > REJECT", "awg1 > REJECT", D, R},
	},
}

const routingConf1 = "[Interface]\nPrivateKey = k\nAddress = 10.8.1.3/32\n[Peer]\nPublicKey = p\nEndpoint = 198.51.100.7:51820\n"

// TestRouting: the tables, cell by cell, with every tunnel loaded up or down.
func TestRouting(t *testing.T) {
	n := 0
	for _, mode := range []string{ctl.ModeOn, ctl.ModeObserve, ctl.ModeTunnel} {
		for _, r := range routingTables[mode] {
			t.Run(mode+"/"+r.loaded, func(t *testing.T) {
				core, loaded := setupRouting(t, mode, r.loaded)
				for _, c := range []struct {
					col, host string
					want      route
				}{
					{"what no list names", hostUnnamed, r.unnamed},
					{"a clean site", hostClean, r.clean},
					{"a preset", hostPreset, r.preset},
					{"the awg2 list", hostAwg2, r.awg2},
					{"Always via tunnel", hostTunnel, r.tunnel},
					{"Always direct", hostDirect, r.direct},
					{"Forbidden", hostBlock, r.block},
				} {
					n++
					for _, alive := range aliveSets(loaded) {
						got, why := core.route(c.host, alive)
						if want := c.want.want(alive); got != want {
							t.Errorf("%s (%s), alive %v: %s, want %s\n  %s", c.col, c.want, alive, got, want, why)
						}
					}
				}
			})
		}
	}
	if n != 3*6*7 {
		t.Errorf("%d cells checked, the tables have %d", n, 3*6*7)
	}
}

// TestRoutingSplit: a name the detector sends direct with its ClientHello
// cut takes direct-split in On and Observe only, whatever is loaded -- with
// no first tunnel too; Tunnel only, whose cut list the controller writes
// empty, sends it where it sends what no list names. QUIC to it is refused,
// and the user's lists stand above it.
func TestRoutingSplit(t *testing.T) {
	split := route(ctl.SplitOutbound)
	for _, mode := range []string{ctl.ModeOn, ctl.ModeObserve, ctl.ModeTunnel} {
		for _, r := range routingTables[mode] {
			t.Run(mode+"/"+r.loaded, func(t *testing.T) {
				core, loaded := setupRouting(t, mode, r.loaded)
				want := map[string]route{ctl.ModeOn: split, ctl.ModeObserve: split, ctl.ModeTunnel: r.unnamed}[mode]
				for _, alive := range aliveSets(loaded) {
					if got, why := core.route(hostSplit, alive); got != want.want(alive) {
						t.Errorf("alive %v: %s, want %s\n  %s", alive, got, want.want(alive), why)
					}
				}
				at := func(rule string) int {
					for i, x := range core.rules {
						if strings.Join(x, ",") == rule {
							return i
						}
					}
					t.Fatalf("no rule %s", rule)
					return -1
				}
				cut := at("RULE-SET," + ctl.SplitProvider + "," + ctl.SplitOutbound)
				if quic := at("AND,((NETWORK,UDP),(DST-PORT,443),(RULE-SET," + ctl.SplitProvider + ")),REJECT"); quic > cut {
					t.Error("QUIC to the cut's names is refused after they are sent direct")
				}
				if at("RULE-SET,force-tunnel,"+ctl.TunnelListsGroup) > cut || at("RULE-SET,force-block,REJECT") > cut {
					t.Error("the user's lists below the cut's")
				}
			})
		}
	}
}

// TestRoutingObserveCut: observe only with the ClientHello cut on sends
// what no list names through direct-split at once, before any check -- with
// no first tunnel too; what the detector found clean without the cut goes
// plain, the cut's names cut, the user's lists as ever.
func TestRoutingObserveCut(t *testing.T) {
	for _, r := range routingTables[ctl.ModeObserve] {
		t.Run(r.loaded, func(t *testing.T) {
			_, loaded := setupRouting(t, ctl.ModeObserve, r.loaded)
			if _, err := ctl.UpdateSettings(paths.Settings(), func(s *ctl.Settings) error {
				s.SplitHello = true
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			ctl.SyncUserFiles()
			// the controller writes the direct list there (see ctl.directLists)
			if err := os.WriteFile(paths.Verified(), []byte(hostClean+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			var out string
			var err error
			if slices.Contains(loaded, "awg1") {
				c, err := ParseFile(paths.SourceConf())
				if err != nil {
					t.Fatal(err)
				}
				if out, err = c.Render(); err != nil {
					t.Fatal(err)
				}
			} else if out, err = RenderNoFirst(); err != nil {
				t.Fatal(err)
			}
			core := parseSimCore(t, out)
			split := route(ctl.SplitOutbound)
			for _, c := range []struct {
				col, host string
				want      route
			}{
				{"what no list names", hostUnnamed, split},
				{"a clean site", hostClean, D},
				{"cut by the detector", hostSplit, split},
				{"Always via tunnel", hostTunnel, r.tunnel},
				{"Always direct", hostDirect, r.direct},
				{"Forbidden", hostBlock, r.block},
			} {
				for _, alive := range aliveSets(loaded) {
					if got, why := core.route(c.host, alive); got != c.want.want(alive) {
						t.Errorf("%s, alive %v: %s, want %s\n  %s", c.col, alive, got, c.want.want(alive), why)
					}
				}
			}
		})
	}
}

// setupRouting: a data directory as the service would hold it for the mode
// and the configs loaded, and the core's config rendered from it
func setupRouting(t *testing.T, mode, loaded string) (*simCore, []string) {
	t.Helper()
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	first := loaded == "awg1" || strings.HasPrefix(loaded, "both")
	second := strings.HasPrefix(loaded, "awg2") || strings.HasPrefix(loaded, "both")
	var tunnels []string
	if first {
		write(paths.SourceConf(), routingConf1)
		tunnels = append(tunnels, "awg1")
	}
	if second {
		write(paths.SourceConf2(), conf2)
		tunnels = append(tunnels, "awg2")
	}
	// the user's lists, and a preset of their own switched on
	write(paths.User(paths.TunnelList), hostTunnel+"\n")
	write(paths.User(paths.DirectList), hostDirect+"\n")
	write(paths.User(paths.BlockList), hostBlock+"\n")
	write(paths.User(paths.Awg2List), hostAwg2+"\n")
	if err := presets.Update(func(all []presets.Preset) ([]presets.Preset, error) {
		return append(all, presets.Preset{ID: "routing", Title: "Routing", Lines: []string{hostPreset}}), nil
	}); err != nil {
		t.Fatal(err)
	}
	set, err := ctl.UpdateSettings(paths.Settings(), func(s *ctl.Settings) error {
		s.SetMode(mode)
		// the switch as the row has it; a row with no second tunnel has
		// it on, as it is by default
		s.SetAwg2(!strings.HasSuffix(loaded, " off"))
		s.Awg2Presets = []string{"routing"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// the detector's verdicts: the controller writes the direct list empty
	// in every mode but On (see ctl.disableAuto), the ClientHello cut's in
	// tunnel only (see ctl.splitNames) -- with or without a first tunnel
	if mode == ctl.ModeOn {
		write(paths.Verified(), hostClean+"\n")
	} else {
		write(paths.Verified(), "# auto-switch disabled\n")
	}
	if mode != ctl.ModeTunnel {
		write(paths.VerifiedSplit(), hostSplit+"\n")
	} else {
		write(paths.VerifiedSplit(), "# auto-switch disabled\n")
	}
	EnsureLists()
	ctl.SyncUserFiles()

	var out string
	if first {
		c, err := ParseFile(paths.SourceConf())
		if err != nil {
			t.Fatal(err)
		}
		out, err = c.Render()
		if err != nil {
			t.Fatal(err)
		}
	} else if out, err = RenderNoFirst(); err != nil {
		t.Fatal(err)
	}
	core := parseSimCore(t, out)
	// the select groups start with the member the controller then keeps
	for g, m := range ctl.RouteChoice(set) {
		if got := core.groups[g]; got.kind != "select" || len(got.members) == 0 || got.members[0] != m {
			t.Fatalf("%s: %v, the settings ask for %s", g, got, m)
		}
	}
	return core, tunnels
}

// aliveSets: every way the tunnels loaded can be up or down
func aliveSets(tunnels []string) []map[string]bool {
	sets := []map[string]bool{{}}
	for _, tn := range tunnels {
		var next []map[string]bool
		for _, s := range sets {
			up := map[string]bool{tn: true}
			for k, v := range s {
				up[k] = v
			}
			next = append(next, up, s)
		}
		sets = next
	}
	return sets
}

// simCore: the rules, groups and rule-providers of a rendered config -- the
// parts the core routes a connection by
type simCore struct {
	rules     [][]string
	groups    map[string]simGroup
	providers map[string]simProvider
}

type simGroup struct {
	kind    string
	members []string
}

type simProvider struct {
	behavior string
	lines    []string
}

// parseSimCore reads the config as this package writes it: a line to a key,
// two spaces to a level
func parseSimCore(t *testing.T, out string) *simCore {
	t.Helper()
	c := &simCore{groups: map[string]simGroup{}, providers: map[string]simProvider{}}
	section, name := "", ""
	var g simGroup
	var p simProvider
	flush := func() {
		switch {
		case section == "proxy-groups" && name != "":
			c.groups[name] = g
		case section == "rule-providers" && name != "":
			c.providers[name] = p
		}
		name, g, p = "", simGroup{}, simProvider{}
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "#") || strings.TrimSpace(l) == "" {
			continue
		}
		if !strings.HasPrefix(l, " ") {
			flush()
			section = strings.TrimSuffix(l, ":")
			continue
		}
		switch section {
		case "rules":
			c.rules = append(c.rules, strings.Split(strings.TrimPrefix(l, "  - "), ","))
		case "proxy-groups":
			switch {
			case strings.HasPrefix(l, "  - name: "):
				flush()
				name = strings.TrimPrefix(l, "  - name: ")
			case strings.HasPrefix(l, "    type: "):
				g.kind = strings.TrimPrefix(l, "    type: ")
			case strings.HasPrefix(l, "      - "):
				g.members = append(g.members, strings.TrimPrefix(l, "      - "))
			}
		case "rule-providers":
			switch {
			case strings.HasPrefix(l, "  ") && !strings.HasPrefix(l, "   "):
				flush()
				name = strings.TrimSuffix(strings.TrimSpace(l), ":")
			case strings.HasPrefix(l, "    behavior: "):
				p.behavior = strings.TrimPrefix(l, "    behavior: ")
			case strings.HasPrefix(l, "    path: "):
				b, err := os.ReadFile(filepath.Join(paths.DataDir(), strings.TrimPrefix(l, "    path: ./")))
				if err != nil {
					t.Fatal(err)
				}
				for _, pl := range strings.Split(string(b), "\n") {
					if pl = strings.TrimSpace(pl); pl != "" && !strings.HasPrefix(pl, "#") {
						p.lines = append(p.lines, pl)
					}
				}
			}
		}
	}
	flush()
	if len(c.rules) == 0 || len(c.groups) == 0 || len(c.providers) == 0 {
		t.Fatalf("config not read: %d rules, %d groups, %d providers", len(c.rules), len(c.groups), len(c.providers))
	}
	return c
}

// route: where a TCP connection to host goes, and the rule and groups that
// sent it there. The first rule that fits decides; a select group takes
// the member it lists first, a fallback the first one alive -- or, with
// none alive, its first, which goes nowhere if a tunnel.
func (c *simCore) route(host string, alive map[string]bool) (string, string) {
	for _, r := range c.rules {
		if !c.fits(r, host) {
			continue
		}
		target := r[len(r)-1]
		if target == "no-resolve" {
			target = r[len(r)-2]
		}
		why := strings.Join(r, ",")
		for {
			g, ok := c.groups[target]
			if !ok {
				break
			}
			next := g.members[0]
			if g.kind == "fallback" {
				for _, m := range g.members {
					if m == "DIRECT" || m == "REJECT" || alive[m] {
						next = m
						break
					}
				}
			}
			why += " -> " + target
			target = next
		}
		if target != "DIRECT" && target != "REJECT" && target != ctl.SplitOutbound && !alive[target] {
			return "REJECT", why + " -> " + target + " (down)"
		}
		return target, why + " -> " + target
	}
	return "none", "no rule fits"
}

// fits: whether a rule takes a TCP connection to host. The connections
// here carry a name: address rules with no-resolve never fire for them.
func (c *simCore) fits(r []string, host string) bool {
	switch r[0] {
	case "MATCH":
		return true
	case "DOMAIN":
		return host == r[1]
	case "DOMAIN-SUFFIX":
		return host == r[1] || strings.HasSuffix(host, "."+r[1])
	case "IP-CIDR", "IP-CIDR6":
		return false
	case "RULE-SET":
		p, ok := c.providers[r[1]]
		if !ok {
			panic("no rule-provider " + r[1])
		}
		for _, l := range p.lines {
			switch p.behavior {
			case "domain":
				if ctl.MatchDomainRule(l, host) {
					return true
				}
			case "classical":
				f := strings.Split(l, ",")
				if len(f) >= 2 && c.fits(f, host) || f[0] == "NETWORK" && strings.EqualFold(f[1], "tcp") {
					return true
				}
			}
		}
		return false
	case "PROCESS-NAME", "PROCESS-PATH", "NETWORK":
		return false
	case "AND":
		// the one AND written refuses QUIC to the cut's names: a TCP
		// connection never fits it
		if strings.HasPrefix(strings.Join(r, ","), "AND,((NETWORK,UDP),") {
			return false
		}
	}
	panic(fmt.Sprintf("a rule the checks do not know: %v", r))
}

// members: a group's members as the config lists them
func members(t *testing.T, out, name string) string {
	t.Helper()
	i := strings.Index(out, "  - name: "+name+"\n")
	if i < 0 {
		t.Fatalf("no group %s", name)
	}
	var m []string
	for _, l := range strings.Split(out[i:], "\n")[3:] {
		if !strings.HasPrefix(l, "      - ") {
			break
		}
		m = append(m, strings.TrimPrefix(l, "      - "))
	}
	return strings.Join(m, " ")
}

// groupBlock: a group's lines, its name's to the next group's
func groupBlock(t *testing.T, out, name string) string {
	t.Helper()
	i := strings.Index(out, "  - name: "+name+"\n")
	if i < 0 {
		t.Fatalf("no group %s", name)
	}
	rest := out[i+1:]
	if j := strings.Index(rest, "\n  - name: "); j >= 0 {
		rest = rest[:j+1]
	}
	if j := strings.Index(rest, "\n\n"); j >= 0 {
		rest = rest[:j+1]
	}
	return " " + rest
}

const conf2 = "[Interface]\nPrivateKey = AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.9.1.3/32\n[Peer]\nPublicKey = p\nEndpoint = 198.51.100.8:51820\n"

// The lists go in their order -- Forbidden, Always via tunnel, Always
// direct, the second tunnel -- above the detector's verdicts, the cut's
// first, then observe only's catch-alls and MATCH: with the cut on, observe
// only cuts all but what the detector found clean without it.
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
	order := []string{"RULE-SET,force-block-apps,REJECT", "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
		"RULE-SET,force-tunnel-apps,tunnel-lists", "RULE-SET,force-tunnel-ip,tunnel-lists,no-resolve",
		"RULE-SET,force-direct-apps,DIRECT", "RULE-SET,force-direct-ip,DIRECT,no-resolve",
		"RULE-SET,presets,tunnel2", "RULE-SET,awg2-hosts-ip,tunnel2,no-resolve",
		"RULE-SET,direct-split-verified,direct-split", "RULE-SET,direct-verified,DIRECT",
		"RULE-SET,observe-split,direct-split", "RULE-SET,observe-all,DIRECT", "MATCH,tunnel-rest"}
	for k := 1; k < len(order); k++ {
		if at(order[k-1]) > at(order[k]) {
			t.Errorf("%s below %s", order[k-1], order[k])
		}
	}
}

// The groups by the tunnels loaded: the lists named for a tunnel never go
// direct; tunnel only's never do; the second tunnel takes what no list
// names only behind the first. The select groups list first the member the
// settings ask for.
func TestRenderGroups(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	c1, err := Parse("[Interface]\nPrivateKey = k\nAddress = 10.8.1.3/32\n[Peer]\nPublicKey = p\nEndpoint = 198.51.100.7:51820\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name        string
		first, awg2 bool
		want        map[string]string
	}{
		{"no tunnel", false, false, map[string]string{
			"tunnel": "DIRECT", "tunnel-soft-any": "DIRECT", "tunnel-one": "REJECT", "tunnel-any": "REJECT",
			"tunnel2-soft": "DIRECT", "tunnel2-strict": "REJECT"}},
		{"the second alone", false, true, map[string]string{
			"tunnel": "DIRECT", "tunnel-soft-any": "DIRECT", "tunnel-one": "REJECT", "tunnel-any": "awg2",
			"tunnel2-soft": "awg2 DIRECT", "tunnel2-strict": "awg2"}},
		{"the first alone", true, false, map[string]string{
			"tunnel": "awg1 DIRECT", "tunnel-soft-any": "awg1 DIRECT", "tunnel-one": "awg1", "tunnel-any": "awg1",
			"tunnel2-soft": "awg1 DIRECT", "tunnel2-strict": "awg1"}},
		{"both", true, true, map[string]string{
			"tunnel": "awg1 DIRECT", "tunnel-soft-any": "awg1 awg2 DIRECT", "tunnel-one": "awg1", "tunnel-any": "awg1 awg2",
			"tunnel2-soft": "awg2 awg1 DIRECT", "tunnel2-strict": "awg2 awg1"}},
	} {
		os.Remove(paths.SourceConf2())
		if c.awg2 {
			if err := os.WriteFile(paths.SourceConf2(), []byte(conf2), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		var out string
		if c.first {
			out, err = c1.Render()
		} else {
			out, err = RenderNoFirst()
		}
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		for g, want := range c.want {
			if got := members(t, out, g); got != want {
				t.Errorf("%s: group %s has %q, want %q", c.name, g, got, want)
			}
			// a group that never goes direct refuses even with no member at
			// all; the others take their members' last, DIRECT, anyway
			strict := g == "tunnel-one" || g == "tunnel-any" || g == "tunnel2-strict"
			if got := groupBlock(t, out, g); strings.Contains(got, "empty-fallback: REJECT\n") != strict {
				t.Errorf("%s: group %s, empty-fallback REJECT wanted %v:\n%s", c.name, g, strict, got)
			}
		}
		if got := strings.Contains(out, "name: probe-tunnel\n"); got != c.first {
			t.Errorf("%s: the tunnel probe listener: %v", c.name, got)
		}
	}
	// the choice at start: tunnel only, the second tunnel switched off
	if _, err := ctl.UpdateSettings(paths.Settings(), func(s *ctl.Settings) error {
		s.SetMode(ctl.ModeTunnel)
		s.SetAwg2(false)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	out, err := c1.Render()
	if err != nil {
		t.Fatal(err)
	}
	for g, first := range map[string]string{"tunnel-lists": "tunnel-one", "tunnel2": "tunnel2-strict", "tunnel-rest": "tunnel-one"} {
		if got := members(t, out, g); !strings.HasPrefix(got, first+" ") {
			t.Errorf("%s lists %q: %s is not chosen at start", g, got, first)
		}
	}
}

// The members the select groups take, by mode and by the second tunnel's
// switch: tunnel only never goes direct.
func TestRouteChoice(t *testing.T) {
	for _, c := range []struct {
		mode             string
		awg2             bool
		lists, two, rest string
	}{
		{ctl.ModeOn, true, ctl.TunnelAnyGroup, ctl.Tunnel2SoftGroup, ctl.TunnelSoftAnyGroup},
		{ctl.ModeOn, false, ctl.TunnelOneGroup, ctl.Tunnel2SoftGroup, ctl.TunnelSoftGroup},
		{ctl.ModeObserve, true, ctl.TunnelAnyGroup, ctl.Tunnel2SoftGroup, ctl.TunnelSoftAnyGroup},
		{ctl.ModeTunnel, true, ctl.TunnelAnyGroup, ctl.Tunnel2StrictGroup, ctl.TunnelAnyGroup},
		{ctl.ModeTunnel, false, ctl.TunnelOneGroup, ctl.Tunnel2StrictGroup, ctl.TunnelOneGroup},
	} {
		s := ctl.DefaultSettings()
		s.SetMode(c.mode)
		s.SetAwg2(c.awg2)
		got := ctl.RouteChoice(s)
		if got[ctl.TunnelListsGroup] != c.lists || got[ctl.Tunnel2Group] != c.two || got[ctl.TunnelRestGroup] != c.rest {
			t.Errorf("%s, awg2 %v: %v", c.mode, c.awg2, got)
		}
	}
}
