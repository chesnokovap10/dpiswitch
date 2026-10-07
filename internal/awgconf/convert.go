// Converts an AmneziaWG configuration (.conf) into a mihomo configuration.
// Self-contained so the binary needs no external generator.
package awgconf

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/dnscache"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/probe"
)

type Section map[string]string

type Conf struct {
	Interface Section
	Peer      Section
}

func Parse(text string) (*Conf, error) {
	c := &Conf{Interface: Section{}, Peer: Section{}}
	var cur Section
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			switch strings.ToLower(strings.Trim(line, "[]")) {
			case "interface":
				cur = c.Interface
			case "peer":
				cur = c.Peer
			default:
				cur = nil
			}
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		cur[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if c.Interface["PrivateKey"] == "" {
		return nil, fmt.Errorf("the config has no PrivateKey")
	}
	if c.Peer["Endpoint"] == "" {
		return nil, fmt.Errorf("the config has no Endpoint")
	}
	return c, nil
}

func ParseFile(path string) (*Conf, error) {
	// the .conf is the user's file, read by the service as SYSTEM: not
	// through a link (see paths.ReadUserFile)
	b, err := paths.ReadUserFile(path, 1<<20)
	if err != nil {
		return nil, err
	}
	return Parse(string(b))
}

// the secret is reused: the tray and the controller rely on it,
// and a new one on every generation would silently break their API access.
// Read the way they read it (ctl.SecretFromConfig): a pattern of its own
// here could take a config they read a secret from for one without.
func keepSecret(existing string) string {
	if s := ctl.SecretFromConfig(existing); s != "" {
		return s
	}
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

// yq: s as a single-quoted YAML scalar. Values from a .conf and from the
// settings went between quotes as they were: a quote in one ended the scalar
// early, and the core refused the whole config -- any user who could write
// a resolver into settings.json kept the tunnel down. A line break has no
// place in any of them and is dropped.
func yq(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// hostRe: a name an Endpoint may give -- it also goes into rules, bare
var hostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)

// check refuses what would be written into the config bare and break it or
// change its meaning: an Endpoint host that is neither an address nor a
// name, a number that is not one.
func (c *Conf) check() error {
	host, port, err := net.SplitHostPort(c.Peer["Endpoint"])
	if err != nil {
		return fmt.Errorf("cannot parse Endpoint: %w", err)
	}
	if net.ParseIP(host) == nil && !hostRe.MatchString(host) {
		return fmt.Errorf("Endpoint %q: not an address or a host name", host)
	}
	nums := map[string]string{"Endpoint port": port, "MTU": c.Interface["MTU"]}
	// AWG 3.x writes it as a range too ("25-35"), see keepalive
	if v := c.Peer["PersistentKeepalive"]; v != "" {
		if _, ok := keepalive(v); !ok {
			return fmt.Errorf("PersistentKeepalive = %q: not a number or a range of them", v)
		}
	}
	for _, k := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4"} {
		nums[k] = c.Interface[k]
	}
	for k, v := range nums {
		if v == "" && k != "Endpoint port" {
			continue
		}
		if n, err := strconv.Atoi(v); err != nil || n < 0 {
			return fmt.Errorf("%s = %q: not a number", k, v)
		}
	}
	return nil
}

// keepalive: the core's keepalive for the .conf's PersistentKeepalive -- a
// number, or a range of them ("25-35"), which AmneziaWG 3.x picks from at
// random. The core takes a number only: the low end, the most often the
// range would send one, so a NAT on the way keeps the tunnel's mapping.
func keepalive(v string) (int, bool) {
	lo, hi, isRange := strings.Cut(v, "-")
	a, err := strconv.Atoi(strings.TrimSpace(lo))
	if err != nil || a < 0 {
		return 0, false
	}
	if isRange {
		b, err := strconv.Atoi(strings.TrimSpace(hi))
		if err != nil || b < a {
			return 0, false
		}
	}
	return a, true
}

// CheckKeys: the .conf's keys are WireGuard keys -- base64 of 32 bytes, as
// the core takes them. A key mistyped went into the config, the UI said it
// was applied, and the tunnel never came up.
func (c *Conf) CheckKeys() error {
	for _, k := range []struct{ name, v string }{
		{"PrivateKey", c.Interface["PrivateKey"]},
		{"PublicKey", c.Peer["PublicKey"]},
		{"PresharedKey", c.Peer["PresharedKey"]},
	} {
		if k.v == "" && k.name == "PresharedKey" {
			continue
		}
		if b, err := base64.StdEncoding.DecodeString(k.v); err != nil || len(b) != 32 {
			return fmt.Errorf("%s is not a WireGuard key (base64 of 32 bytes)", k.name)
		}
	}
	return nil
}

func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func quoteList(items []string) string {
	q := make([]string, 0, len(items))
	for _, i := range items {
		q = append(q, yq(i))
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// DNS: resolvers from the [Interface] section
func (c *Conf) DNS() []string {
	out := split(c.Interface["DNS"])
	if out == nil {
		out = []string{}
	}
	return out
}

// Usable: whether the core can make a tunnel of the .conf -- its endpoint,
// its addresses and its numbers as the config needs them. The UI asks it of
// a .conf it saves, and the service of one it renders.
func (c *Conf) Usable() error {
	if _, _, err := c.addrs(); err != nil {
		return err
	}
	return c.check()
}

// ErrSameKey: the two tunnels' configs have one key: to their servers they
// are one peer, and both would keep dropping
var ErrSameKey = errors.New("this is the same config as the first tunnel")

// Second: the second tunnel's .conf as the config takes it. nil and no
// error when none is loaded; nil and why, when one is and the core could
// not use it -- the first tunnel's key included, first given. The config,
// the UI's state of the tunnel and the service's IPv6 check go by it alike:
// the UI said "attached" of a .conf the service had left out.
func Second(first *Conf) (*Conf, error) {
	if _, err := os.Stat(paths.SourceConf2()); err != nil {
		return nil, nil
	}
	c, err := ParseFile(paths.SourceConf2())
	if err != nil {
		return nil, err
	}
	if err := c.Usable(); err != nil {
		return nil, err
	}
	if first != nil && SameKey(first, c) {
		// the UI refuses it either way; a pair from before that, or files
		// put there by hand, must not bring both tunnels down
		return nil, ErrSameKey
	}
	return c, nil
}

// the controller asks whether the second tunnel is in the config as this
// package builds it: a .conf loaded and left out (unusable, or the first
// tunnel's key) is not
func init() {
	ctl.Awg2Attached = func() bool {
		first, _ := ParseFile(paths.SourceConf())
		c2, _ := Second(first)
		return c2 != nil
	}
}

// Tunnels: the tunnels the config is built with, by the core's proxy
// names -- the first if its .conf is there, the second if it is attached.
func Tunnels() []string {
	var out []string
	first, err := ParseFile(paths.SourceConf())
	if err == nil {
		out = append(out, "awg1")
	}
	if c2, _ := Second(first); c2 != nil {
		out = append(out, "awg2")
	}
	return out
}

// Render builds the mihomo configuration from a parsed .conf.
func (c *Conf) Render() (string, error) { return render(c) }

// RenderNoFirst builds the configuration with no first tunnel: the core
// runs all the same -- Live shows what goes where, the lists apply -- and
// what no list names goes direct. A second tunnel carries its presets and
// list, and the always-tunnel list. With none, the presets and the list go
// direct; the always-tunnel list, named for a tunnel, is refused.
func RenderNoFirst() (string, error) { return render(nil) }

// render: the configuration for the first tunnel c, nil for none.
func render(c *Conf) (string, error) {
	var host string
	if c != nil {
		var err error
		if host, _, err = net.SplitHostPort(c.Peer["Endpoint"]); err != nil {
			return "", fmt.Errorf("cannot parse Endpoint: %w", err)
		}
		if _, _, err := c.addrs(); err != nil {
			return "", err
		}
		if err := c.check(); err != nil {
			return "", err
		}
	}
	// the second tunnel, if loaded; a broken second source
	// must not break the first one, so the error only goes to the log
	c2, err := Second(c)
	if err != nil {
		log.Printf("second tunnel not attached: %v", err)
	}

	set := ctl.LoadSettings(paths.Settings())
	// IPv6 as the settings ask, unless the check found Windows keeping it
	// from the TUN adapter (see ctl.TunKey): the programs get no IPv6 then --
	// no stand-in addresses, no AAAA answers, the tunnels on IPv4. The
	// adapter keeps its IPv6 address and route, for the check at the next
	// start to find whether it gets through again: that answer is kept
	// across starts, and a config built with it the same each time needs no
	// core restart to take it (see supervisor.checkIPv6).
	tunV6 := ctl.LoadTunnelIPv6(paths.TunnelIPv6())
	ipv6 := set.IPv6 && !tunV6.SystemBlocked()
	// tunnel resolvers: from settings, otherwise from the .conf
	var tunDNS []string
	if c != nil {
		tunDNS = split(c.Interface["DNS"])
	}
	if len(set.TunnelDNS) > 0 {
		tunDNS = set.TunnelDNS
	}
	// the second tunnel's own: from the settings, otherwise from its .conf
	// -- names are resolved by the server the traffic goes through
	var tun2DNS []string
	if c2 != nil {
		tun2DNS = c2.DNS()
		if len(set.TunnelDNS2) > 0 {
			tun2DNS = set.TunnelDNS2
		}
	}
	directDNS := set.DirectDNS
	bootstrap := bootstrapDNS(directDNS)
	// the direct path's names, as the core resolves them to dial: the
	// program's own cache when it is on and answering (see dnscache) -- it
	// asks directDNS itself
	directNS := directDNS
	if set.DNSCache {
		if a := cacheAddr(); a != "" {
			directNS = []string{"udp://" + a}
		}
	}
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("# generated by dpiswitch from source.conf -- manual edits are pointless,")
	w("# the file is rewritten whenever the config is rebuilt.")
	w("# provider paths are relative: mihomo forbids paths outside")
	w("# its home directory, so the core runs with -d <data directory>")
	w("allow-lan: false")
	w("mode: rule")
	w("log-level: info")
	w("ipv6: true")
	w("unified-delay: true")
	w("tcp-concurrent: true")
	w("# every connection gets its program looked up, not only the ones that")
	w("# reach a process rule: the live page names the program of each")
	w("find-process-mode: always")
	w("external-controller: 127.0.0.1:9090")
	secret := keepSecret(paths.Config())
	w("secret: %s", yq(secret))
	w("# the choice of a select group comes from the settings, not from the")
	w("# core's cache: the one kept there could be stale by a start")
	w("profile:")
	w("  store-selected: false")
	w("")
	w("# a dedicated listener for the prober: bypasses rules, always direct.")
	w("# the only way to give the prober a direct path while TUN")
	w("# captures all other traffic. SOCKS only: the prober speaks nothing else,")
	w("# and the core is built without the other inbounds.")
	w("listeners:")
	// the prober alone: any program of any account took them, the direct
	// one past the tunnel. The core takes UDP only from what an association
	// of this user names (the core's listener/socks/assoc.go).
	users := func() {
		w("    users:")
		w("      - username: %s", probe.SocksUser)
		w("        password: %s", yq(secret))
	}
	w("  - name: probe-direct")
	w("    type: socks")
	w("    listen: 127.0.0.1")
	w("    port: 7892")
	w("    proxy: DIRECT")
	users()
	w("  # the direct path with the ClientHello cut: the detector's second try")
	w("  # at a name blocked by it -- through the very outbound such names take")
	w("  - name: probe-split")
	w("    type: socks")
	w("    listen: 127.0.0.1")
	w("    port: 7894")
	w("    proxy: %s", ctl.SplitOutbound)
	users()
	if c != nil {
		// with no first tunnel the detector has nothing to measure against:
		// it probes nothing, and has no listener
		w("  # the tunnel probe listener is bound to awg1 itself, NOT to the group:")
		w("  # if the group fell back to DIRECT both probes would go direct and")
		w("  # the detector would call everything clean -- the costliest mistake")
		w("  - name: probe-tunnel")
		w("    type: socks")
		w("    listen: 127.0.0.1")
		w("    port: 7891")
		w("    proxy: awg1")
		users()
	}
	if c2 != nil {
		// the settings' DNS test through the second tunnel; the detector
		// never probes through it
		w("  - name: probe-tunnel2")
		w("    type: socks")
		w("    listen: 127.0.0.1")
		w("    port: 7893")
		w("    proxy: awg2")
		users()
	}
	w("")
	w("tun:")
	w("  enable: true")
	w("  # the Windows TCP stack, not gVisor: gVisor retransmitted tail segments")
	w("  # 2-3 times (Meta counter ~2.2x the payload) and capped the upload")
	w("  # through the tunnel at ~160 Mbit/s; system gives 230-250 at half the")
	w("  # CPU. The core is built without gVisor, so no other stack is available.")
	w("  stack: system")
	if set.IPv6 {
		// IPv6 inside the tunnel: the system needs an IPv6 address and route,
		// otherwise programs don't even try IPv6. Kept with IPv6 found not
		// getting through: the check at the next start probes by it
		w("  inet6-address:")
		w("    - 'fdfe:dcba:9876::1/126'")
	}
	w("  auto-route: true")
	w("  auto-detect-interface: true")
	w("  dns-hijack:")
	w("    - any:53")
	w("")
	w("# recovers the domain from the ClientHello for software that")
	w("# resolves around us (browsers with their own DoH)")
	w("#")
	w("# The destination is replaced by the name on every protocol, HTTP too:")
	w("# the route is chosen by that name, so the dial must follow it through")
	w("# the path's own resolver -- the very node the detector probed. HTTP used")
	w("# to keep the address the program chose, and a browser with its own DoH")
	w("# picks IPv6: a dual-stack name verified clean went direct to an IPv6")
	w("# address the ISP does not carry, and every http:// request to it broke.")
	w("# A Host that is an address is never taken (the core refuses it).")
	w("sniffer:")
	w("  enable: true")
	w("  override-destination: true")
	w("  skip-src-address:")
	w("    - 127.0.0.1/32")
	w("  # the local network stays addressed as dialled: a public name pointing")
	w("  # at a LAN box (plex.direct, nip.io) would otherwise lose the address the")
	w("  # local-network rules match on and be sent into a tunnel")
	w("  skip-dst-address:")
	for _, cidr := range localCIDRs {
		w("    - %s", cidr)
	}
	w("  sniff:")
	w("    TLS:")
	w("      ports: [443, 8443]")
	w("    QUIC:")
	w("      ports: [443]")
	w("    HTTP:")
	w("      ports: [80, 8080, 8880]")
	w("")
	w("dns:")
	w("  enable: true")
	w("  listen: 127.0.0.1:1053")
	if !ipv6 && set.IPv6 {
		// IPv6 found not reaching the adapter: no AAAA answers, or programs
		// would dial real IPv6 addresses into it and hang
		w("  ipv6: false")
	} else {
		w("  ipv6: true")
	}
	w("  enhanced-mode: fake-ip")
	w("  fake-ip-range: 198.18.0.1/16")
	if ipv6 {
		// AAAA queries get a fake address too: the connection arrives
		// with the domain, and "direct / tunnel" rules work just as for IPv4.
		//
		// The range is 2001:2::/48 (reserved for benchmarking, RFC 5180),
		// NOT ULA fc00::/7. Chrome treats ULA as a local network and, under
		// Local Network Access rules, silently blocks requests from public
		// pages to such addresses (ERR_FAILED, the request never hits the network).
		// With ULA, iframes, WebSockets and navigation broke: Telegram Web
		// hung on "Waiting for network", embedded video players did not load.
		// Chrome does not treat 198.18.0.0/15 as local for IPv4 -- so the same
		// kind of benchmarking range is used for IPv6.
		w("  fake-ip-range6: '2001:2::/48'")
	}
	w("  fake-ip-filter:")
	for _, z := range localPatterns() {
		w("    - %s", yq(z))
	}
	if c != nil && net.ParseIP(host) == nil {
		w("    - %s", yq(host))
	}
	if c2 != nil {
		if h2, _, err := net.SplitHostPort(c2.Peer["Endpoint"]); err == nil && net.ParseIP(h2) == nil {
			w("    - %s", yq(h2))
		}
	}
	// Two resolvers for two paths.
	// The tunnel resolves by itself, with its DNS inside the tunnel (remote-dns-resolve
	// on awg1): the node is chosen for the VPS that traffic will exit from.
	// The direct path uses direct-nameserver, reached directly: CDNs
	// hand out nodes for the user's ISP. The prober asks the same server,
	// so exactly the node traffic will use gets tested.
	// When the tunnel group falls back to DIRECT, names also resolve
	// via direct-nameserver -- they keep working without the tunnel.
	// No list mixes paths: the core queries the resolvers of a list
	// concurrently, and a mix would return answers from either one.
	w("  # resolves servers given by name; IPs only -- avoids chicken-and-egg")
	w("  default-nameserver:")
	for _, d := range bootstrap {
		w("    - %s", yq(d))
	}
	w("  # everything else (fake-ip-filter, internal queries) -- the same direct DNS")
	w("  nameserver:")
	for _, d := range directDNS {
		w("    - %s", yq(d))
	}
	w("  # local names go to the DNS the router hands out over DHCP: the remote")
	w("  # resolver has never heard of them, and the router answers for itself")
	w("  nameserver-policy:")
	w("    %s:", yq(strings.Join(localPatterns(), ",")))
	w("      - 'dhcp://system'")
	w("      - 'system'")
	w("  direct-nameserver:")
	for _, d := range directNS {
		w("    - %s", yq(d))
	}
	w("  proxy-server-nameserver:")
	for _, d := range bootstrap {
		w("    - %s", yq(d))
	}
	w("")
	// the tunnels there are, by their proxy names
	var first, second []string
	if c != nil {
		first = []string{"awg1"}
	}
	if c2 != nil {
		second = []string{"awg2"}
	}
	// a group with no tunnel to take it refuses, if it may not go direct
	orReject := func(p []string) []string {
		if len(p) == 0 {
			return []string{"REJECT"}
		}
		return p
	}
	cat := func(ps ...[]string) []string {
		var out []string
		for _, p := range ps {
			out = append(out, p...)
		}
		return out
	}
	direct := []string{"DIRECT"}
	// strict: a group that may never go direct. With all its members down
	// the core keeps the first one (and the dial fails), but a group with
	// no member at all -- a provider not loaded yet, a filter matching
	// nothing -- takes empty-fallback, COMPATIBLE by default: that is
	// DIRECT. None of ours can be empty today; this keeps it so if one ever is
	fallback := func(name string, members []string, strict bool) {
		w("  - name: %s", name)
		w("    type: fallback")
		w("    proxies:")
		for _, m := range members {
			w("      - %s", m)
		}
		w("    url: %s", yq(ctl.HealthURL))
		w("    interval: 30")
		// the first check runs as the core starts, when the WireGuard
		// handshake has not finished yet: DNS inside the tunnel is lost and
		// retried after ~5 s. With the default 5 s the check failed, the
		// tunnel was considered dead, and until the next check (30 s) the
		// group sent everything direct -- blocked sites included. Until the
		// check completes the tunnel counts as alive anyway, so the extra
		// margin costs nothing
		w("    timeout: 15000")
		w("    lazy: false")
		if strict {
			w("    empty-fallback: REJECT")
		}
	}
	choice := ctl.RouteChoice(set)
	// a select group: the member the settings ask for first, the choice at start
	selectGroup := func(name string, members ...string) {
		want := choice[name]
		w("  - name: %s", name)
		w("    type: select")
		w("    proxies:")
		w("      - %s", want)
		for _, m := range members {
			if m != want {
				w("      - %s", m)
			}
		}
	}
	w("# Where a connection goes past the lists that name it depends on the mode")
	w("# and on the second tunnel switched on or off. Each route is a select group;")
	w("# the service picks its member as the settings say, with no core restart.")
	w("# A fallback checks its tunnels and, when one is down, takes the next.")
	w("# The lists named for a tunnel never go direct, and tunnel only sends")
	w("# nothing direct but the always-direct list.")
	w("proxy-groups:")
	w("  # the first tunnel, then direct: without it a dead tunnel would mean no")
	w("  # internet at all. With no first tunnel, direct -- the second one takes")
	w("  # only its own lists.")
	fallback(ctl.TunnelSoftGroup, cat(first, direct), false)
	// the second takes what no list names only behind the first
	var behind []string
	if c != nil {
		behind = second
	}
	fallback(ctl.TunnelSoftAnyGroup, cat(first, behind, direct), false)
	w("  # the tunnels alone, never direct: the always-tunnel list, and tunnel only")
	fallback(ctl.TunnelOneGroup, orReject(first), true)
	fallback(ctl.TunnelAnyGroup, orReject(cat(first, second)), true)
	w("  # the presets and the awg2 list: the second tunnel, then the first; then")
	w("  # direct, or in tunnel only refused")
	fallback(ctl.Tunnel2SoftGroup, cat(second, first, direct), false)
	fallback(ctl.Tunnel2StrictGroup, orReject(cat(second, first)), true)
	w("")
	selectGroup(ctl.TunnelListsGroup, ctl.TunnelOneGroup, ctl.TunnelAnyGroup)
	selectGroup(ctl.Tunnel2Group, ctl.Tunnel2SoftGroup, ctl.Tunnel2StrictGroup)
	selectGroup(ctl.TunnelRestGroup, ctl.TunnelSoftGroup, ctl.TunnelSoftAnyGroup, ctl.TunnelOneGroup, ctl.TunnelAnyGroup)
	w("")
	w("rule-providers:")
	w("  # second-tunnel presets: the rules of the ones switched on, in one file")
	w("  # the service writes -- switching, editing, adding and deleting one")
	w("  # need no core restart")
	w("  %s:", ctl.PresetsProvider)
	w("    type: file")
	w("    behavior: classical")
	w("    format: text")
	w("    path: ./%s", filepath.Base(paths.Presets()))
	w("  # observe only: everything goes direct -- the service writes the")
	w("  # catch-all here in that mode and leaves the file empty otherwise")
	w("  observe-all:")
	w("    type: file")
	w("    behavior: classical")
	w("    format: text")
	w("    path: ./observe-all.txt")
	w("  # the same with the ClientHello cut switched on: everything goes direct")
	w("  # through the outbound that cuts it")
	w("  %s:", ctl.ObserveSplitProvider)
	w("    type: file")
	w("    behavior: classical")
	w("    format: text")
	w("    path: ./%s", filepath.Base(paths.ObserveSplit()))
	w("  # the user's lists -- direct, via the tunnel, forbidden, via awg2 -- each")
	w("  # in three: names, addresses and programs. The service writes them from")
	w("  # what the user wrote; the controller never touches them")
	for _, l := range paths.UserLists {
		for _, f := range []struct{ file, behavior string }{
			{l, "domain"}, {paths.IPList(l), "ipcidr"}, {paths.AppList(l), "classical"},
		} {
			w("  %s:", strings.TrimSuffix(f.file, ".txt"))
			w("    type: file")
			w("    behavior: %s", f.behavior)
			w("    format: text")
			w("    path: ./%s", f.file)
		}
	}
	w("  # detector memory: rewritten by the controller")
	w("  %s:", ctl.SplitProvider)
	w("    type: file")
	w("    behavior: domain")
	w("    format: text")
	w("    path: ./%s", filepath.Base(paths.VerifiedSplit()))
	w("  # of those, the ones whose QUIC the decoy does not get through")
	w("  %s:", ctl.NoQUICProvider)
	w("    type: file")
	w("    behavior: domain")
	w("    format: text")
	w("    path: ./%s", filepath.Base(paths.VerifiedSplitNoQUIC()))
	w("  direct-verified:")
	w("    type: file")
	w("    behavior: domain")
	w("    format: text")
	w("    path: ./direct-verified.txt")
	w("  # the probed node with the ports probed, for connections with no name;")
	w("  # classical, since a rule there joins address, port and protocol")
	w("  direct-verified-addr:")
	w("    type: file")
	w("    behavior: classical")
	w("    format: text")
	w("    path: ./direct-verified-addr.txt")
	w("")
	// a tunnel the check found IPv6 dead on keeps its address but resolves
	// IPv4 only -- otherwise every IPv6-only host hangs until its timeout
	w("proxies:")
	w("  # direct, with the client's ClientHello cut in two TLS records in the")
	w("  # middle of the server name and the first TCP segment ending inside the")
	w("  # first record: DPI that reads the name off the hello does not find it.")
	w("  # Only the names the detector found blocked by name and clean this way.")
	w("  - name: %s", ctl.SplitOutbound)
	w("    type: direct")
	w("    tls-split: true")
	// always: only the bypass's names go this way, and with it off none do --
	// switching it needs no core restart
	w("    # and a decoy QUIC Initial for www.google.com ahead of the client's")
	w("    # first one: DPI that reads the name off the Initial reads the decoy's")
	w("    quic-fake: true")
	if c != nil {
		c.writeProxy(w, "awg1", tunDNS, ipv6, tunV6.Dead("awg1"))
	}
	if c2 != nil {
		// the second tunnel uses its own DNS from the .conf: names must be
		// resolved by the server that traffic will go through
		c2.writeProxy(w, "awg2", tun2DNS, ipv6, tunV6.Dead("awg2"))
	}
	w("")
	w("rules:")
	w("  # 1. the tunnel endpoints themselves -- always outside the tunnel, or it loops")
	if c != nil {
		writeEndpointRule(w, host)
	}
	if c2 != nil {
		if h2, _, err := net.SplitHostPort(c2.Peer["Endpoint"]); err == nil {
			writeEndpointRule(w, h2)
		}
	}
	w("")
	w("  # 2. addressing INSIDE the tunnels. It lives in ULA space, which the local")
	w("  #    networks block sends direct -- including the DNS server inside the tunnel.")
	w("  #    These have to come first, or that DNS would be dialled on the local")
	w("  #    network, where nothing answers.")
	if c != nil {
		writeInsideRules(w, c, tunDNS, "tunnel")
	}
	if c2 != nil {
		writeInsideRules(w, c2, tun2DNS, "tunnel2")
	}
	w("")
	w("  # 3. forbidden: refused in every mode, above everything but the tunnels'")
	w("  #    own addresses -- a local address the user named included")
	w("  - RULE-SET,force-block-apps,REJECT")
	w("  - RULE-SET,force-block,REJECT")
	w("  - RULE-SET,force-block-ip,REJECT,no-resolve")
	w("")
	w("  # 4. local networks -- the LAN, the router, printers, network shares.")
	w("  # Nothing here is reachable from the other end of a tunnel anyway.")
	w("  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve")
	w("  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve")
	w("  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve")
	w("  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve")
	w("  - IP-CIDR,169.254.0.0/16,DIRECT,no-resolve")
	w("  - IP-CIDR,100.64.0.0/10,DIRECT,no-resolve")
	w("  # multicast: mDNS 224.0.0.251 and SSDP 239.255.255.250 find the printers,")
	w("  # speakers and TVs on this network")
	w("  - IP-CIDR,224.0.0.0/4,DIRECT,no-resolve")
	w("  - IP-CIDR,255.255.255.255/32,DIRECT,no-resolve")
	w("  - IP-CIDR,0.0.0.0/8,DIRECT,no-resolve")
	w("  - IP-CIDR6,::1/128,DIRECT,no-resolve")
	w("  - IP-CIDR6,fe80::/10,DIRECT,no-resolve")
	w("  - IP-CIDR6,ff00::/8,DIRECT,no-resolve")
	w("  - IP-CIDR6,fc00::/7,DIRECT,no-resolve")
	w("  # the same networks by name. An IP rule with no-resolve never fires for")
	w("  # a connection that carries a domain, and a request to the router does.")
	for _, s := range localSuffixes {
		w("  - DOMAIN-SUFFIX,%s,DIRECT", s)
	}
	for _, d := range localExact {
		w("  - DOMAIN,%s,DIRECT", d)
	}
	w("")
	w("  # 5. the user's always-tunnel list: programs, names, addresses -- above")
	w("  #    every other list but Forbidden, in every mode; never direct")
	w("  - RULE-SET,force-tunnel-apps,%s", ctl.TunnelListsGroup)
	w("  - RULE-SET,force-tunnel,%s", ctl.TunnelListsGroup)
	w("  - RULE-SET,force-tunnel-ip,%s,no-resolve", ctl.TunnelListsGroup)
	w("")
	w("  # 6. the user's always-direct list: programs, names, addresses -- in")
	w("  #    every mode; in tunnel only the one way out past the tunnels")
	w("  - RULE-SET,force-direct-apps,DIRECT")
	w("  - RULE-SET,force-direct,DIRECT")
	w("  - RULE-SET,force-direct-ip,DIRECT,no-resolve")
	w("")
	w("  # 7. second tunnel: presets and the user's awg2 list -- the detector leaves")
	w("  #    them alone. The service writes them empty while awg2 is not loaded")
	w("  #    or switched off.")
	w("  - RULE-SET,%s,%s", ctl.PresetsProvider, ctl.Tunnel2Group)
	w("  - RULE-SET,awg2-hosts-apps,%s", ctl.Tunnel2Group)
	w("  - RULE-SET,awg2-hosts,%s", ctl.Tunnel2Group)
	w("  - RULE-SET,awg2-hosts-ip,%s,no-resolve", ctl.Tunnel2Group)
	w("")
	w("  # 8. the detector's names blocked by name and clean with the ClientHello")
	w("  #    cut: direct through the outbound that cuts it -- above observe only's")
	w("  #    catch-all, which would send them direct uncut. The controller writes")
	w("  #    the list in On and observe only, empty in tunnel only.")
	w("  #    QUIC goes the same way, the decoy Initial ahead of it -- but for")
	w("  #    the names whose QUIC the detector found it does not get through")
	w("  - AND,((NETWORK,UDP),(DST-PORT,443),(RULE-SET,%s)),REJECT", ctl.NoQUICProvider)
	w("  - RULE-SET,%s,%s", ctl.SplitProvider, ctl.SplitOutbound)
	w("")
	w("  # 9. detector verdicts: direct as it is. Written in On, and in observe")
	w("  #    only with the cut on -- there they keep the names the cut harms")
	w("  #    out of its catch-all below")
	w("  - RULE-SET,direct-verified,DIRECT")
	w("  # the same verdicts by the address that was probed, for connections that")
	w("  # carry no name at all (a speedtest client dialling a bare IP on 20000)")
	w("  - RULE-SET,direct-verified-addr,DIRECT,no-resolve")
	w("")
	w("  # 10. observe only: everything the lists above leave goes direct -- with")
	w("  #     the ClientHello cut when it is switched on, the service writes one")
	w("  #     of the two")
	w("  - RULE-SET,%s,%s", ctl.ObserveSplitProvider, ctl.SplitOutbound)
	w("  - RULE-SET,observe-all,DIRECT")
	w("")
	w("  # 11. everything else: the tunnels as the mode says -- in tunnel only")
	w("  #     never direct")
	w("  - MATCH,%s", ctl.TunnelRestGroup)
	return b.String(), nil
}

// addrs: interface addresses from [Interface] Address
func (c *Conf) addrs() (v4, v6 string, err error) {
	// one address of each family: the core's outbound takes one of each, and
	// a second used to replace the first without a word
	for _, a := range split(c.Interface["Address"]) {
		s, _, _ := strings.Cut(a, "/")
		ip := net.ParseIP(s)
		switch {
		case ip == nil:
			return "", "", fmt.Errorf("Address %q: not an IP address", a)
		case ip.To4() == nil && v6 != "", ip.To4() != nil && v4 != "":
			return "", "", fmt.Errorf("Address %q: only one IPv4 and one IPv6 address are supported", a)
		case ip.To4() == nil:
			v6 = ip.String()
		default:
			v4 = ip.String()
		}
	}
	if v4 == "" {
		return "", "", fmt.Errorf("the config has no IPv4 address")
	}
	return v4, v6, nil
}

// Names that belong to this machine's own network. They are kept out of
// fake-ip, resolved by the DNS the router hands out over DHCP, and routed
// direct BY NAME: the IP rules below carry no-resolve, so they never fire for
// a connection that arrives with a domain -- and these always do.
var (
	// suffix and everything under it
	localSuffixes = []string{
		"lan", "local", "home", "home.arpa", "internal", "localdomain",
		// router names. Each is also a real public domain, so resolving them
		// through a tunnel would answer with the vendor's website instead of
		// the box in the next room.
		"miwifi.com", "fritz.box", "tplinkwifi.net", "routerlogin.net",
	}
	// exact names only: the rest of the domain is an ordinary website
	localExact = []string{"router.asus.com"}
	// the unicast ranges of the local-network rules, for the sniffer to skip
	localCIDRs = []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "100.64.0.0/10", "::1/128", "fe80::/10", "fc00::/7"}
)

// localPatterns: what fake-ip and the DNS policy match on.
func localPatterns() []string {
	out := make([]string, 0, len(localSuffixes)+len(localExact))
	for _, s := range localSuffixes {
		out = append(out, "+."+s)
	}
	return append(out, localExact...)
}

// writeInsideRules pins a tunnel's own ULA addressing to that tunnel. The
// local-network block below sends the whole of fc00::/7 direct, and the DNS
// server inside a tunnel lives in exactly that space.
func writeInsideRules(w func(string, ...any), c *Conf, dns []string, group string) {
	seen := map[string]bool{}
	emit := func(cidr string) {
		if cidr == "" || seen[cidr] {
			return
		}
		seen[cidr] = true
		w("  - IP-CIDR6,%s,%s,no-resolve", cidr, group)
	}
	if _, v6, err := c.addrs(); err == nil && v6 != "" {
		emit(prefix64(v6))
	}
	for _, d := range dns {
		ip := net.ParseIP(strings.Trim(d, "[]"))
		if ip == nil || ip.To4() != nil {
			continue
		}
		emit(prefix64(ip.String()))
	}
}

// prefix64: the /64 an address belongs to. Both ends of a tunnel and its DNS
// sit in the same /64, so one rule covers them.
func prefix64(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil || ip.To4() != nil {
		return ""
	}
	n := &net.IPNet{IP: ip.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)}
	return n.String()
}

func writeEndpointRule(w func(string, ...any), host string) {
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			w("  - IP-CIDR,%s/32,DIRECT,no-resolve", host)
		} else {
			w("  - IP-CIDR6,%s/128,DIRECT,no-resolve", host)
		}
	} else {
		w("  - DOMAIN,%s,DIRECT", host)
	}
}

// writeProxy: an AmneziaWG outbound with the given name
func (c *Conf) writeProxy(w func(string, ...any), name string, tunDNS []string, ipv6, v6Dead bool) {
	host, port, _ := net.SplitHostPort(c.Peer["Endpoint"])
	v4, v6, _ := c.addrs()
	mtu := c.Interface["MTU"]
	if mtu == "" {
		mtu = "1420"
	}
	ka, _ := keepalive(c.Peer["PersistentKeepalive"])
	w("  - name: %s", name)
	w("    type: wireguard")
	w("    server: %s", yq(host))
	w("    port: %s", port)
	w("    ip: %s", yq(v4))
	if v6 != "" {
		w("    ipv6: %s", yq(v6))
	}
	w("    private-key: %s", yq(c.Interface["PrivateKey"]))
	w("    public-key: %s", yq(c.Peer["PublicKey"]))
	if k := c.Peer["PresharedKey"]; k != "" {
		w("    pre-shared-key: %s", yq(k))
	}
	allowed := split(c.Peer["AllowedIPs"])
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}
	w("    allowed-ips: %s", quoteList(allowed))
	w("    mtu: %s", mtu)
	// mihomo's own userspace TCP stack with BBR instead of the default gVisor
	// one. With gVisor the upload through the tunnel was capped at 5-20 Mbit/s
	// with an idle CPU and zero loss on the server -- a sender-side window
	// limit. Measured on the same tunnel: gVisor 7, mips 28, mips+cubic 108,
	// mips+bbr ~150 Mbit/s upload; download unchanged. The core no longer
	// includes gVisor, so mips is also the only stack left.
	w("    ip-stack:")
	w("      mode: mips")
	w("      congestion-controller: bbr")
	w("    persistent-keepalive: %d", ka)
	w("    udp: true")
	w("    remote-dns-resolve: true")
	if ipv6 && !v6Dead {
		// IPv4 first, IPv6 when a site has only IPv6. The address family a
		// program chose is not preserved with fake-ip: the core resolves the
		// domain again itself. With ipv6-prefer all tunnel traffic went over
		// IPv6, and a VPS may have several IPv6 addresses, some of which geo
		// databases place in another country -- sites saw the user hop countries.
		// A VPS typically has one IPv4, so the country stays consistent.
		w("    ip-version: ipv4-prefer")
	} else {
		// IPv6 turned off in the settings, or dead through this tunnel. Without this the outbound keeps
		// the core default, which is DualStack: the TUN hands out no IPv6
		// and no AAAA fake address, so nothing reaches the tunnel over IPv6,
		// but the core still resolves the domain itself on the other side and
		// may pick an AAAA there -- the very IPv6 egress the switch turns off.
		// The value is "ipv4", not "ipv4-only": an unknown one silently
		// unmarshals back to DualStack (constant/dns.go).
		w("    ip-version: ipv4")
	}
	if len(tunDNS) > 0 {
		w("    dns: %s", quoteList(tunDNS))
	}
	w("    amnezia-wg-option:")
	w("      version: 3")
	for _, k := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4"} {
		if v := c.Interface[k]; v != "" {
			w("      %s: %s", strings.ToLower(k), v)
		}
	}
	for _, k := range []string{"H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"} {
		if v := c.Interface[k]; v != "" {
			w("      %s: %s", strings.ToLower(k), yq(v))
		}
	}
	strMap := [][2]string{
		{"HeaderProtectionKey", "header-protection-key"},
		{"ContentPaddingAddition", "content-padding-addition"},
		{"RekeyAfterTime", "rekey-after-time"},
		{"RekeyTimeout", "rekey-timeout"},
		{"RejectAfterTime", "reject-after-time"},
		{"KeepaliveTimeout", "keepalive-timeout"},
		{"MaxHandshakeAttempts", "max-handshake-attempts"},
	}
	for _, kv := range strMap {
		if v := c.Interface[kv[0]]; v != "" {
			w("      %s: %s", kv[1], yq(v))
		}
	}
	for _, kv := range [][2]string{{"RandomTrailers", "random-trailers"}, {"DisableCookies", "disable-cookies"}} {
		switch strings.ToLower(c.Interface[kv[0]]) {
		case "on", "true", "1", "yes":
			w("      %s: true", kv[1])
		}
	}
}

// cacheAddr: where the program's DNS cache answers, "" when it does not; a
// var for tests
var cacheAddr = dnscache.Serving

// Regenerate rebuilds config.yaml from the saved source.
//
// The config is fully generated, so a new program version must
// deliver its changes (rules, providers) to an existing installation
// by itself, without reloading the .conf. The file holds the private
// keys: it is replaced whole, readable by the owner alone besides SYSTEM
// and the administrators (see paths.WriteServiceSecret). Returns true if
// anything changed.
func Regenerate() (bool, error) {
	c, err := ParseFile(paths.SourceConf())
	if errors.Is(err, fs.ErrNotExist) {
		c, err = nil, nil
	}
	if err != nil {
		return false, err
	}
	out, err := render(c)
	if err != nil {
		return false, err
	}
	if old, err := os.ReadFile(paths.Config()); err == nil && string(old) == out {
		return false, nil
	}
	// replaced whole -- it holds the private keys; it used to be truncated
	// first and left empty by a failed write
	if err := paths.WriteServiceSecret(paths.Config(), []byte(out), paths.Owner()); err != nil {
		return false, err
	}
	return true, nil
}

// EnsureLists creates missing list files: a provider without
// its file prevents the core from starting
func EnsureLists() {
	files := []string{paths.Verified(), paths.VerifiedAddr(), paths.VerifiedSplit(), paths.VerifiedSplitNoQUIC(), paths.ObserveAll(), paths.ObserveSplit(), paths.Presets()}
	for _, l := range paths.UserLists {
		files = append(files, paths.Data(l), paths.Data(paths.IPList(l)), paths.Data(paths.AppList(l)))
	}
	for _, p := range files {
		if _, err := os.Stat(p); err != nil {
			os.WriteFile(p, []byte("# empty\n"), 0o644)
		}
	}
}

// bootstrapDNS: resolvers given by address, not by name. Plain
// UDP/53 is blocked by some ISPs, so the fallback is
// encrypted and by IP as well.
func bootstrapDNS(list []string) []string {
	var out []string
	for _, d := range list {
		r, err := probe.ParseResolver(d)
		if err == nil && net.ParseIP(r.Host) != nil {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		// the direct path's default, see ctl.defaultDirectDNS
		out = []string{"tls://8.8.8.8", "tls://8.8.4.4"}
	}
	return out
}

// SameKey: the two configs are one peer to their servers -- the same
// private key. Two tunnels with one key are one session the servers keep
// taking from each other, and both keep dropping. Compared as keys, not as
// text: base64 written differently is still the same key.
func SameKey(a, b *Conf) bool {
	ka, ea := base64.StdEncoding.DecodeString(a.Interface["PrivateKey"])
	kb, eb := base64.StdEncoding.DecodeString(b.Interface["PrivateKey"])
	if ea != nil || eb != nil {
		return a.Interface["PrivateKey"] == b.Interface["PrivateKey"]
	}
	return bytes.Equal(ka, kb)
}
