package ctl

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dpiswitch/internal/probe"
)

// Scenario tests: connections as the core reports them go through the
// watcher and a whole cycle, with the probe scripted; what comes out is
// memory and the rule files the core reads. Each case is a situation that
// once went wrong.

type scenario struct {
	t   *testing.T
	cfg Config
	api *api
	st  *state
	w   *watcher

	mu      sync.Mutex
	conns   []connection
	reloads map[string]int
	results map[string]probe.Report // "name tcp/443" -> what the probe says
	probed  []string
	noV6    map[string]bool // what the direct dialer said of IPv6, by probe
	where   atomic.Value    // the network the machine is attached to, see attachmentNow
}

func newScenario(t *testing.T) *scenario {
	t.Helper()
	s := &scenario{t: t, reloads: map[string]int{}, results: map[string]probe.Report{},
		noV6: map[string]bool{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/connections":
			json.NewEncoder(w).Encode(map[string]any{"connections": s.conns})
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/providers/rules/"):
			s.reloads[strings.TrimPrefix(r.URL.Path, "/providers/rules/")]++
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	s.api = newAPI(strings.TrimPrefix(srv.URL, "http://"), "")

	dir := t.TempDir()
	preset := filepath.Join(dir, "presets.txt")
	if err := os.WriteFile(preset, []byte("# preset ai\nDOMAIN-SUFFIX,claude.ai\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.cfg = Config{
		ProxyName: "awg", Provider: "direct-verified", AddrProvider: "direct-verified-addr",
		ListPath: filepath.Join(dir, "direct-verified.txt"), AddrListPath: filepath.Join(dir, "addr.txt"),
		StatePath: filepath.Join(dir, "state.json"),
		TTL:       7 * 24 * time.Hour, FailTTL: time.Hour, MaxBackoff: 24 * time.Hour, Idle: 24 * time.Hour,
		Families: true, Attempts: 1, Workers: 4, PerCycle: 20, Apply: true,
		PinnedLists: []string{preset},
	}
	s.st = loadState(s.cfg.StatePath)
	s.w = &watcher{seen: map[string]map[endpoint]bool{}, bare: map[string]bool{},
		live: map[string]bool{}, pinned: map[string]bool{},
		addrPorts: map[string]map[endpoint]bool{}, addrCycles: map[string]int{}}

	old := checkProto
	checkProto = s.check
	t.Cleanup(func() { checkProto = old })
	s.where.Store("wifi-a")
	oldAt := attachmentNow
	attachmentNow = func() string { return s.where.Load().(string) }
	t.Cleanup(func() { attachmentNow = oldAt })
	return s
}

// check stands in for the probe: it answers from the script.
func (s *scenario) check(direct, _ probe.Dialer, dom string, port, _ int, udp bool, _ probe.Verdict) probe.Report {
	key := dom + " " + endpoint{udp: udp, port: port}.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.probed = append(s.probed, key)
	s.noV6[key] = direct.NoV6
	r, ok := s.results[key]
	if !ok {
		s.t.Errorf("unscripted probe: %s", key)
		r = probe.Report{Verdict: probe.Inconcl, Unmeasured: true}
	}
	r.Domain, r.Port, r.Proto = dom, port, "tcp"
	if udp {
		r.Proto = "quic"
	}
	return r
}

// see: the core shows these connections now, and the watcher takes them in.
func (s *scenario) see(conns ...connection) {
	s.mu.Lock()
	s.conns = conns
	s.mu.Unlock()
	s.w.observe(s.cfg, conns)
}

func (s *scenario) script(key string, r probe.Report) { s.results[key] = r }

func (s *scenario) cycle() {
	s.mu.Lock()
	s.probed = nil
	s.mu.Unlock()
	cycle(s.cfg, s.api, s.st, "n", s.w)
}

func (s *scenario) wasProbed(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Contains(s.probed, key)
}

func (s *scenario) entry(dom string) *entry {
	e, _ := s.st.get("n", dom)
	return e
}

// --- connections and probe results as the core and the prober give them ---

// via: a connection with a name, and the route the core gave it
func via(host string, port int, network, chain, rule, payload string) connection {
	var c connection
	c.Chains = []string{chain}
	c.Rule, c.RulePayload = rule, payload
	c.Start = time.Now().Add(-time.Minute).Format(time.RFC3339)
	c.Download = 1000
	c.Metadata.SourceIP = "198.18.0.1"
	c.Metadata.Host = host
	c.Metadata.DestinationPort = strconv.Itoa(port)
	c.Metadata.Network = network
	return c
}

func tunnelled(host string, port int) connection {
	return via(host, port, "tcp", "awg", "Match", "")
}

func quic(host string) connection { return via(host, 443, "udp", "awg", "Match", "") }

var (
	pathOK   = probe.PathResult{TCPOk: true, TLSTried: true, TLSOk: true, CertValid: true}
	tlsCut   = probe.PathResult{TCPOk: true, TLSTried: true, Err: "EOF", ErrStage: "tls"}
	tcpFails = probe.PathResult{Err: "i/o timeout", ErrStage: "tcp"}
)

func clean(ip string) probe.Report {
	return probe.Report{Verdict: probe.Clean, TestedIP: ip, Direct: pathOK, Tunnel: pathOK}
}

func cleanTCP(ip string) probe.Report {
	ok := probe.PathResult{TCPOk: true}
	return probe.Report{Verdict: probe.Clean, TestedIP: ip, Direct: ok, Tunnel: ok}
}

func blockedTLS(ip string) probe.Report {
	return probe.Report{Verdict: probe.BlockedTLS, Reason: "tls: EOF", TestedIP: ip, Direct: tlsCut, Tunnel: pathOK}
}

// --- the scenarios ---

func TestCycleCleanNameGoesDirect(t *testing.T) {
	s := newScenario(t)
	s.see(tunnelled("a.example.org", 443))
	s.script("a.example.org tcp/443", clean("192.0.2.1"))
	s.cycle()
	if got := listRules(s.cfg.ListPath); !slices.Equal(got, []string{"a.example.org"}) {
		t.Fatalf("list %v", got)
	}
	if s.reloads["direct-verified"] == 0 {
		t.Fatal("the core was not told to reload the list")
	}
	// decided: the next cycle leaves it alone
	s.cycle()
	if s.wasProbed("a.example.org tcp/443") {
		t.Fatal("a fresh CLEAN was probed again")
	}
}

// The worst port decides: a rule covers the name on every port.
func TestCycleWorstPortWins(t *testing.T) {
	s := newScenario(t)
	s.see(tunnelled("b.example.org", 443), tunnelled("b.example.org", 5228))
	s.script("b.example.org tcp/443", clean("192.0.2.2"))
	s.script("b.example.org tcp/5228", probe.Report{Verdict: probe.BlockedTCP, TestedIP: "192.0.2.2",
		Direct: tcpFails, Tunnel: probe.PathResult{TCPOk: true}})
	s.cycle()
	if e := s.entry("b.example.org"); e.Verdict != probe.BlockedTCP {
		t.Fatalf("verdict %s", e.Verdict)
	}
	if got := listRules(s.cfg.ListPath); len(got) != 0 {
		t.Fatalf("list %v", got)
	}
}

// Clean on 443, and on 5228 the direct side fails where the tunnel's fails
// differently: INCONCLUSIVE for that port, but not CLEAN for the name --
// it used to come out CLEAN.
func TestCycleDirectDownOnAnotherPort(t *testing.T) {
	s := newScenario(t)
	s.see(tunnelled("c.example.org", 443), tunnelled("c.example.org", 5228))
	s.script("c.example.org tcp/443", clean("192.0.2.3"))
	s.script("c.example.org tcp/5228", probe.Report{Verdict: probe.Inconcl, TestedIP: "192.0.2.3",
		Reason: "tunnel path unavailable", Direct: tcpFails, Tunnel: tlsCut})
	s.cycle()
	e := s.entry("c.example.org")
	if e.Verdict != probe.Inconcl || !e.DirectDown {
		t.Fatalf("verdict %s, direct down %v", e.Verdict, e.DirectDown)
	}
	if got := listRules(s.cfg.ListPath); len(got) != 0 {
		t.Fatalf("list %v", got)
	}
}

// A speedtest server: nothing speaks TLS on its 443, on either path, and
// its 20000 works direct. The same failure on both paths is the server's;
// it used to lock the server into the tunnel. Its node goes to the address
// list on 20000 only, for the client that dials it by address.
func TestCycleSpeedtestServer(t *testing.T) {
	s := newScenario(t)
	s.see(tunnelled("speed.example.org", 443), tunnelled("speed.example.org", 20000))
	s.script("speed.example.org tcp/443", probe.Report{Verdict: probe.Inconcl, TestedIP: "192.0.2.4",
		Reason: "fails the same on both paths: tls: EOF", Direct: tlsCut, Tunnel: tlsCut})
	s.script("speed.example.org tcp/20000", cleanTCP("192.0.2.4"))
	s.cycle()
	if e := s.entry("speed.example.org"); e.Verdict != probe.Clean {
		t.Fatalf("verdict %s", e.Verdict)
	}
	addrs := listRules(s.cfg.AddrListPath)
	if len(addrs) != 1 || !strings.Contains(addrs[0], "192.0.2.4/32") ||
		!strings.Contains(addrs[0], "DST-PORT,20000)") {
		t.Fatalf("address rules %v", addrs)
	}
}

// A name a preset routes is never probed, and a verdict made before the
// preset existed is dropped -- a CLEAN there made families of its siblings.
func TestCyclePinnedLeftAlone(t *testing.T) {
	s := newScenario(t)
	s.st.put("n", "api.claude.ai", &entry{Verdict: probe.Clean, DecidedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour), LastSeen: time.Now()})
	s.see(via("claude.ai", 443, "tcp", "awg2", "RuleSet", PresetsProvider))
	s.cycle()
	if len(s.probed) != 0 {
		t.Fatalf("probed %v", s.probed)
	}
	if e := s.entry("api.claude.ai"); e != nil {
		t.Fatalf("the preset's name kept its verdict: %s", e.Verdict)
	}
}

// A name seen only over QUIC is probed over TCP on that port too: a browser
// falls back to TCP whenever it likes, and the rule covers both.
func TestCycleQUICOnlyGetsTCP(t *testing.T) {
	s := newScenario(t)
	s.see(quic("q.example.org"))
	s.script("q.example.org quic/443", clean("192.0.2.5"))
	s.script("q.example.org tcp/443", blockedTLS("192.0.2.5"))
	s.cycle()
	if !s.wasProbed("q.example.org tcp/443") {
		t.Fatal("TCP was not probed")
	}
	if e := s.entry("q.example.org"); e.Verdict == probe.Clean {
		t.Fatal("CLEAN with TCP blocked")
	}
}

// An expired CLEAN a re-check cannot confirm leaves the list, instead of
// being kept on the strength of the old result.
func TestCycleExpiredCleanNotKept(t *testing.T) {
	s := newScenario(t)
	s.st.put("n", "old.example.org", &entry{Verdict: probe.Clean, TestedIP: "192.0.2.6",
		DecidedAt: time.Now().Add(-8 * 24 * time.Hour), ExpiresAt: time.Now().Add(-time.Hour),
		LastSeen: time.Now(), Endpoints: []string{"tcp/443"}})
	s.see(tunnelled("old.example.org", 443))
	s.script("old.example.org tcp/443", probe.Report{Verdict: probe.Inconcl, Unmeasured: true,
		Reason: "tunnel path unavailable", TestedIP: "192.0.2.6", Direct: pathOK, Tunnel: tcpFails})
	s.cycle()
	if e := s.entry("old.example.org"); e.Verdict == probe.Clean {
		t.Fatal("an unconfirmed expired CLEAN was kept")
	}
	if got := listRules(s.cfg.ListPath); len(got) != 0 {
		t.Fatalf("list %v", got)
	}
}

// A blocked name confirmed again waits twice as long, and is not probed
// in between.
func TestCycleBlockedBacksOff(t *testing.T) {
	s := newScenario(t)
	s.st.put("n", "ads.example.org", &entry{Verdict: probe.BlockedTLS, TestedIP: "192.0.2.7",
		DecidedAt: time.Now().Add(-2 * time.Hour), ExpiresAt: time.Now().Add(-time.Minute),
		LastSeen: time.Now(), Endpoints: []string{"tcp/443"}})
	s.see(tunnelled("ads.example.org", 443))
	s.script("ads.example.org tcp/443", blockedTLS("192.0.2.7"))
	s.cycle()
	e := s.entry("ads.example.org")
	if e.Streak != 1 || time.Until(e.ExpiresAt) < 110*time.Minute {
		t.Fatalf("streak %d, next check in %s", e.Streak, time.Until(e.ExpiresAt).Round(time.Minute))
	}
	s.see(tunnelled("ads.example.org", 443))
	s.cycle()
	if s.wasProbed("ads.example.org tcp/443") {
		t.Fatal("probed again before its term")
	}
}

// Three CLEAN hosts make their domain go direct whole; one whose direct path
// is down breaks it -- a family must not sweep a broken host direct.
func TestCycleFamily(t *testing.T) {
	s := newScenario(t)
	for i := 1; i <= 3; i++ {
		h := fmt.Sprintf("h%d.famtest.org", i)
		s.see(tunnelled(h, 443))
		s.script(h+" tcp/443", clean(fmt.Sprintf("192.0.2.%d", 10+i)))
		s.cycle()
	}
	if got := listRules(s.cfg.ListPath); !slices.Contains(got, "+.famtest.org") {
		t.Fatalf("no family in %v", got)
	}
	s.see(tunnelled("h4.famtest.org", 443))
	s.script("h4.famtest.org tcp/443", probe.Report{Verdict: probe.Inconcl, TestedIP: "192.0.2.14",
		Reason: "direct path fails", Direct: tcpFails, Tunnel: tlsCut})
	s.cycle()
	if got := listRules(s.cfg.ListPath); slices.Contains(got, "+.famtest.org") {
		t.Fatalf("the family held with a broken host: %v", got)
	}
}

// Three names in a row whose IPv6 node the direct path does not reach: the
// network has no IPv6 direct, and the next IPv6 probe is told so.
func TestCycleLearnsNoIPv6(t *testing.T) {
	s := newScenario(t)
	miss := func(ip string) probe.Report {
		return probe.Report{Verdict: probe.Inconcl, DirectNoV6: true, TestedIP: ip,
			Reason: "IPv6 node the direct path does not reach", Direct: tlsCut, Tunnel: pathOK}
	}
	var conns []connection
	for i := 1; i <= 3; i++ {
		h := fmt.Sprintf("v6-%d.example.net", i)
		conns = append(conns, tunnelled(h, 443))
		s.script(h+" tcp/443", miss(fmt.Sprintf("2001:db8::%d", i)))
	}
	s.see(conns...)
	s.cycle()
	if !s.st.directNoV6("n") {
		t.Fatal("not learned")
	}
	s.see(tunnelled("v6-4.example.net", 443))
	s.script("v6-4.example.net tcp/443", miss("2001:db8::4"))
	s.cycle()
	if !s.noV6["v6-4.example.net tcp/443"] {
		t.Fatal("the next probe was not told the direct path has no IPv6")
	}
}

// A probe the core's restart cut short leaves memory alone.
func TestCycleAbortedLeavesMemory(t *testing.T) {
	s := newScenario(t)
	s.see(tunnelled("r.example.org", 443))
	s.script("r.example.org tcp/443", probe.Report{Verdict: probe.Inconcl, Aborted: true})
	s.cycle()
	if e := s.entry("r.example.org"); e != nil {
		t.Fatalf("an aborted probe was remembered: %s", e.Verdict)
	}
	// the core is back, and no connection shows the name again: it is
	// checked all the same -- drain had let go of it, and it was lost
	s.see()
	s.script("r.example.org tcp/443", clean("192.0.2.64"))
	s.cycle()
	if e := s.entry("r.example.org"); e == nil || e.Verdict != probe.Clean {
		t.Fatalf("the name cut short was not checked again: %v", e)
	}
}

// "Everything via tunnel" from the tray drops every verdict and empties both
// lists -- and the next cycle does not write the old rules back, as it did
// when the tray emptied a file behind the controller's back.
func TestCycleResetFromTray(t *testing.T) {
	s := newScenario(t)
	s.cfg.ResetPath = filepath.Join(t.TempDir(), "reset.request")
	s.see(tunnelled("a.example.org", 443), tunnelled("speed.example.org", 20000))
	s.script("a.example.org tcp/443", clean("192.0.2.1"))
	s.script("speed.example.org tcp/20000", cleanTCP("192.0.2.4"))
	s.cycle()
	if len(listRules(s.cfg.ListPath)) == 0 || len(listRules(s.cfg.AddrListPath)) == 0 {
		t.Fatal("setup: the lists were not written")
	}
	if takeReset(s.cfg, s.api, s.st) {
		t.Fatal("a reset without a request")
	}
	if err := os.WriteFile(s.cfg.ResetPath, []byte("now"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !takeReset(s.cfg, s.api, s.st) {
		t.Fatal("the request was not taken")
	}
	if _, err := os.Stat(s.cfg.ResetPath); !os.IsNotExist(err) {
		t.Fatal("the request was left behind: the tray would wait in vain")
	}
	check := func(when string) {
		t.Helper()
		if got := listRules(s.cfg.ListPath); len(got) != 0 {
			t.Fatalf("%s: names %v", when, got)
		}
		if got := listRules(s.cfg.AddrListPath); len(got) != 0 {
			t.Fatalf("%s: addresses %v", when, got)
		}
		if e := s.entry("a.example.org"); e != nil {
			t.Fatalf("%s: memory kept %s", when, e.Verdict)
		}
	}
	check("after the reset")
	s.cycle()
	check("a cycle later")
}

// A reset whose emptied memory could not be saved is not done: the old
// state file would bring every verdict back at the next start. The request
// stays, and the reset is done once the file can be written.
func TestResetNotSaved(t *testing.T) {
	s := newScenario(t)
	s.cfg.ResetPath = filepath.Join(t.TempDir(), "reset.request")
	s.see(tunnelled("a.example.org", 443))
	s.script("a.example.org tcp/443", clean("192.0.2.1"))
	s.cycle()
	if _, err := os.Stat(s.cfg.StatePath); err != nil {
		t.Fatalf("setup: no state file: %v", err)
	}
	// the state file cannot be replaced: a folder stands in its place
	if err := os.Remove(s.cfg.StatePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.cfg.StatePath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.cfg.ResetPath, []byte("now"), 0o644); err != nil {
		t.Fatal(err)
	}
	if takeReset(s.cfg, s.api, s.st) {
		t.Fatal("a reset not saved was taken as done")
	}
	if _, err := os.Stat(s.cfg.ResetPath); err != nil {
		t.Fatalf("the request went with the reset not saved: %v", err)
	}
	if err := os.Remove(s.cfg.StatePath); err != nil {
		t.Fatal(err)
	}
	if !takeReset(s.cfg, s.api, s.st) {
		t.Fatal("the reset was not done once the file could be written")
	}
	if _, err := os.Stat(s.cfg.ResetPath); !os.IsNotExist(err) {
		t.Fatal("the request was left behind")
	}
	if st := loadState(s.cfg.StatePath); len(st.Networks["n"]) != 0 {
		t.Fatalf("the saved state kept %d verdicts", len(st.Networks["n"]))
	}
}

// A name on more ports than a check takes is not called clean -- the ports
// beyond the cap were never probed -- and a CLEAN it had is not kept.
func TestCycleTooManyPorts(t *testing.T) {
	s := newScenario(t)
	var conns []connection
	for p := 1; p <= maxEndpoints+1; p++ {
		port := 5000 + p
		conns = append(conns, tunnelled("many.example.org", port))
		s.script(fmt.Sprintf("many.example.org tcp/%d", port), cleanTCP("192.0.2.20"))
	}
	s.see(conns...)
	s.cycle()
	if e := s.entry("many.example.org"); e.Verdict != probe.Inconcl {
		t.Fatalf("verdict %s (%s)", e.Verdict, e.Reason)
	}
	if got := listRules(s.cfg.ListPath); len(got) != 0 {
		t.Fatalf("list %v", got)
	}

	// a CLEAN from before, due again, now seen on one port more
	var stored []string
	for p := 1; p <= maxEndpoints; p++ {
		stored = append(stored, fmt.Sprintf("tcp/%d", 6000+p))
		s.script(fmt.Sprintf("was.example.org tcp/%d", 6000+p), cleanTCP("192.0.2.21"))
	}
	s.st.put("n", "was.example.org", &entry{Verdict: probe.Clean, TestedIP: "192.0.2.21",
		DecidedAt: time.Now().Add(-8 * 24 * time.Hour), ExpiresAt: time.Now().Add(-time.Minute),
		LastSeen: time.Now(), Endpoints: stored})
	s.see(tunnelled("was.example.org", 7000))
	s.script("was.example.org tcp/7000", cleanTCP("192.0.2.21"))
	s.cycle()
	if e := s.entry("was.example.org"); e.Verdict == probe.Clean {
		t.Fatalf("a CLEAN with an unprobed port was kept: %s", e.Reason)
	}
}

// A changed blocked re-check reaches verdicts already made; a save that
// changes something else moves no term -- a CLEAN measured slower once
// keeps its short one.
func TestSettingsMoveTerms(t *testing.T) {
	s := newScenario(t)
	now := time.Now()
	s.st.put("n", "blocked.example.org", &entry{Verdict: probe.BlockedTLS,
		DecidedAt: now, ExpiresAt: now.Add(time.Hour)})
	s.st.put("n", "slow.example.org", &entry{Verdict: probe.Clean, SlowOnce: true,
		DecidedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)})

	set := DefaultSettings()
	set.AutoSwitch = true
	cfg := set.apply(s.cfg)

	// something else changed: nothing moves
	other := set
	other.Attempts = 5
	cfg = onSettingsChanged(cfg, other, s.api, s.st, "n")
	if e := s.entry("blocked.example.org"); !e.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("an unrelated save moved a blocked term to %s", e.ExpiresAt)
	}

	// the blocked re-check shortened: the waiting verdict follows
	short := other
	short.FailTTLMin = 5
	onSettingsChanged(cfg, short, s.api, s.st, "n")
	if e := s.entry("blocked.example.org"); !e.ExpiresAt.Equal(now.Add(5 * time.Minute)) {
		t.Fatalf("blocked term %s, want the new five minutes", e.ExpiresAt.Sub(now))
	}
	if e := s.entry("slow.example.org"); !e.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("a CLEAN measured slower once lost its short term: %s", e.ExpiresAt.Sub(now))
	}
}

// Families on a mixed CDN: three clean hosts make the domain go direct
// whole only when no host of it is known bad.
func TestCycleFamilyMixed(t *testing.T) {
	// three CLEAN hosts of a domain, and one more with what it is given
	build := func(t *testing.T, domain string, fourth probe.Report) *scenario {
		t.Helper()
		s := newScenario(t)
		var conns []connection
		for i := 1; i <= 3; i++ {
			h := fmt.Sprintf("h%d.%s", i, domain)
			conns = append(conns, tunnelled(h, 443))
			s.script(h+" tcp/443", clean(fmt.Sprintf("192.0.2.%d", 30+i)))
		}
		h4 := "h4." + domain
		conns = append(conns, tunnelled(h4, 443))
		s.script(h4+" tcp/443", fourth)
		s.see(conns...)
		s.cycle()
		return s
	}
	family := func(s *scenario, domain string) bool {
		return slices.Contains(listRules(s.cfg.ListPath), "+."+domain)
	}

	t.Run("a blocked host", func(t *testing.T) {
		s := build(t, "cdn-a.net", blockedTLS("192.0.2.40"))
		if family(s, "cdn-a.net") {
			t.Fatal("a family with a blocked host")
		}
		if slices.Contains(listRules(s.cfg.ListPath), "h4.cdn-a.net") {
			t.Fatal("the blocked host went direct")
		}
	})
	t.Run("an IPv6-only host", func(t *testing.T) {
		s := build(t, "cdn-b.net", probe.Report{Verdict: probe.Inconcl, DirectNoV6: true,
			TestedIP: "2001:db8::40", Reason: "IPv6 node the direct path does not reach",
			Direct: tlsCut, Tunnel: pathOK})
		if family(s, "cdn-b.net") {
			t.Fatal("a family swept an IPv6-only host direct")
		}
	})
	t.Run("a host dead on both paths", func(t *testing.T) {
		// the server's own failure says nothing about the direct path: the
		// family holds, and the host fails direct as it fails everywhere
		s := build(t, "cdn-c.net", probe.Report{Verdict: probe.Inconcl, TestedIP: "192.0.2.41",
			Reason: "fails the same on both paths: tls: EOF", Direct: tlsCut, Tunnel: tlsCut})
		if !family(s, "cdn-c.net") {
			t.Fatal("a host dead everywhere broke the family")
		}
	})
	t.Run("a clean host past its term", func(t *testing.T) {
		s := build(t, "cdn-d.net", clean("192.0.2.42"))
		if !family(s, "cdn-d.net") {
			t.Fatal("setup: no family from four clean hosts")
		}
		// two of them past their term and no longer in use, so not re-checked
		s.see()
		for _, h := range []string{"h1.cdn-d.net", "h2.cdn-d.net"} {
			e := s.entry(h)
			e.ExpiresAt = time.Now().Add(-time.Minute)
			e.LastSeen = time.Now().Add(-48 * time.Hour)
		}
		s.cycle()
		if family(s, "cdn-d.net") {
			t.Fatal("expired CLEANs kept the family")
		}
	})
	t.Run("a host sent direct by the family turns out blocked", func(t *testing.T) {
		s := build(t, "cdn-e.net", clean("192.0.2.43"))
		if !family(s, "cdn-e.net") {
			t.Fatal("setup: no family")
		}
		// a new host, direct by the family rule alone, gets its own check
		s.see(via("h9.cdn-e.net", 443, "tcp", "DIRECT", "RuleSet", "direct-verified"))
		s.script("h9.cdn-e.net tcp/443", blockedTLS("192.0.2.49"))
		s.cycle()
		if family(s, "cdn-e.net") {
			t.Fatal("the family held after a host of it was found blocked")
		}
		if slices.Contains(listRules(s.cfg.ListPath), "h9.cdn-e.net") {
			t.Fatal("the blocked host is still direct")
		}
	})
}

// More new names than a cycle takes: the rest wait for the next cycles, in
// the order they turned up, and none is lost -- they used to be dropped,
// and a name requested once was never probed.
func TestCycleBacklog(t *testing.T) {
	s := newScenario(t)
	s.cfg.PerCycle = 5
	var conns []connection
	var names []string
	for i := 1; i <= 12; i++ {
		h := fmt.Sprintf("n%02d.backlog.org", i)
		names = append(names, h)
		conns = append(conns, tunnelled(h, 443))
		s.script(h+" tcp/443", clean(fmt.Sprintf("192.0.2.%d", 100+i)))
	}
	s.see(conns...)
	for c, want := range [][]string{names[0:5], names[5:10], names[10:12]} {
		s.cycle()
		s.see() // the connections are gone: only the backlog remembers them
		s.mu.Lock()
		got := make([]string, 0, len(s.probed))
		for _, k := range s.probed {
			got = append(got, strings.TrimSuffix(k, " tcp/443"))
		}
		s.mu.Unlock()
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Fatalf("cycle %d probed %v, want %v", c+1, got, want)
		}
	}
	for _, h := range names {
		if s.entry(h) == nil {
			t.Fatalf("%s was never probed", h)
		}
	}
}

// The machine moves to another network while a cycle's probes run: what
// they measured is the new network's, and is not filed under the old one.
func TestCycleNetworkChangesMidway(t *testing.T) {
	s := newScenario(t)
	s.see(tunnelled("moved.example.org", 443))
	s.script("moved.example.org tcp/443", clean("192.0.2.60"))
	checkProto = func(direct, tunnel probe.Dialer, dom string, port, att int, udp bool, was probe.Verdict) probe.Report {
		s.where.Store("wifi-b") // the switch happens while the probe runs
		return s.check(direct, tunnel, dom, port, att, udp, was)
	}
	s.cycle()
	if e := s.entry("moved.example.org"); e != nil {
		t.Fatalf("a verdict measured on another network was filed: %s", e.Verdict)
	}
	if got := listRules(s.cfg.ListPath); len(got) != 0 {
		t.Fatalf("list %v", got)
	}

	// back on the first network, and staying there: the name is checked and
	// filed -- with no connection showing it again: the cycle gave it back
	checkProto = s.check
	s.where.Store("wifi-a")
	s.see()
	s.cycle()
	if e := s.entry("moved.example.org"); e == nil || e.Verdict != probe.Clean {
		t.Fatalf("verdict %v", e)
	}
}

// The verdicts are reset from the tray while a cycle's probes run: what they
// found does not come back into the memory the reset emptied.
func TestCycleResetMidway(t *testing.T) {
	s := newScenario(t)
	s.see(tunnelled("reset.example.org", 443))
	s.script("reset.example.org tcp/443", clean("192.0.2.62"))
	checkProto = func(direct, tunnel probe.Dialer, dom string, port, att int, udp bool, was probe.Verdict) probe.Report {
		s.st.resetVerdicts() // the reset lands while the probe runs
		return s.check(direct, tunnel, dom, port, att, udp, was)
	}
	s.cycle()
	if e := s.entry("reset.example.org"); e != nil {
		t.Fatalf("a probe started before the reset filed %s after it", e.Verdict)
	}
	if got := listRules(s.cfg.ListPath); len(got) != 0 {
		t.Fatalf("list %v", got)
	}
	// the name is checked again on the emptied memory
	checkProto = s.check
	s.see()
	s.cycle()
	if e := s.entry("reset.example.org"); e == nil || e.Verdict != probe.Clean {
		t.Fatalf("the name was not checked after the reset: %v", e)
	}
}

// The prober's own connections -- from loopback, through its listeners --
// are no use of a name: a re-check renewed LastSeen, and a name nothing went
// to was never forgotten. Nor are they candidates, or suspect direct ones.
func TestCycleProbeIsNoUse(t *testing.T) {
	s := newScenario(t)
	s.see(tunnelled("old.example.org", 443))
	s.script("old.example.org tcp/443", clean("192.0.2.61"))
	s.cycle()
	e := s.entry("old.example.org")
	if e == nil {
		t.Fatal("no verdict")
	}
	seen := time.Now().Add(-48 * time.Hour)
	e.LastSeen = seen

	byProbe := func(inbound, src string) connection {
		c := via("old.example.org", 443, "tcp", "DIRECT", "", "")
		c.Download = 0
		c.Metadata.SourceIP, c.Metadata.InboundName = src, inbound
		return c
	}
	s.see(byProbe("probe-direct", "127.0.0.1"), byProbe("", "127.0.0.1"), byProbe("probe-tunnel", "198.18.0.1"))
	if live := s.w.drainLive(); len(live) != 0 {
		t.Fatalf("probe connections counted as use: %v", live)
	}
	s.see(byProbe("probe-direct", "127.0.0.1"))
	s.cycle()
	if s.wasProbed("old.example.org tcp/443") {
		t.Fatal("a probe connection made its name suspect")
	}
	if got := s.entry("old.example.org").LastSeen; !got.Equal(seen) {
		t.Fatalf("LastSeen renewed by the probe: %s", got)
	}
}

// The controller is stopping: a cycle starts no more probes, and files
// nothing -- the service's stop waits for it.
func TestCycleStopping(t *testing.T) {
	s := newScenario(t)
	stop := make(chan struct{})
	close(stop)
	s.cfg.stop = stop
	s.see(tunnelled("stop.example.org", 443))
	s.script("stop.example.org tcp/443", clean("192.0.2.63"))
	s.cycle()
	if s.wasProbed("stop.example.org tcp/443") {
		t.Fatal("probed while stopping")
	}
	if e := s.entry("stop.example.org"); e != nil {
		t.Fatalf("filed %s while stopping", e.Verdict)
	}
}

// Observe only: everything the lists leave goes direct by the catch-all,
// and is probed. What a list the core reads pins to a tunnel stays pinned
// -- it goes through the tunnel in observe only too; a second tunnel
// switched off writes its files empty, and what they named is probed then.
func TestCycleObserveAll(t *testing.T) {
	s := newScenario(t)
	s.cfg.Apply = false
	s.cfg.mode = new(atomic.Value)
	s.cfg.setMode(ModeObserve)
	s.see(via("claude.ai", 443, "tcp", "awg2", "RuleSet", PresetsProvider),
		via("o.example.org", 443, "tcp", "DIRECT", "RuleSet", ObserveProvider))
	s.script("claude.ai tcp/443", blockedTLS("192.0.2.70"))
	s.script("o.example.org tcp/443", clean("192.0.2.71"))
	s.cycle()
	if s.wasProbed("claude.ai tcp/443") {
		t.Fatal("observe only probed a name a list pins")
	}
	if !s.wasProbed("o.example.org tcp/443") {
		t.Fatal("observe only left a name unprobed")
	}
	if got := listRules(s.cfg.ListPath); got != nil {
		t.Fatalf("observe only wrote the list: %v", got)
	}
	// the second tunnel switched off: its file empty, the name goes direct
	// by the catch-all, and is measured
	if err := os.WriteFile(s.cfg.PinnedLists[0], awg2OffBody, 0o644); err != nil {
		t.Fatal(err)
	}
	s.see(via("claude.ai", 443, "tcp", "DIRECT", "RuleSet", ObserveProvider))
	s.cycle()
	if e := s.entry("claude.ai"); e == nil || e.Verdict != probe.BlockedTLS {
		t.Fatalf("name no list pins not filed: %v", e)
	}
}

// A verdict dropped from the verdicts page: the name leaves the list and
// memory, the others stay, the request goes -- and the next cycle does not
// write the name back. "+." drops a whole domain.
func TestForgetFromUI(t *testing.T) {
	s := newScenario(t)
	dir := t.TempDir()
	s.cfg.ForgetPath = filepath.Join(dir, "forget-*.request")
	s.st.setCurrent("n")
	s.see(tunnelled("a.example.org", 443), tunnelled("b.example.org", 443), tunnelled("c.example.net", 443))
	s.script("a.example.org tcp/443", clean("192.0.2.1"))
	s.script("b.example.org tcp/443", clean("192.0.2.2"))
	s.script("c.example.net tcp/443", clean("192.0.2.3"))
	s.cycle()
	if !slices.Contains(listRules(s.cfg.ListPath), "a.example.org") {
		t.Fatalf("setup: list %v", listRules(s.cfg.ListPath))
	}
	ask := func(lines string) string {
		t.Helper()
		p := filepath.Join(dir, "forget-"+strconv.Itoa(len(lines))+".request")
		if err := os.WriteFile(p, []byte(lines), 0o644); err != nil {
			t.Fatal(err)
		}
		takeForget(s.cfg, s.api, s.st)
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatal("the request was left behind: the UI would wait in vain")
		}
		return p
	}
	ask("A.example.org\n# a comment\nnot a name\n")
	if e := s.entry("a.example.org"); e != nil {
		t.Fatalf("memory kept %s", e.Verdict)
	}
	if got := listRules(s.cfg.ListPath); slices.Contains(got, "a.example.org") || !slices.Contains(got, "b.example.org") {
		t.Fatalf("list after the drop: %v", got)
	}
	s.cycle()
	if slices.Contains(listRules(s.cfg.ListPath), "a.example.org") {
		t.Fatal("a cycle wrote the name dropped back without checking it")
	}
	ask("+.example.org\n")
	for _, d := range []string{"a.example.org", "b.example.org"} {
		if e := s.entry(d); e != nil {
			t.Fatalf("%s stayed after its whole domain was dropped: %s", d, e.Verdict)
		}
	}
	if got := listRules(s.cfg.ListPath); !slices.Equal(got, []string{"c.example.net"}) {
		t.Fatalf("list after the whole domain went: %v", got)
	}
	if e := s.entry("c.example.net"); e == nil {
		t.Fatal("another domain's verdict went too")
	}

	// a request that is another file's second name is not read -- the
	// service would read, as SYSTEM, what the user may not -- and goes;
	// the file it names stays as it was
	other := filepath.Join(dir, "other.txt")
	if err := os.WriteFile(other, []byte("c.example.net\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "forget-link.request")
	if err := os.Link(other, link); err != nil {
		t.Fatal(err)
	}
	takeForget(s.cfg, s.api, s.st)
	if e := s.entry("c.example.net"); e == nil {
		t.Fatal("a request through a second name was read")
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatal("the refused request was left behind")
	}
	if b, err := os.ReadFile(other); err != nil || string(b) != "c.example.net\n" {
		t.Fatalf("the file it named was touched: %q %v", b, err)
	}
}
