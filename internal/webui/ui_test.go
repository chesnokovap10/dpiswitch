package webui

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
	"dpiswitch/internal/probe"
)

// testServer: the UI over an empty data directory, with a fixed status --
// the real one asks the service manager and the core.
func testServer(t *testing.T) (*Server, string) {
	t.Helper()
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	// no core: on a machine running the service 127.0.0.1:9090 is the live
	// one, and a list saved here would reload its providers and close its
	// connections. A port just closed refuses the dial, as with no core.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	old := apiAddr
	apiAddr = l.Addr().String()
	l.Close()
	t.Cleanup(func() { apiAddr = old })
	// and no service: the machine's real one must not be waited on
	was := serviceRunning
	serviceRunning = func() bool { return false }
	t.Cleanup(func() { serviceRunning = was })
	s := &Server{statusFn: func() status {
		return status{Installed: true, PathOK: true, ServiceRun: true, TunnelAlive: true, TunnelNote: "60 ms",
			Awg2: true, Version: "test", DataDir: paths.DataDir(), NetworkID: "AS1", Mode: ctl.ModeOn}
	}}
	return s, paths.DataDir()
}

func do(t *testing.T, h http.Handler, method, target string, form url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if form != nil {
		r = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	r.Host = "127.0.0.1:8080"
	r.Header.Set("Referer", "http://127.0.0.1:8080/settings")
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// Every page and every part a page refreshes renders in both languages.
func TestPagesRender(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	frags := map[string][]string{
		"overview": {"summary", "events"},
		"verdicts": {"tabs", "table", "vnote"},
		"lists":    {"list-direct", "list-tunnel", "list-block"},
		"awg2":     {"awg2state", "presets", "list-awg2"},
		"settings": {"form", "dns"},
		"logs":     {"log"},
	}
	for _, lang := range []string{"en", "ru"} {
		cookie := map[string]string{"Cookie": "lang=" + lang}
		for _, p := range pageNames {
			for _, target := range []string{"/" + p, "/verdicts?cat=blocked&q=x"} {
				if target != "/"+p && p != "verdicts" {
					continue
				}
				w := do(t, h, "GET", target, nil, cookie)
				body := w.Body.String()
				if w.Code != 200 || strings.Contains(body, `class="msg bad"`) || !strings.Contains(body, "</html>") {
					t.Errorf("%s %s: %d\n%s", lang, target, w.Code, body)
				}
			}
			for _, f := range append(frags[p], "header", "navitems", "svcbox") {
				w := do(t, h, "GET", "/frag/"+p+"/"+f, nil, cookie)
				if w.Code != 200 || strings.Contains(w.Body.String(), `class="msg bad"`) {
					t.Errorf("%s %s/%s: %d %s", lang, p, f, w.Code, w.Body.String())
				}
			}
		}
	}
	if w := do(t, h, "GET", "/nope", nil, nil); w.Code != 404 {
		t.Errorf("an unknown page: %d", w.Code)
	}
}

// Every string the UI shows has its Russian: in the templates, the Go code
// that answers the forms, and the preset names.
func TestTranslations(t *testing.T) {
	var keys []string
	add := func(re *regexp.Regexp, text string) {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			for _, k := range m[1:] {
				if k != "" {
					// the keys are Go strings in the source: \n and \" as written there
					if u, err := strconv.Unquote(`"` + k + `"`); err == nil {
						k = u
					}
					keys = append(keys, k)
				}
			}
		}
	}
	tmplKey := regexp.MustCompile(`\.(?:T|TH|Tf) "((?:[^"\\]|\\.)*)"`)
	err := fs.WalkDir(uiFS, "tmpl", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := uiFS.ReadFile(path)
		add(tmplKey, string(b))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	goKey := regexp.MustCompile(`(?:v\.Tf?\(|tr\(lang\(r\), |done\(r, [a-z]+, |redirect\(w, r, [^,"]+, )"([^"]+)"|note = "([^"]+)"|return "(Config[^"]+)"|\{\d+, "([^"]+)"\}`)
	for _, f := range []string{"actions.go", "ui.go", "pages.go", "live.go", "entries.go", "presets.go", "livemenu.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		add(goKey, string(b))
	}
	// the tray speaks the pages' language, from the same table
	trayKey := regexp.MustCompile(`\bT\("((?:[^"\\]|\\.)*)"\)`)
	for _, f := range []string{"main.go", "install.go", "remove.go"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "cmd", "dpiswitch", f))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range trayKey.FindAllStringSubmatch(string(b), -1) {
			k, err := strconv.Unquote(`"` + m[1] + `"`)
			if err != nil {
				t.Fatal(err)
			}
			keys = append(keys, k)
		}
	}
	for _, p := range presets.Builtin() {
		keys = append(keys, p.Title, p.Note)
	}
	if len(keys) < 150 {
		t.Fatalf("only %d strings found: the patterns no longer match the code", len(keys))
	}
	for _, k := range keys {
		if _, ok := ru[k]; !ok {
			t.Errorf("no Russian for %q", k)
		}
	}
}

// A setting applies the moment its control changes, one field at a time:
// the others -- the presets among them -- stay as they were.
func TestSettingInstant(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	set := ctl.DefaultSettings()
	set.Awg2Presets = []string{"youtube"}
	if err := ctl.SaveSettings(paths.Settings(), set); err != nil {
		t.Fatal(err)
	}
	post := func(field, value string) string {
		w := do(t, h, "POST", "/act/set", url.Values{"field": {field}, "value": {value}}, nil)
		if w.Code != 200 {
			t.Fatalf("%s=%s: %d %s", field, value, w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	post("attempts", "5")
	post("auto_switch", "tunnel")
	got := ctl.LoadSettings(paths.Settings())
	if got.Attempts != 5 || got.Mode() != ctl.ModeTunnel || len(got.Awg2Presets) != 1 {
		t.Fatalf("after two changes: %+v", got)
	}
	// the header's buttons, and "0" and "off" from a page served by 1.4.2 or
	// before, where off kept everything in the tunnel: tunnel only now
	for _, c := range []struct{ path, field, value, want string }{
		{"/act/auto", "", "on", ctl.ModeOn},
		{"/act/auto", "", "observe", ctl.ModeObserve},
		{"/act/auto", "", "off", ctl.ModeTunnel},
		{"/act/set", "auto_switch", "1", ctl.ModeOn},
		{"/act/set", "auto_switch", "0", ctl.ModeTunnel},
		{"/act/auto", "", "on", ctl.ModeOn},
		{"/act/auto", "", "tunnel", ctl.ModeTunnel},
	} {
		if w := do(t, h, "POST", c.path, url.Values{"field": {c.field}, "value": {c.value}}, nil); w.Code != 200 {
			t.Fatalf("%s %s: %d", c.path, c.value, w.Code)
		}
		if got := ctl.LoadSettings(paths.Settings()).Mode(); got != c.want {
			t.Fatalf("%s %s: mode %s, want %s", c.path, c.value, got, c.want)
		}
	}
	if body := post("auto_switch", "nope"); !strings.Contains(body, `msg bad`) {
		t.Fatalf("an unknown mode was not refused:\n%s", body)
	}
	// a re-check past the pause cap raises the cap instead of being refused
	post("fail_ttl_min", "4320")
	if got := ctl.LoadSettings(paths.Settings()); got.FailTTLMin != 4320 || got.MaxBackoffMin != 4320 {
		t.Fatalf("the cap did not follow: %+v", got)
	}
	// a cap below the re-check is refused, and the file keeps its value
	if body := post("max_backoff_min", "60"); !strings.Contains(body, `msg bad`) {
		t.Fatalf("a cap below the re-check was not refused:\n%s", body)
	}
	if got := ctl.LoadSettings(paths.Settings()); got.MaxBackoffMin != 4320 {
		t.Fatalf("a refused change was saved: %+v", got)
	}
	if w := do(t, h, "POST", "/act/set", url.Values{"field": {"nope"}, "value": {"1"}}, nil); w.Code != 400 {
		t.Fatalf("an unknown setting: %d", w.Code)
	}
}

// A term offers only what the settings take: the blocked re-check once
// offered 30 days, which was always refused, and the pause cap offers
// nothing below the re-check. A value set by hand is among the choices.
func TestSettingsTerms(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	set := ctl.DefaultSettings()
	set.FailTTLMin, set.MaxBackoffMin = 7, 180
	if err := ctl.SaveSettings(paths.Settings(), set); err != nil {
		t.Fatal(err)
	}
	body := do(t, h, "GET", "/settings", nil, nil).Body.String()
	options := func(name string) []int {
		m := regexp.MustCompile(`(?s)<select[^>]*name="` + name + `">(.*?)</select>`).FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("no %s select:\n%s", name, body)
		}
		var out []int
		for _, v := range regexp.MustCompile(`value="(\d+)"`).FindAllStringSubmatch(m[1], -1) {
			n, _ := strconv.Atoi(v[1])
			out = append(out, n)
		}
		return out
	}
	for _, c := range []struct {
		name   string
		lo, hi int
		has    int
	}{
		{"clean_ttl_min", 10, 43200, 10080},
		{"fail_ttl_min", 5, 10080, 7},
		{"max_backoff_min", 7, 43200, 180},
	} {
		opts := options(c.name)
		found := false
		for _, n := range opts {
			if n < c.lo || n > c.hi {
				t.Errorf("%s offers %d, outside %d..%d", c.name, n, c.lo, c.hi)
			}
			found = found || n == c.has
		}
		if !found {
			t.Errorf("%s: %d not among %v", c.name, c.has, opts)
		}
	}
	// every choice offered is taken
	for _, name := range []string{"clean_ttl_min", "fail_ttl_min", "max_backoff_min"} {
		for _, n := range options(name) {
			w := do(t, h, "POST", "/act/set", url.Values{"field": {name}, "value": {strconv.Itoa(n)}}, nil)
			if strings.Contains(w.Body.String(), "msg bad") {
				t.Errorf("%s=%d offered but refused", name, n)
			}
			if err := ctl.SaveSettings(paths.Settings(), set); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// A DNS save refused keeps what was typed, and says why in the page's
// language; the core restart is announced only when there is one.
func TestDNSSave(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	ru := map[string]string{"Cookie": "lang=ru"}
	typed := "https://77.88.8.8/dns-query\nudp://9.9.9.9:99999"
	w := do(t, h, "POST", "/act/dns", url.Values{"direct_dns": {typed}, "tunnel_dns": {"10.8.0.1"}}, ru)
	body := w.Body.String()
	if !strings.Contains(body, "msg bad") || !strings.Contains(body, "неверный порт") {
		t.Fatalf("the refusal is not said in Russian:\n%s", body)
	}
	if !strings.Contains(body, "udp://9.9.9.9:99999</textarea>") || !strings.Contains(body, ">10.8.0.1</textarea>") {
		t.Fatalf("what was typed is lost:\n%s", body)
	}
	if got := ctl.LoadSettings(paths.Settings()); len(got.TunnelDNS) != 0 {
		t.Fatalf("a refused save was written: %+v", got)
	}
	// the same in the DNS test
	w = do(t, h, "POST", "/act/dnstest?path=direct", url.Values{"direct_dns": {"quic://1.1.1.1"}}, ru)
	if !strings.Contains(w.Body.String(), "поддерживаются только") {
		t.Fatalf("the test's reason is not in Russian:\n%s", w.Body.String())
	}

	restart := "the core restarts"
	save := func(direct string) string {
		return do(t, h, "POST", "/act/dns", url.Values{"direct_dns": {direct}, "tunnel_dns": {""}}, nil).Body.String()
	}
	def := strings.Join(ctl.DefaultSettings().DirectDNS, "\n")
	if b := save(def); strings.Contains(b, restart) || !strings.Contains(b, "msg ok") {
		t.Fatalf("a save changing nothing announced a restart:\n%s", b)
	}
	if b := save("tls://77.88.8.1"); !strings.Contains(b, restart) {
		t.Fatalf("a change did not announce the restart:\n%s", b)
	}
	// IPv6 goes into the core too
	ipv6 := func(v string) string {
		return do(t, h, "POST", "/act/set", url.Values{"field": {"ipv6"}, "value": {v}}, nil).Body.String()
	}
	if b := ipv6("0"); !strings.Contains(b, restart) {
		t.Fatalf("IPv6 switched did not announce the restart:\n%s", b)
	}
	if b := ipv6("0"); strings.Contains(b, restart) {
		t.Fatalf("IPv6 left as it was announced a restart:\n%s", b)
	}
	// defaults put the DNS back: that restarts the core too
	if w := do(t, h, "POST", "/act/defaults", url.Values{}, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("defaults: %d", w.Code)
	}
	if b := do(t, h, "GET", "/settings", nil, nil).Body.String(); !strings.Contains(b, "Settings reset to defaults: "+restart) {
		t.Fatalf("defaults changing the DNS did not announce the restart:\n%s", b)
	}
	// a stopped service restarts nothing
	st := s.statusFn()
	st.ServiceRun = false
	s.statusFn = func() status { return st }
	if b := save("tls://77.88.8.1"); strings.Contains(b, restart) || !strings.Contains(b, "msg ok") {
		t.Fatalf("a stopped service announced a restart:\n%s", b)
	}
}

// Each reason a DNS address is refused for has its Russian.
func TestResolverReasonsTranslated(t *testing.T) {
	for _, in := range []string{"", "udp://1.1.1.1 8.8.8.8", "quic://1.1.1.1", "udp://1.1.1.1:0", "https:///dns-query", "tls://1.1.1.1#x"} {
		_, err := probe.ParseResolver(in)
		var re *probe.ResolverError
		if !errors.As(err, &re) {
			t.Errorf("%q: %v, not a ResolverError", in, err)
			continue
		}
		if _, ok := ru[re.Why]; !ok {
			t.Errorf("%q: no Russian for %q", in, re.Why)
		}
	}
}

// The verdict tables: a row is found by what it shows, a name in Russian
// letters is shown in them, an expired verdict nothing uses is not "due
// now", the filter survives the tables' own refresh, and the mode that sets
// the verdicts aside is said.
func TestVerdictsPage(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	now := time.Now()
	e := func(v string, expires, seen time.Duration) map[string]any {
		return map[string]any{"verdict": v, "decided_at": now.Add(-48 * time.Hour),
			"expires_at": now.Add(expires), "last_seen": now.Add(seen)}
	}
	day := 24 * time.Hour
	st := map[string]any{"current": "AS1", "networks": map[string]any{"AS1": map[string]any{
		"a.xn--e1afmkfd.xn--p1ai": e("CLEAN", day, 0),
		"b.xn--e1afmkfd.xn--p1ai": e("CLEAN", day, 0),
		"c.xn--e1afmkfd.xn--p1ai": e("CLEAN", day, 0),
		"idle.test":               e("BLOCKED_TLS", -time.Hour, -3*day),
		"busy.test":               e("BLOCKED_TCP", -time.Hour, -time.Minute),
	}}}
	b, _ := json.Marshal(st)
	if err := os.WriteFile(paths.State(), b, 0o644); err != nil {
		t.Fatal(err)
	}
	get := func(target string) string {
		w := do(t, h, "GET", target, nil, nil)
		if w.Code != 200 {
			t.Fatalf("%s: %d", target, w.Code)
		}
		// as the browser reads it: html/template writes "+" as "&#43;"
		return html.UnescapeString(w.Body.String())
	}
	body := get("/verdicts?q=" + url.QueryEscape("Пример"))
	if !strings.Contains(body, "(+.пример.рф)") || strings.Count(body, ".пример.рф)") != 4 {
		t.Fatalf("the Russian name is not found or not shown:\n%s", body)
	}
	// a whole domain by the "+." it is shown with
	body = get("/frag/verdicts/table?cat=direct&q=" + url.QueryEscape("+.xn--e1afmkfd"))
	if !strings.Contains(body, "+.xn--e1afmkfd.xn--p1ai") || strings.Contains(body, "a.xn--e1afmkfd") {
		t.Fatalf("the whole domain is not found by its +.:\n%s", body)
	}
	body = get("/frag/verdicts/table?cat=blocked")
	if !regexp.MustCompile(`(?s)idle\.test.*when next used`).MatchString(body) || strings.Count(body, "when next used") != 1 ||
		!regexp.MustCompile(`(?s)busy\.test.*due now`).MatchString(body) {
		t.Fatalf("idle and due verdicts:\n%s", body)
	}
	// the parts refresh with the filter as typed
	body = get("/verdicts?cat=blocked&q=" + url.QueryEscape("c++ 50%"))
	for _, part := range []string{"tabs", "table"} {
		if !strings.Contains(body, `data-poll="/frag/verdicts/`+part+`?cat=blocked&q=c%2B%2B+50%25"`) {
			t.Fatalf("%s: the filter is not in its address as typed:\n%s", part, body)
		}
	}
	// the mode that sets the verdicts aside
	for mode, want := range map[string]string{ctl.ModeOn: "", ctl.ModeObserve: "Observe only is on", ctl.ModeTunnel: "Tunnel only is on"} {
		st := s.statusFn()
		st.Mode, st.HasConfig = mode, true
		s.statusFn = func() status { return st }
		note := get("/frag/verdicts/vnote")
		if want == "" && strings.TrimSpace(note) != "" || want != "" && !strings.Contains(note, want) {
			t.Errorf("%s: note %q", mode, note)
		}
		if want != "" && !strings.Contains(get("/verdicts"), want) {
			t.Errorf("%s: the page has no note", mode)
		}
	}
}

// A reset asked for while the service is stopped waits for it to start, as
// the tray's does: its verdicts are applied when it does.
func TestResetStopped(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	if w := do(t, h, "POST", "/act/reset", url.Values{}, map[string]string{"Referer": "http://127.0.0.1:8080/verdicts"}); w.Code != http.StatusSeeOther {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(paths.ResetRequest()); err != nil {
		t.Fatalf("no request left: %v", err)
	}
	if b := do(t, h, "GET", "/verdicts", nil, nil).Body.String(); !strings.Contains(b, "the service takes it when it starts") {
		t.Fatalf("the page does not say the reset waits:\n%s", b)
	}
}

// The overview: a config counts as loaded when the user's .conf is there,
// whatever the service has built; the tunnel's DNS is the one in use; a
// tunnel's state says what the service is doing; the mode that sets the
// verdicts aside is said under their counts.
func TestOverview(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	if st := collectStatus(); st.HasConfig {
		t.Fatal("a config loaded with none there")
	}
	conf := "[Interface]\nPrivateKey = AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.8.1.3/32\nDNS = 10.8.1.1\n" +
		"[Peer]\nPublicKey = cA==\nEndpoint = vpn.example.org:51820\n"
	if err := os.WriteFile(paths.SourceConf(), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(paths.Config()); err == nil {
		t.Fatal("setup: the service's config.yaml is there")
	}
	if st := collectStatus(); !st.HasConfig || st.Endpoint != "vpn.example.org:51820" {
		t.Fatalf("the .conf loaded, the service not started: has config %v, endpoint %q", st.HasConfig, st.Endpoint)
	}

	base := s.statusFn()
	base.HasConfig = true
	with := func(f func(*status)) string {
		st := base
		f(&st)
		s.statusFn = func() status { return st }
		return do(t, h, "GET", "/overview", nil, nil).Body.String()
	}
	body := with(func(*status) {})
	if strings.Contains(body, "Getting started") || !strings.Contains(body, "10.8.1.1") || strings.Contains(body, "from the settings") {
		t.Fatalf("the .conf's DNS:\n%s", body)
	}
	set := ctl.DefaultSettings()
	set.TunnelDNS = []string{"tls://9.9.9.9"}
	if err := ctl.SaveSettings(paths.Settings(), set); err != nil {
		t.Fatal(err)
	}
	if body := with(func(*status) {}); !strings.Contains(body, "tls://9.9.9.9") || strings.Contains(body, "10.8.1.1") ||
		!strings.Contains(body, "from the settings") {
		t.Fatalf("the settings' tunnel DNS is not the one shown:\n%s", body)
	}
	for want, f := range map[string]func(*status){
		"service not installed": func(st *status) { st.Installed, st.ServiceRun = false, false },
		`pill warn">starting…`:  func(st *status) { st.ServiceRun, st.Pending, st.ServiceText = false, true, "starting" },
		"service stopped":       func(st *status) { st.ServiceRun = false },
		"Observe only is on":    func(st *status) { st.Mode = ctl.ModeObserve },
	} {
		if body := with(f); !strings.Contains(body, want) {
			t.Errorf("no %q:\n%s", want, body)
		}
	}
	if body := with(func(*status) {}); strings.Contains(body, "is on: the verdicts are recorded") {
		t.Error("a mode note with auto-switch on")
	}
}

// A list takes sites, addresses and programs in one box, each written the
// one way, once, sites first; the core gets each kind in a file of its own.
func TestListSave(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	in := strings.Join([]string{"Example.com", "https://sub.example.org/path", "", "+.example.net", "example.com",
		"192.168.12.0/16", "1.2.3.4", "Telegram.exe"}, "\n")
	w := do(t, h, "POST", "/act/list", url.Values{"kind": {"tunnel"}, "entries": {in}}, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "msg ok") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	want := []string{"+.example.net", "example.com", "sub.example.org", "1.2.3.4", "192.168.0.0/16", "Telegram.exe"}
	if got := readEntries(paths.TunnelList); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
	// the core reads the service's copies, made from the user's
	if ctl.Synced(paths.TunnelList) {
		t.Fatal("synced before the service ran")
	}
	ctl.SyncUserFiles()
	if !ctl.Synced(paths.TunnelList) {
		t.Fatal("not synced after the service ran")
	}
	for f, want := range map[string]string{
		paths.ForceTunnel():                         "+.example.net,example.com,sub.example.org",
		paths.Data(paths.IPList(paths.TunnelList)):  "1.2.3.4/32,192.168.0.0/16",
		paths.Data(paths.AppList(paths.TunnelList)): "PROCESS-NAME,Telegram.exe",
	} {
		if got := strings.Join(readList(f), ","); got != want {
			t.Errorf("%s: %s, want %s", f, got, want)
		}
	}

	// a program is added by name and saved at once, to any of the lists
	w = do(t, h, "POST", "/act/list", url.Values{"kind": {"block"}, "entries": {"a.exe"}, "add": {"b.exe"}, "op": {"add"}}, nil)
	if got := readEntries(paths.BlockList); strings.Join(got, ",") != "a.exe,b.exe" {
		t.Fatalf("forbidden %v: %s", got, w.Body.String())
	}
	w = do(t, h, "POST", "/act/list", url.Values{"kind": {"block"}, "entries": {"a.exe"}, "add": {""}, "op": {"add"}}, nil)
	if !strings.Contains(w.Body.String(), "msg bad") {
		t.Fatalf("an empty pick was not refused: %s", w.Body.String())
	}
	// a line of no kind refuses the save, and the list stays as it was
	w = do(t, h, "POST", "/act/list", url.Values{"kind": {"block"}, "entries": {"c.exe\nbad host"}}, nil)
	if !strings.Contains(w.Body.String(), "msg bad") || strings.Join(readEntries(paths.BlockList), ",") != "a.exe,b.exe" {
		t.Fatalf("a bad line was saved: %s", w.Body.String())
	}
	// and what was typed stays in the box to be fixed
	if !strings.Contains(w.Body.String(), "bad host</textarea>") {
		t.Fatalf("the typed lines were lost: %s", w.Body.String())
	}
	if w := do(t, h, "POST", "/act/list", url.Values{"kind": {"nope"}}, nil); w.Code != 400 {
		t.Fatalf("an unknown list: %d", w.Code)
	}
}

// A list the service would not read -- larger than it takes -- is refused,
// what was pasted kept in the box; it used to be saved, and never taken.
// A name in its own letters is kept as the core sees it, in punycode.
func TestListLimits(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	var big strings.Builder
	for i := 0; big.Len() <= ctl.UserListMax; i++ {
		fmt.Fprintf(&big, "s%07d.example.com\n", i)
	}
	w := do(t, h, "POST", "/act/list", url.Values{"kind": {"block"}, "entries": {big.String()}}, nil)
	if body := w.Body.String(); !strings.Contains(body, "msg bad") || !strings.Contains(body, "s0000000.example.com") {
		t.Fatalf("too large: %d %.300s", w.Code, body)
	}
	if _, err := os.Stat(paths.User(paths.BlockList)); err == nil {
		t.Fatal("a list too large was written")
	}
	w = do(t, h, "POST", "/act/list", url.Values{"kind": {"direct"}, "entries": {"госуслуги.рф\n+.пример.рф"}}, nil)
	if got := strings.Join(readEntries(paths.DirectList), ","); !strings.Contains(w.Body.String(), "msg ok") ||
		got != "+.xn--e1afmkfd.xn--p1ai,xn--c1aapkosapc.xn--p1ai" {
		t.Fatalf("names in their own letters: %q", got)
	}
}

// No mode sets a list aside: Tunnel only keeps Always direct, Observe only
// the always-tunnel list. The second tunnel starts off in Observe only, and
// its list says so.
func TestListModeNotes(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	st := s.statusFn()
	s.statusFn = func() status { return st }
	get := func(frag string) string { return do(t, h, "GET", "/frag/"+frag, nil, nil).Body.String() }
	for _, c := range []struct {
		mode, frag, want string
		said             bool
	}{
		// tunnel only keeps the direct list: its way out past the tunnels
		{ctl.ModeTunnel, "lists/list-direct", "is on:", false},
		{ctl.ModeTunnel, "lists/list-tunnel", "is on:", false},
		{ctl.ModeObserve, "lists/list-tunnel", "is on:", false},
		{ctl.ModeObserve, "lists/list-tunnel", "switched off", false},
		{ctl.ModeObserve, "awg2/list-awg2", "The second tunnel is switched off", true},
		{ctl.ModeObserve, "awg2/awg2state", "The second tunnel is switched off", true},
		{ctl.ModeOn, "awg2/list-awg2", "switched off", false},
		{ctl.ModeObserve, "lists/list-direct", "is on:", false},
		{ctl.ModeObserve, "lists/list-block", "is on:", false},
		{ctl.ModeOn, "lists/list-direct", "is on:", false},
		{ctl.ModeOn, "lists/list-tunnel", "is on:", false},
	} {
		st.Mode, st.Awg2, st.Awg2On = c.mode, true, c.mode != ctl.ModeObserve
		if got := strings.Contains(get(c.frag), c.want); got != c.said {
			t.Errorf("%s, %s: said %v, want %v", c.mode, c.frag, got, c.said)
		}
	}
}

// The programs' list of its own from before shows in the direct list, and
// goes with the direct list's first save.
func TestListOldApps(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	os.WriteFile(paths.User(paths.AppsList), []byte("PROCESS-NAME,wow.exe\n"), 0o644)
	if got := readEntries(paths.DirectList); strings.Join(got, ",") != "wow.exe" {
		t.Fatalf("old programs not shown: %v", got)
	}
	w := do(t, h, "POST", "/act/list", url.Values{"kind": {"direct"}, "entries": {"wow.exe\nbank.example"}}, nil)
	if !strings.Contains(w.Body.String(), "msg ok") {
		t.Fatalf("%s", w.Body.String())
	}
	if _, err := os.Stat(paths.User(paths.AppsList)); err == nil {
		t.Fatal("the old list is still there")
	}
	if got := readEntries(paths.DirectList); strings.Join(got, ",") != "bank.example,wow.exe" {
		t.Fatalf("after the save: %v", got)
	}
}

// With the service running, a saved list waits for the service to take it
// before the connections it moves are closed -- closed earlier, they would
// reconnect on the old rules -- and says so when it is not taken.
func TestListWaitsForService(t *testing.T) {
	s, _ := testServer(t)
	serviceRunning = func() bool { return true }
	syncWait = 300 * time.Millisecond
	t.Cleanup(func() { syncWait = 5 * time.Second })
	h := s.Handler()
	go func() {
		time.Sleep(20 * time.Millisecond)
		ctl.SyncUserFiles()
	}()
	w := do(t, h, "POST", "/act/list", url.Values{"kind": {"direct"}, "entries": {"a.example"}}, nil)
	if !strings.Contains(w.Body.String(), "msg ok") || !ctl.Synced(paths.DirectList) {
		t.Fatalf("not taken: %s", w.Body.String())
	}
	// no service to take it: the save is kept, the move is not claimed
	w = do(t, h, "POST", "/act/list", url.Values{"kind": {"direct"}, "entries": {"b.example"}}, nil)
	if !strings.Contains(w.Body.String(), "msg bad") || readEntries(paths.DirectList)[0] != "b.example" {
		t.Fatalf("an untaken save: %s", w.Body.String())
	}
}

// A change moves the open connections to what it names: a site by its
// name, an address only for a connection with none, a program by its name
// or path.
func TestEntryMatch(t *testing.T) {
	m := entryMatch([]string{"+.example.com", "10.1.0.0/16", "x.exe"})
	for c, want := range map[ctl.Conn]bool{
		{Host: "www.example.com"}:                   true,
		{Host: "example.org"}:                       false,
		{IP: "10.1.2.3"}:                            true,
		{Host: "a.example.org", IP: "10.1.2.3"}:     false,
		{IP: "10.2.0.1"}:                            false,
		{Host: "a.test", Process: "X.EXE"}:          true,
		{Host: "a.test", ProcessPath: `C:\y\x.exe`}: false,
	} {
		if got := m(c); got != want {
			t.Errorf("%+v: %v, want %v", c, got, want)
		}
	}
}

// Another web page cannot drive the UI: a form it sends to 127.0.0.1 names
// it in Origin, and DNS rebinding shows as another Host.
func TestGuard(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	form := url.Values{"field": {"attempts"}, "value": {"7"}}
	if w := do(t, h, "POST", "/act/set", form, map[string]string{"Origin": "https://evil.example"}); w.Code != 403 {
		t.Errorf("a cross-origin form: %d", w.Code)
	}
	if w := do(t, h, "POST", "/act/set", form, map[string]string{"Sec-Fetch-Site": "cross-site"}); w.Code != 403 {
		t.Errorf("a cross-site fetch: %d", w.Code)
	}
	r := httptest.NewRequest("GET", "/overview", nil)
	r.Host = "rebound.example:8080"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Errorf("another host: %d", w.Code)
	}
	if got := ctl.LoadSettings(paths.Settings()); got.Attempts == 7 {
		t.Error("a refused request changed the settings")
	}
	if w := do(t, h, "POST", "/act/set", form, map[string]string{"Origin": "http://127.0.0.1:8080"}); w.Code != 200 {
		t.Errorf("our own page: %d", w.Code)
	}
}

// The language switch goes back to the page it was pressed on, and nowhere
// else.
func TestLang(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	for back, want := range map[string]string{
		"/verdicts?cat=slow":   "/verdicts?cat=slow",
		"https://evil.example": "/overview",
		"//evil.example/x":     "/overview",
	} {
		w := do(t, h, "GET", "/lang?to=ru&back="+url.QueryEscape(back), nil, nil)
		if loc := w.Header().Get("Location"); loc != want {
			t.Errorf("back %q: went to %q, want %q", back, loc, want)
		}
		if c := w.Result().Cookies(); len(c) != 1 || c[0].Value != "ru" {
			t.Errorf("cookie %v", c)
		}
	}
}

// Changes sent at once all land: each control is its own request, and
// two served together used to read the same file, the second save undoing
// the first. The preset files follow the settings.
func TestSettingsAtOnce(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	all := presets.Load()
	var wg sync.WaitGroup
	send := func(path, field, value string) {
		defer wg.Done()
		if w := do(t, h, "POST", path, url.Values{"field": {field}, "value": {value}}, nil); w.Code != 200 {
			t.Errorf("%s %s=%s: %d", path, field, value, w.Code)
		}
	}
	for i := 0; i < 20; i++ {
		wg.Add(4)
		go send("/act/set", "attempts", "5")
		go send("/act/set", "slow_pct", "30")
		go send("/act/set", "families", "0")
		go send("/act/preset", all[i%len(all)].ID, "1")
	}
	wg.Wait()
	got := ctl.LoadSettings(paths.Settings())
	if got.Attempts != 5 || got.SlowPct != 30 || got.Families || len(got.Awg2Presets) != len(all) {
		t.Fatalf("changes lost: %+v", got)
	}
	// the service writes the presets the settings ask for
	ctl.SyncUserFiles()
	for _, p := range all {
		if !ctl.PresetWritten(p, true) {
			b, err := os.ReadFile(paths.Presets())
			t.Fatalf("preset %s not written: %q, %v", p.ID, b, err)
		}
	}
}

// With a key, nothing is served to a request without it: another account
// on the machine reaches 127.0.0.1 too. The key in the address is traded
// for a cookie and taken out of the address.
func TestKey(t *testing.T) {
	s, _ := testServer(t)
	s.Key = strings.Repeat("ab", 32)
	h := s.Handler()
	form := url.Values{"field": {"attempts"}, "value": {"7"}}
	if w := do(t, h, "GET", "/overview", nil, nil); w.Code != 403 {
		t.Errorf("a page without the key: %d", w.Code)
	}
	if w := do(t, h, "POST", "/act/set", form, nil); w.Code != 403 {
		t.Errorf("a form without the key: %d", w.Code)
	}
	if w := do(t, h, "GET", "/overview?k="+strings.Repeat("cd", 32), nil, nil); w.Code != 403 {
		t.Errorf("a wrong key: %d", w.Code)
	}
	if ctl.LoadSettings(paths.Settings()).Attempts == 7 {
		t.Fatal("a request without the key changed the settings")
	}
	w := do(t, h, "GET", "/verdicts?q=x&k="+s.Key, nil, nil)
	c := w.Result().Cookies()
	if w.Code != 303 || w.Header().Get("Location") != "/verdicts?q=x" || len(c) != 1 || c[0].Value != s.Key || !c[0].HttpOnly {
		t.Fatalf("the key in the address: %d, to %q, cookies %v", w.Code, w.Header().Get("Location"), c)
	}
	if w := do(t, h, "GET", "/overview", nil, map[string]string{"Cookie": c[0].Name + "=" + s.Key}); w.Code != 200 {
		t.Errorf("a page with the cookie: %d", w.Code)
	}
	if w := do(t, h, "POST", "/act/set", form, map[string]string{"Cookie": c[0].Name + "=" + s.Key}); w.Code != 200 {
		t.Errorf("a form with the cookie: %d", w.Code)
	}
	if w := do(t, h, "GET", "/api/status", nil, map[string]string{keyHeader: s.Key}); w.Code != 200 {
		t.Errorf("the status with the key header: %d", w.Code)
	}
}

// The icon is served without the key: the browser fetches it on its own,
// without the page's cookie, and a refusal left the tab without it.
func TestIconWithoutKey(t *testing.T) {
	s, _ := testServer(t)
	s.Key = strings.Repeat("ab", 32)
	h := s.Handler()
	if w := do(t, h, "GET", "/favicon.ico", nil, nil); w.Code != 200 || w.Header().Get("Content-Type") != "image/x-icon" {
		t.Fatalf("icon: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	if w := do(t, h, "GET", "/overview", nil, nil); w.Code != 403 || !strings.Contains(w.Body.String(), `rel="icon"`) {
		t.Fatalf("the refusal: %d %s", w.Code, w.Body.String())
	}
}

// The page shows the program's icon.
func TestFavicon(t *testing.T) {
	s, _ := testServer(t)
	w := do(t, s.Handler(), "GET", "/favicon.ico", nil, nil)
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/x-icon" || !strings.HasPrefix(w.Body.String(), "\x00\x00\x01\x00") {
		t.Fatalf("favicon: %d %q, %d bytes", w.Code, w.Header().Get("Content-Type"), w.Body.Len())
	}
}

// One .conf in both tunnels is refused whichever is loaded second.
func TestSameConfBothTunnels(t *testing.T) {
	testServer(t)
	conf := func(key, host string) string {
		return "[Interface]\nPrivateKey = " + key + "\nAddress = 10.8.1.3/32\n[Peer]\nPublicKey = cA==\nEndpoint = " + host + ":51820\n"
	}
	k1 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	k2 := "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if err := saveConf1(conf(k1, "198.51.100.7")); err != nil {
		t.Fatal(err)
	}
	if err := saveConf2(conf(k1, "198.51.100.8")); err == nil {
		t.Fatal("the first tunnel's key taken for the second")
	}
	if err := saveConf2(conf(k2, "198.51.100.8")); err != nil {
		t.Fatal(err)
	}
	if err := saveConf1(conf(k2, "198.51.100.9")); err == nil {
		t.Fatal("the second tunnel's key taken for the first")
	}
	if b, _ := os.ReadFile(paths.SourceConf()); !strings.Contains(string(b), k1) {
		t.Fatal("the refused config replaced the first one")
	}
	// the first one replaced by another of its own: fine
	if err := saveConf1(conf(k1, "198.51.100.10")); err != nil {
		t.Fatal(err)
	}
}

// A second tunnel's .conf the core could not use is refused when loaded --
// it used to be taken, and left out of the config by the service with a
// line in its log alone -- and one found on disk is said so, not shown as
// attached.
func TestSecondConfUsable(t *testing.T) {
	s, _ := testServer(t)
	conf := func(iface, peer string) string {
		return "[Interface]\nPrivateKey = AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n" + iface +
			"[Peer]\nPublicKey = cA==\n" + peer
	}
	for name, text := range map[string]string{
		"no IPv4 address": conf("Address = fd00::2/128\n", "Endpoint = 198.51.100.8:51820\n"),
		"two IPv4":        conf("Address = 10.8.1.3/32, 10.8.1.4/32\n", "Endpoint = 198.51.100.8:51820\n"),
		"a bad MTU":       conf("Address = 10.8.1.3/32\nMTU = big\n", "Endpoint = 198.51.100.8:51820\n"),
		"a bad port":      conf("Address = 10.8.1.3/32\n", "Endpoint = 198.51.100.8:port\n"),
		"a bad Endpoint":  conf("Address = 10.8.1.3/32\n", "Endpoint = bad host!:51820\n"),
	} {
		if err := saveConf2(text); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	if _, err := os.Stat(paths.SourceConf2()); err == nil {
		t.Fatal("a refused config was written")
	}

	st := s.statusFn()
	st.Awg2, st.Awg2Err = false, "the config has no IPv4 address"
	s.statusFn = func() status { return st }
	for _, l := range []string{"en", "ru"} {
		for _, target := range []string{"/frag/awg2/awg2state", "/overview"} {
			body := do(t, s.Handler(), "GET", target, nil, map[string]string{"Cookie": "lang=" + l}).Body.String()
			want := map[string]string{"en": "cannot be used: the config has no IPv4 address", "ru": "нельзя использовать: в конфиге нет IPv4-адреса"}[l]
			if !strings.Contains(body, want) {
				t.Errorf("%s %s: the reason is not said:\n%s", l, target, body)
			}
			if target != "/overview" && !strings.Contains(body, "/act/detach2") {
				t.Errorf("%s: no way to remove it", l)
			}
		}
	}
}

// The DNS test tries the other spelling of a DoH address the server did not
// answer -- no path and /dns-query, each for the other -- and hands the box
// the spelling that answered. What answers as written stays as written.
func TestDNSTestFixesPath(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	answers := map[string]bool{ // what the servers answer on
		"https://a.test":                 true, // no path, works
		"https://b.test/dns-query":       true, // no path fails, /dns-query works
		"https://c.test/dns-query":       true, // /dns-query works
		"https://d.test:8443":            true, // /dns-query fails, no path works
		"https://e.test/dns-query?ecs=0": false,
		"tls://f.test":                   true,
	}
	// as probe.PingEither does it, over the servers above
	old := pingEither
	pingEither = func(_ probe.Dialer, srv, _ string) ([]string, time.Duration, string, error) {
		if answers[srv] {
			return []string{"192.0.2.1"}, time.Millisecond, srv, nil
		}
		if alt, ok := probe.DoHPathAlternative(srv); ok && answers[alt] {
			return []string{"192.0.2.1"}, time.Millisecond, alt, nil
		}
		return nil, 0, srv, errors.New("HTTP 404")
	}
	defer func() { pingEither = old }()

	lines := func(l ...string) string { return strings.Join(l, "\n") }
	in := lines("https://a.test", "https://b.test", "https://c.test/dns-query",
		"https://d.test:8443/dns-query", "https://e.test/dns-query?ecs=0", "tls://f.test")
	w := do(t, h, "POST", "/act/dnstest?path=direct", url.Values{"direct_dns": {in}}, nil)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	want := lines("https://a.test", "https://b.test/dns-query", "https://c.test/dns-query",
		"https://d.test:8443", "https://e.test/dns-query?ecs=0", "tls://f.test")
	if !strings.Contains(body, `data-fill="direct_dns">`+want+`</span>`) {
		t.Fatalf("the box is not handed the spellings that answer:\n%s", body)
	}
	if n := strings.Count(body, "pill warn"); n != 2 {
		t.Fatalf("%d addresses marked fixed, want 2:\n%s", n, body)
	}
	if n := strings.Count(body, "pill bad"); n != 1 {
		t.Fatalf("%d failed, want 1 (e.test answers neither way):\n%s", n, body)
	}

	// nothing to fix: the box is left alone
	w = do(t, h, "POST", "/act/dnstest?path=direct", url.Values{"direct_dns": {lines("https://a.test", "https://c.test/dns-query")}}, nil)
	if strings.Contains(w.Body.String(), "data-fill") {
		t.Fatalf("a box with nothing to fix was refilled:\n%s", w.Body.String())
	}
}

// The second tunnel's switch is kept per auto-switch mode, and observe only
// starts off each time it is chosen.
func TestAwg2Switch(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	active := func() bool { return ctl.LoadSettings(paths.Settings()).Awg2Active() }
	mode := func(m string) {
		t.Helper()
		if w := do(t, h, "POST", "/act/auto", url.Values{"value": {m}}, nil); w.Code != 200 {
			t.Fatalf("mode %s: %d", m, w.Code)
		}
	}
	sw := func(on string) string {
		t.Helper()
		w := do(t, h, "POST", "/act/awg2", url.Values{"field": {"awg2"}, "value": {on}}, nil)
		if w.Code != 200 || strings.Contains(w.Body.String(), `class="msg bad"`) {
			t.Fatalf("switch %s: %d %s", on, w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	if !active() {
		t.Fatal("off to begin with in on")
	}
	sw("0")
	if active() {
		t.Fatal("not switched off")
	}
	mode(ctl.ModeObserve)
	if active() {
		t.Fatal("observe only started on")
	}
	sw("1")
	mode(ctl.ModeTunnel)
	if !active() {
		t.Fatal("tunnel only never switched: not on")
	}
	mode(ctl.ModeOn)
	if active() {
		t.Fatal("on forgot it was switched off")
	}
	mode(ctl.ModeObserve)
	if active() {
		t.Fatal("observe only kept the switch from before")
	}
}

// With no first tunnel's config the core runs without it: the first is
// said not loaded, not down, and the second tunnel's page says it takes its
// own lists only.
func TestNoFirstTunnel(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	st := s.statusFn()
	st.Installed, st.ServiceRun, st.HasConfig, st.Awg2, st.Awg2On, st.Awg2Alive = true, true, false, true, true, true
	s.statusFn = func() status { return st }
	head := do(t, h, "GET", "/frag/awg2/header", nil, nil).Body.String()
	if !strings.Contains(head, "awg no config loaded") || strings.Contains(head, "not responding") {
		t.Errorf("header: %s", head)
	}
	if b := do(t, h, "GET", "/frag/awg2/awg2state", nil, nil).Body.String(); !strings.Contains(b, "The first tunnel (awg1) is not loaded") {
		t.Errorf("awg2 state: %s", b)
	}
	st.HasConfig = true
	if b := do(t, h, "GET", "/frag/awg2/awg2state", nil, nil).Body.String(); strings.Contains(b, "is not loaded") {
		t.Errorf("awg2 state with the first loaded: %s", b)
	}
}

// With no first tunnel the detector checks nothing, auto-switch On or not:
// the overview, the verdicts and the settings say so.
func TestNoFirstNoProbes(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	st := s.statusFn()
	st.Installed, st.ServiceRun, st.Mode = true, true, ctl.ModeOn
	s.statusFn = func() status { return st }
	for _, has := range []bool{false, true} {
		st.HasConfig = has
		for _, pg := range []string{"/overview", "/verdicts", "/settings"} {
			b := do(t, h, "GET", pg, nil, nil).Body.String()
			if got := strings.Contains(b, "the detector checks nothing"); got != !has {
				t.Errorf("first tunnel %v, %s: said %v", has, pg, got)
			}
		}
	}
}

// The second tunnel's DNS is its own: saved beside the first's, and the
// page says which tunnel is not loaded -- its test is off then.
func TestDNSSecondTunnel(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	body := do(t, h, "POST", "/act/dns", url.Values{"direct_dns": {"https://77.88.8.8/dns-query"},
		"tunnel_dns": {""}, "tunnel_dns2": {"10.9.0.1"}}, nil).Body.String()
	if strings.Contains(body, `class="msg bad"`) {
		t.Fatalf("not saved: %s", body)
	}
	set := ctl.LoadSettings(paths.Settings())
	if strings.Join(set.TunnelDNS2, ",") != "10.9.0.1" || len(set.TunnelDNS) != 0 {
		t.Fatalf("saved: first %v, second %v", set.TunnelDNS, set.TunnelDNS2)
	}
	page := do(t, h, "GET", "/settings", nil, nil).Body.String()
	for _, want := range []string{"awg1 is not loaded.", "awg2 is not loaded.", `id="tunnel_dns2"`, "10.9.0.1"} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if err := os.WriteFile(paths.SourceConf2(), []byte(testConf2), 0o600); err != nil {
		t.Fatal(err)
	}
	if page = do(t, h, "GET", "/settings", nil, nil).Body.String(); strings.Contains(page, "awg2 is not loaded.") {
		t.Error("awg2 loaded, said not")
	}
}

// The first tunnel's config is deleted by its button, as the second's is;
// a second delete -- from another window -- is no error.
func TestDeleteFirst(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	if err := os.WriteFile(paths.SourceConf(), []byte("[Interface]\nPrivateKey = k\nAddress = 10.8.1.3/32\n[Peer]\nPublicKey = p\nEndpoint = 198.51.100.7:51820\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := s.statusFn()
	st.HasConfig = true
	s.statusFn = func() status { return st }
	if b := do(t, h, "GET", "/overview", nil, nil).Body.String(); !strings.Contains(b, `action="/act/delete1"`) {
		t.Fatal("no delete button with the config loaded")
	}
	for i := 0; i < 2; i++ {
		w := do(t, h, "POST", "/act/delete1", url.Values{}, nil)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("delete %d: %d", i, w.Code)
		}
		// the message it left on the page it came back to
		if b := do(t, h, "GET", "/settings", nil, nil).Body.String(); !strings.Contains(b, "First tunnel config deleted") {
			t.Fatalf("delete %d: not said deleted", i)
		}
	}
	if _, err := os.Stat(paths.SourceConf()); !os.IsNotExist(err) {
		t.Fatalf("the config is still there: %v", err)
	}
	st.HasConfig = false
	if b := do(t, h, "GET", "/overview", nil, nil).Body.String(); strings.Contains(b, `action="/act/delete1"`) {
		t.Fatal("a delete button with no config")
	}
}

// IPv6 switched off by the program is said beside the setting, and only
// while the setting asks for it.
func TestIPv6BlockedSaid(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	st := s.statusFn()
	st.Installed, st.ServiceRun, st.IPv6Blocked = true, true, true
	s.statusFn = func() status { return st }
	const said = "Switched off by the program"
	if b := do(t, h, "GET", "/settings", nil, nil).Body.String(); !strings.Contains(b, said) {
		t.Error("not said with IPv6 on in the settings")
	}
	if _, err := ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error { set.IPv6 = false; return nil }); err != nil {
		t.Fatal(err)
	}
	if b := do(t, h, "GET", "/settings", nil, nil).Body.String(); strings.Contains(b, said) {
		t.Error("said with IPv6 off in the settings")
	}
	st.IPv6Blocked = false
	if _, err := ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error { set.IPv6 = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if b := do(t, h, "GET", "/settings", nil, nil).Body.String(); strings.Contains(b, said) {
		t.Error("said with IPv6 reaching the adapter")
	}
}

// No traffic reaching the adapter is said on the overview, and only then.
func TestTunBlockedSaid(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	st := s.statusFn()
	st.Installed, st.ServiceRun = true, true
	s.statusFn = func() status { return st }
	const said = "Windows does not let traffic into the DPI Switch adapter"
	for _, blocked := range []bool{true, false} {
		st.TunBlocked = blocked
		if got := strings.Contains(do(t, h, "GET", "/overview", nil, nil).Body.String(), said); got != blocked {
			t.Errorf("blocked %v: said %v", blocked, got)
		}
	}
}

// A verdict's key as the connections it routed are matched: an address
// only with its "@", a whole domain with its "+.", no program at all --
// the request is the service's to read.
func TestForgetEntry(t *testing.T) {
	for key, want := range map[string]string{
		"a.example.org":  "a.example.org",
		"+.example.org":  "+.example.org",
		"@192.0.2.1":     "192.0.2.1",
		"@2001:db8::1":   "2001:db8::1",
		"":               "",
		"x.exe":          "",
		"@a.example.org": "",
		"192.0.2.1":      "",
	} {
		got, ok := forgetEntry(key)
		if ok != (want != "") || got != want {
			t.Errorf("%q: %q %v, want %q", key, got, ok, want)
		}
	}
}

// A verdict reset from its row: the request is left for the service, the
// answer waits for it to be taken, and says when it was not. The page's
// rows carry the key the reset and the menu need.
func TestForget(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	ask := func(key string) string {
		t.Helper()
		w := do(t, h, "POST", "/act/forget", url.Values{"key": {key}}, map[string]string{"Referer": "http://127.0.0.1:8080/verdicts"})
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", key, w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	if w := do(t, h, "POST", "/act/forget", url.Values{"key": {"x.exe"}}, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("a program taken for a verdict: %d", w.Code)
	}
	// the service stopped: the request waits for it
	if b := ask("a.example.org"); !strings.Contains(b, "when it starts") {
		t.Fatalf("stopped: %s", b)
	}
	reqs, _ := filepath.Glob(paths.ForgetRequests())
	if len(reqs) != 1 {
		t.Fatalf("requests: %v", reqs)
	}
	if b, _ := os.ReadFile(reqs[0]); string(b) != "a.example.org\n" {
		t.Fatalf("request: %q", b)
	}
	os.Remove(reqs[0])

	// running, and the request taken
	serviceRunning = func() bool { return true }
	forgetWait = 300 * time.Millisecond
	t.Cleanup(func() { forgetWait = 5 * time.Second })
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			// on Windows a file still being written cannot go: the service
			// tries again the next second
			if reqs, _ := filepath.Glob(paths.ForgetRequests()); len(reqs) > 0 && os.Remove(reqs[0]) == nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	if b := ask("+.example.org"); !strings.Contains(b, "Verdict reset: +.example.org") {
		t.Fatalf("taken: %s", b)
	}
	<-done
	// running, and not taken
	if b := ask("@192.0.2.1"); !strings.Contains(b, "as soon as its controller runs") {
		t.Fatalf("not taken: %s", b)
	}

	now := time.Now()
	st := map[string]any{"current": "AS1", "networks": map[string]any{"AS1": map[string]any{
		"www.example.org": map[string]any{"verdict": "CLEAN", "decided_at": now, "expires_at": now.Add(time.Hour), "last_seen": now},
		"@192.0.2.9":      map[string]any{"verdict": "BLOCKED_TCP", "decided_at": now, "expires_at": now.Add(time.Hour), "last_seen": now},
	}}}
	b, _ := json.Marshal(st)
	if err := os.WriteFile(paths.State(), b, 0o644); err != nil {
		t.Fatal(err)
	}
	body := do(t, h, "GET", "/verdicts", nil, nil).Body.String()
	for _, want := range []string{`data-key="www.example.org" data-dom="example.org"`, `id="lmenu"`, `id="vwords"`, `class="lx"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the direct tab lacks %s", want)
		}
	}
	if strings.Contains(body, `id="lreveal"`) {
		t.Error("a program's file on the verdicts page")
	}
	body = do(t, h, "GET", "/verdicts?cat=blocked", nil, nil).Body.String()
	if !strings.Contains(body, `data-key="@192.0.2.9" data-addr="192.0.2.9"`) {
		t.Errorf("the blocked tab's address row:\n%s", body)
	}
}

// The old programs' list that cannot go would go on routing its programs:
// the direct list's save is undone, and said not saved.
func TestListOldAppsStuck(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	os.WriteFile(paths.User(paths.DirectList), []byte("a.example\n"), 0o644)
	// a folder with something in it: no Remove takes it
	stuck := paths.User(paths.AppsList)
	if err := os.MkdirAll(filepath.Join(stuck, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	w := do(t, h, "POST", "/act/list", url.Values{"kind": {"direct"}, "entries": {"b.example"}}, nil)
	if !strings.Contains(w.Body.String(), "msg bad") {
		t.Fatalf("said saved: %s", w.Body.String())
	}
	if b, _ := os.ReadFile(paths.User(paths.DirectList)); strings.TrimSpace(string(b)) != "a.example" {
		t.Fatalf("the list after a save undone: %q", b)
	}
}
