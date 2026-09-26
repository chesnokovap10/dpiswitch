package webui

import (
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
			Awg2: true, Version: "test", DataDir: paths.DataDir(), NetworkID: "AS1", AutoSwitch: true}
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
		"verdicts": {"tabs", "table"},
		"lists":    {"list-direct", "list-tunnel", "list-apps"},
		"awg2":     {"awg2state", "presets", "hosts"},
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
					keys = append(keys, strings.ReplaceAll(k, `\"`, `"`))
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
	for _, f := range []string{"actions.go", "ui.go", "pages.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		add(goKey, string(b))
	}
	// the tray speaks the pages' language, from the same table
	trayKey := regexp.MustCompile(`\bT\("((?:[^"\\]|\\.)*)"\)`)
	for _, f := range []string{"main.go", "install.go"} {
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
	for _, p := range presets.All {
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
	post("auto_switch", "0")
	got := ctl.LoadSettings(paths.Settings())
	if got.Attempts != 5 || got.AutoSwitch || len(got.Awg2Presets) != 1 {
		t.Fatalf("after two changes: %+v", got)
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

// A list is saved as the core reads it: lower case, names only, once each.
func TestListSave(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	w := do(t, h, "POST", "/act/list", url.Values{"kind": {"tunnel"},
		"hosts": {"Example.com\nhttps://sub.example.org/path\n\n+.example.net\nexample.com"}}, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "msg ok") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	want := []string{"+.example.net", "example.com", "sub.example.org"}
	if got := readList(paths.User(paths.TunnelList)); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
	// the core reads the service's copy, made from the user's
	if ctl.Synced(paths.TunnelList) {
		t.Fatal("synced before the service ran")
	}
	ctl.SyncUserFiles()
	if got := readList(paths.ForceTunnel()); strings.Join(got, ",") != strings.Join(want, ",") || !ctl.Synced(paths.TunnelList) {
		t.Fatalf("service copy %v, want %v", got, want)
	}
	// a program is added by name and saved at once
	w = do(t, h, "POST", "/act/apps", url.Values{"apps": {"a.exe"}, "add": {"b.exe"}, "op": {"add"}}, nil)
	if got := readApps(); strings.Join(got, ",") != "a.exe,b.exe" {
		t.Fatalf("apps %v: %s", got, w.Body.String())
	}
	w = do(t, h, "POST", "/act/apps", url.Values{"apps": {"a.exe"}, "add": {""}, "op": {"add"}}, nil)
	if !strings.Contains(w.Body.String(), "msg bad") {
		t.Fatalf("an empty pick was not refused: %s", w.Body.String())
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
	w := do(t, h, "POST", "/act/list", url.Values{"kind": {"direct"}, "hosts": {"a.example"}}, nil)
	if !strings.Contains(w.Body.String(), "msg ok") || !ctl.Synced(paths.DirectList) {
		t.Fatalf("not taken: %s", w.Body.String())
	}
	// no service to take it: the save is kept, the move is not claimed
	w = do(t, h, "POST", "/act/list", url.Values{"kind": {"direct"}, "hosts": {"b.example"}}, nil)
	if !strings.Contains(w.Body.String(), "msg bad") || readList(paths.User(paths.DirectList))[0] != "b.example" {
		t.Fatalf("an untaken save: %s", w.Body.String())
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
		go send("/act/preset", presets.All[i%len(presets.All)].ID, "1")
	}
	wg.Wait()
	got := ctl.LoadSettings(paths.Settings())
	if got.Attempts != 5 || got.SlowPct != 30 || got.Families || len(got.Awg2Presets) != len(presets.All) {
		t.Fatalf("changes lost: %+v", got)
	}
	// the service writes the preset files the settings ask for
	ctl.SyncUserFiles()
	for _, p := range presets.All {
		b, err := os.ReadFile(paths.Preset(p.ID))
		if err != nil || !strings.Contains(string(b), ",") {
			t.Fatalf("preset %s: file %q, %v", p.ID, b, err)
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
