package ctl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dpiswitch/internal/paths"
	"dpiswitch/internal/probe"
)

// Observe only chosen in the UI: within a second the detector's lists are
// empty, the connections through the tunnels are closed to reconnect direct
// and the direct ones stay open, and a cycle started before cannot write the
// rules back.
func TestAutoSwitchOffAtOnce(t *testing.T) {
	// the change of mode writes the list copies: not the real ones
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	old := settingsPoll
	settingsPoll = 10 * time.Millisecond
	defer func() { settingsPoll = old }()
	var mu sync.Mutex
	var closed []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/connections":
			w.Write([]byte(`{"connections":[
				{"id":"det","rule":"RuleSet","rulePayload":"p","chains":["DIRECT"]},
				{"id":"addr","rule":"RuleSet","rulePayload":"pi","chains":["DIRECT"]},
				{"id":"user","rule":"RuleSet","rulePayload":"force-direct","chains":["DIRECT"]},
				{"id":"tun","rule":"Match","rulePayload":"","chains":["awg","tunnel"]},
				{"id":"tun-a","rule":"Match","chains":["awg","tunnel"],"metadata":
					{"host":"a.example","destinationPort":"443","network":"tcp","sourceIP":"198.18.0.1"}},
				{"id":"probe-a","rule":"Match","chains":["awg"],"metadata":
					{"host":"a.example","destinationPort":"443","network":"tcp","sourceIP":"127.0.0.1","inboundName":"probe-tunnel"}},
				{"id":"pinned-a","rule":"RuleSet","rulePayload":"force-tunnel","chains":["awg"],"metadata":
					{"host":"a.example","destinationPort":"443","network":"tcp","sourceIP":"198.18.0.1"}}]}`))
		case r.Method == http.MethodDelete:
			mu.Lock()
			closed = append(closed, strings.TrimPrefix(r.URL.Path, "/connections/"))
			mu.Unlock()
		}
	}))
	defer srv.Close()
	a := newAPI(strings.TrimPrefix(srv.URL, "http://"), "")

	dir := t.TempDir()
	cfg := Config{Apply: true, ProxyName: "awg", Provider: "p", ListPath: filepath.Join(dir, "d.txt"),
		AddrProvider: "pi", AddrListPath: filepath.Join(dir, "ip.txt"),
		SettingsPath: paths.Settings(), autoOff: new(atomic.Bool)}
	e := &entry{Verdict: probe.Clean, ExpiresAt: time.Now().Add(time.Hour), TestedIP: "192.0.2.1"}
	st := &state{Networks: map[string]map[string]*entry{"n": {"a.example": e}}, Current: "n"}
	syncList(cfg, a, st, "n", true)
	if listRules(cfg.ListPath) == nil {
		t.Fatal("the list was not written to begin with")
	}

	set := DefaultSettings()
	if err := SaveSettings(cfg.SettingsPath, set); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wake := make(chan struct{}, 1)
	go watchSettings(ctx, cfg, a, st, set, true, wake)

	set.AutoSwitch = false
	if err := SaveSettings(cfg.SettingsPath, set); err != nil {
		t.Fatal(err)
	}
	select {
	case <-wake:
	case <-time.After(3 * time.Second):
		t.Fatal("the change was not seen")
	}
	if listRules(cfg.ListPath) != nil || listRules(cfg.AddrListPath) != nil {
		t.Fatal("the lists were not emptied")
	}
	mu.Lock()
	got := append([]string(nil), closed...)
	mu.Unlock()
	sort.Strings(got)
	if want := []string{"pinned-a", "tun", "tun-a"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("closed %v, want %v", got, want)
	}
	if !strings.Contains(strings.Join(listRules(paths.ObserveAll()), " "), "NETWORK") {
		t.Fatal("the catch-all was not written")
	}

	// the cycle that was running holds Apply true
	syncList(cfg, a, st, "n", true)
	if listRules(cfg.ListPath) != nil {
		t.Fatal("a cycle started before wrote the rules back")
	}

	// turned back on: the lists are written at once, whatever the main loop
	// is busy with, and the tunnel connections they now send direct closed
	mu.Lock()
	closed = nil
	mu.Unlock()
	set.AutoSwitch = true
	if err := SaveSettings(cfg.SettingsPath, set); err != nil {
		t.Fatal(err)
	}
	select {
	case <-wake:
	case <-time.After(3 * time.Second):
		t.Fatal("turning back on was not seen")
	}
	mu.Lock()
	got = append([]string(nil), closed...)
	mu.Unlock()
	if want := []string{"tun-a"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("closed on turning on %v, want %v", got, want)
	}
	if !reflect.DeepEqual(listRules(cfg.ListPath), []string{"a.example"}) {
		t.Fatalf("list after turning back on: %v", listRules(cfg.ListPath))
	}
}

// A change of mode closes the open connections it sends another way, and
// only those: the prober's own and the local networks' are left alone.
func TestModeCloses(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	// the user's direct lists as the core reads them once on again
	os.WriteFile(paths.ForceDirect(), []byte("d.example\n"), 0o644)
	os.WriteFile(paths.ForceDirectApps(), []byte("PROCESS-NAME,x.exe\n"), 0o644)
	var mu sync.Mutex
	var closed []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/connections":
			w.Write([]byte(`{"connections":[
				{"id":"det","rule":"RuleSet","rulePayload":"p","chains":["DIRECT"]},
				{"id":"user","rule":"RuleSet","rulePayload":"force-direct","chains":["DIRECT"]},
				{"id":"app","rule":"RuleSet","rulePayload":"force-direct-apps","chains":["DIRECT"],"metadata":{"process":"x.exe"}},
				{"id":"obs","rule":"RuleSet","rulePayload":"observe-all","chains":["DIRECT"]},
				{"id":"lan","rule":"IPCIDR","rulePayload":"192.168.0.0/16","chains":["DIRECT"]},
				{"id":"tun","rule":"Match","chains":["awg","tunnel"],"metadata":{"host":"t.example"}},
				{"id":"preset","rule":"RuleSet","rulePayload":"presets","chains":["awg2","tunnel2"]},
				{"id":"d-tun","rule":"Match","chains":["awg","tunnel"],"metadata":{"host":"d.example"}},
				{"id":"app-tun","rule":"RuleSet","rulePayload":"presets","chains":["awg2","tunnel2"],"metadata":{"process":"X.EXE"}},
				{"id":"probe","rule":"Match","chains":["awg"],"metadata":{"inboundName":"probe-tunnel","sourceIP":"127.0.0.1"}}]}`))
		case r.Method == http.MethodDelete:
			mu.Lock()
			closed = append(closed, strings.TrimPrefix(r.URL.Path, "/connections/"))
			mu.Unlock()
		}
	}))
	defer srv.Close()
	a := newAPI(strings.TrimPrefix(srv.URL, "http://"), "")
	for _, c := range []struct {
		from, to string
		want     []string
	}{
		{ModeOn, ModeObserve, []string{"app-tun", "d-tun", "preset", "tun"}},
		{ModeOn, ModeTunnel, []string{"app", "det", "obs", "user"}},
		{ModeObserve, ModeOn, []string{"obs"}},
		{ModeTunnel, ModeOn, []string{"app-tun", "d-tun", "obs"}},
	} {
		mu.Lock()
		closed = nil
		mu.Unlock()
		closeRerouted(Config{}, a, c.from, c.to)
		mu.Lock()
		got := append([]string(nil), closed...)
		mu.Unlock()
		sort.Strings(got)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s -> %s closed %v, want %v", c.from, c.to, got, c.want)
		}
	}
}

// The files a mode decides follow the settings: observe only writes the
// catch-all, tunnel only sets the direct lists aside, and the UI's wait for
// a saved list still ends in that mode.
func TestModeFiles(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(paths.User(paths.DirectList), []byte("d.example\n"), 0o644)
	os.WriteFile(paths.User(paths.TunnelList), []byte("t.example\n"), 0o644)
	set := DefaultSettings()
	for _, c := range []struct {
		mode, direct, tunnel string
		observe              bool
	}{
		{ModeObserve, "d.example", "t.example", true},
		{ModeTunnel, "", "t.example", false},
		{ModeOn, "d.example", "t.example", false},
	} {
		set.SetMode(c.mode)
		if err := SaveSettings(paths.Settings(), set); err != nil {
			t.Fatal(err)
		}
		SyncUserFiles()
		if got := strings.Join(listRules(paths.ForceDirect()), " "); got != c.direct {
			t.Errorf("%s: direct list %q, want %q", c.mode, got, c.direct)
		}
		if got := strings.Join(listRules(paths.ForceTunnel()), " "); got != c.tunnel {
			t.Errorf("%s: tunnel list %q, want %q", c.mode, got, c.tunnel)
		}
		if got := listRules(paths.ObserveAll()) != nil; got != c.observe {
			t.Errorf("%s: catch-all %v", c.mode, listRules(paths.ObserveAll()))
		}
		if !Synced(paths.DirectList) {
			t.Errorf("%s: the direct list never counts as taken", c.mode)
		}
	}
}
