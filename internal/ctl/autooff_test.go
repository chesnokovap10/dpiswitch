package ctl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dpiswitch/internal/probe"
)

// Auto-switch turned off in the UI: within a second the lists are empty,
// the connections they sent direct are closed and the user's own and the
// tunnel's stay open, and a cycle started before cannot write the rules back.
func TestAutoSwitchOffAtOnce(t *testing.T) {
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
		SettingsPath: filepath.Join(dir, "settings.json"), autoOff: new(atomic.Bool)}
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
	if want := []string{"addr", "det"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("closed %v, want %v", got, want)
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
