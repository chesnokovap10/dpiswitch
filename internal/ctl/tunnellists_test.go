package ctl

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"dpiswitch/internal/paths"
)

// The members the select groups take, by mode and by the second tunnel's
// switch: tunnel only never goes direct.
func TestRouteChoice(t *testing.T) {
	for _, c := range []struct {
		mode             string
		awg2             bool
		lists, two, rest string
	}{
		{ModeOn, true, TunnelAnyGroup, Tunnel2SoftGroup, TunnelSoftAnyGroup},
		{ModeOn, false, TunnelOneGroup, Tunnel2SoftGroup, TunnelSoftGroup},
		{ModeObserve, true, TunnelAnyGroup, Tunnel2SoftGroup, TunnelSoftAnyGroup},
		{ModeTunnel, true, TunnelAnyGroup, Tunnel2StrictGroup, TunnelAnyGroup},
		{ModeTunnel, false, TunnelOneGroup, Tunnel2StrictGroup, TunnelOneGroup},
	} {
		s := DefaultSettings()
		s.SetMode(c.mode)
		s.SetAwg2(c.awg2)
		got := RouteChoice(s)
		if got[TunnelListsGroup] != c.lists || got[Tunnel2Group] != c.two || got[TunnelRestGroup] != c.rest {
			t.Errorf("%s, awg2 %v: %v", c.mode, c.awg2, got)
		}
	}
}

// The core's select groups take what the settings ask for; asked once per
// change, and not at all of a core without the member.
func TestSyncRoutes(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	now := map[string]string{TunnelListsGroup: TunnelOneGroup, Tunnel2Group: Tunnel2SoftGroup, TunnelRestGroup: TunnelSoftGroup}
	all := map[string]string{
		TunnelListsGroup: `["tunnel-one","tunnel-any"]`,
		Tunnel2Group:     `["tunnel2-soft","tunnel2-strict"]`,
		TunnelRestGroup:  `["tunnel","tunnel-soft-any","tunnel-one","tunnel-any"]`,
	}
	puts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		g := strings.TrimPrefix(r.URL.Path, "/proxies/")
		if all[g] == "" {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.Write([]byte(`{"all":` + all[g] + `,"now":"` + now[g] + `"}`))
		case http.MethodPut:
			b, _ := io.ReadAll(r.Body)
			puts++
			now[g] = strings.Trim(strings.TrimPrefix(string(b), `{"name":`), `"}`)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()
	a := newAPI(strings.TrimPrefix(srv.URL, "http://"), "")
	routesSet = map[string]string{}
	defer func() { routesSet = map[string]string{} }()
	set := func(mode string, on bool) {
		t.Helper()
		if _, err := UpdateSettings(paths.Settings(), func(s *Settings) error { s.SetMode(mode); s.SetAwg2(on); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	check := func(want map[string]string, nput int) {
		t.Helper()
		syncRoutes(a)
		syncRoutes(a)
		mu.Lock()
		defer mu.Unlock()
		for g, m := range want {
			if now[g] != m {
				t.Errorf("%s is %s, want %s", g, now[g], m)
			}
		}
		if puts != nput {
			t.Errorf("%d switches, want %d", puts, nput)
		}
	}
	set(ModeOn, true)
	check(map[string]string{TunnelListsGroup: TunnelAnyGroup, TunnelRestGroup: TunnelSoftAnyGroup}, 2)
	set(ModeTunnel, true)
	check(map[string]string{Tunnel2Group: Tunnel2StrictGroup, TunnelRestGroup: TunnelAnyGroup}, 4)
	// a core from before, without the member: nothing sent
	mu.Lock()
	all[TunnelRestGroup] = `["tunnel"]`
	mu.Unlock()
	routesSet = map[string]string{}
	set(ModeTunnel, false)
	check(map[string]string{TunnelListsGroup: TunnelOneGroup}, 5)
}
