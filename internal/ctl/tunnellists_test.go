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
		if _, err := UpdateSettings(paths.Settings(), func(s *Settings) error { s.SecondTunnel = true; s.SetMode(mode); s.SetAwg2(on); return nil }); err != nil {
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
	// the member comes -- a core rebuilt with it: the choice goes now. It
	// was taken as made while missing, and never sent
	mu.Lock()
	all[TunnelRestGroup] = `["tunnel","tunnel-soft-any","tunnel-one","tunnel-any"]`
	now[TunnelRestGroup] = "tunnel"
	mu.Unlock()
	check(map[string]string{TunnelRestGroup: TunnelOneGroup}, 6)
}
