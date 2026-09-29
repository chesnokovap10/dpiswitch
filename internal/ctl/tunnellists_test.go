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

// The always-tunnel list's group takes one tunnel, or the first and then
// the second with the second tunnel switched on; asked once per change, and
// not at all of a core without the member.
func TestSyncTunnelLists(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	now, all := "tunnel-one", `["tunnel-one","tunnel-any"]`
	var puts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != "/proxies/"+TunnelListsGroup {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.Write([]byte(`{"all":` + all + `,"now":"` + now + `"}`))
		case http.MethodPut:
			b, _ := io.ReadAll(r.Body)
			puts = append(puts, string(b))
			now = strings.Trim(strings.TrimPrefix(string(b), `{"name":`), `"}`)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()
	a := newAPI(strings.TrimPrefix(srv.URL, "http://"), "")
	tunnelListsSet = ""
	defer func() { tunnelListsSet = "" }()
	set := func(on bool) {
		t.Helper()
		if _, err := UpdateSettings(paths.Settings(), func(s *Settings) error { s.SetAwg2(on); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	check := func(want string, nput int) {
		t.Helper()
		syncTunnelLists(a)
		syncTunnelLists(a)
		mu.Lock()
		defer mu.Unlock()
		if now != want || len(puts) != nput {
			t.Fatalf("now %s after %v, want %s after %d", now, puts, want, nput)
		}
	}
	set(true)
	check(TunnelAnyGroup, 1)
	set(false)
	check(TunnelOneGroup, 2)
	// a core from before, without the member: nothing sent
	mu.Lock()
	all = `["tunnel-one"]`
	mu.Unlock()
	tunnelListsSet = ""
	set(true)
	check(TunnelOneGroup, 2)
}
