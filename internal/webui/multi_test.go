package webui

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
)

// The rows picked at once on the verdicts page go in one request: one file
// for the service, every name in it, said as a count. A key no verdict can
// have among them refuses them all.
func TestForgetMany(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	keys := url.Values{"key": {"a.example.org", "+.b.example.org", "@192.0.2.7", "A.example.org"}}
	w := do(t, h, "POST", "/act/forget", keys, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "when it starts") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	reqs, _ := filepath.Glob(paths.ForgetRequests())
	if len(reqs) != 1 {
		t.Fatalf("requests: %v", reqs)
	}
	// the same key twice goes once
	if b, _ := os.ReadFile(reqs[0]); string(b) != "a.example.org\n+.b.example.org\n@192.0.2.7\n" {
		t.Fatalf("request: %q", b)
	}
	os.Remove(reqs[0])
	bad := url.Values{"key": {"a.example.org", "x.exe"}}
	if w := do(t, h, "POST", "/act/forget", bad, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("a program among them: %d", w.Code)
	}
	if reqs, _ := filepath.Glob(paths.ForgetRequests()); len(reqs) != 0 {
		t.Fatalf("a request made for a refused set: %v", reqs)
	}
}

// The rows picked on Live closed in one request; an id of no kind among
// them closes none.
func TestLiveCloseMany(t *testing.T) {
	s, core, _ := liveTest(t)
	h := s.Handler()
	a, b := "0d5f2a7e-1111-4c3b-9a7e-2b1c3d4e5f60", "0d5f2a7e-2222-4c3b-9a7e-2b1c3d4e5f60"
	if w := do(t, h, "POST", "/act/liveclose", url.Values{"id": {a, "../configs"}}, nil); w.Code != 400 {
		t.Fatalf("a bad id among them: %d", w.Code)
	}
	if w := do(t, h, "POST", "/act/liveclose", url.Values{"id": {a, b}}, nil); w.Code != 204 {
		t.Fatalf("close: %d %s", w.Code, w.Body)
	}
	core.mu.Lock()
	got := slices.Clone(core.closed)
	core.mu.Unlock()
	if !slices.Equal(got, []string{a, b}) {
		t.Errorf("the core closed %v", got)
	}
}

// Several lines sent to a list at once: each goes in, the ones there
// already are counted, and a line of another list that routed one of them
// comes out -- written once, said as a count.
func TestLiveAddMany(t *testing.T) {
	s, _ := testServer(t)
	add := func(to string, entries ...string) liveAnswer {
		t.Helper()
		return liveAct(t, s, "/act/liveadd", url.Values{"to": {to}, "entry": entries}, nil)
	}
	list := func(name string) string { return strings.Join(readEntries(name), ",") }

	if a := add("tunnel", "+.a.example", "b.example"); !a.OK || a.Msg != "Added to “Always via tunnel”: 2 of 2" {
		t.Fatalf("two lines: %+v", a)
	}
	a := add("direct", "+.a.example", "c.example", "C.example", "Telegram.exe")
	if !a.OK || !strings.HasPrefix(a.Msg, "Added to “Always direct”: 3 of 3") || !strings.Contains(a.Msg, "(taken out of «Always via tunnel»: +.a.example)") {
		t.Fatalf("moved out of the tunnel: %+v", a)
	}
	if list(paths.TunnelList) != "b.example" {
		t.Fatalf("the tunnel's list: %s", list(paths.TunnelList))
	}
	for _, want := range []string{"+.a.example", "c.example"} {
		if !strings.Contains(list(paths.DirectList), want) {
			t.Fatalf("the direct list has no %s: %s", want, list(paths.DirectList))
		}
	}
	if a := add("direct", "c.example", "d.example"); !a.OK || a.Msg != "Added to “Always direct”: 1 of 2; there already: 1" {
		t.Fatalf("one there already: %+v", a)
	}
	// a line of no kind among them: nothing saved
	before := list(paths.BlockList)
	if a := add("block", "e.example", "no such thing!"); a.OK || list(paths.BlockList) != before {
		t.Fatalf("a bad line among them: %+v, %s", a, list(paths.BlockList))
	}
}

// Live's route filters: one for both tunnels, and the bypass's only while
// the bypass is on
func TestLiveRouteFilters(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	for _, on := range []bool{false, true} {
		if _, err := ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error { set.SplitHello = on; return nil }); err != nil {
			t.Fatal(err)
		}
		body := do(t, h, "GET", "/live", nil, nil).Body.String()
		if got := strings.Contains(body, `data-route="split"`); got != on {
			t.Errorf("bypass %v: its filter shown %v", on, got)
		}
		if !strings.Contains(body, `data-route="tunnel"`) || strings.Contains(body, `data-route="awg1"`) || strings.Contains(body, `data-route="awg2"`) {
			t.Errorf("bypass %v: the tunnels' filters are not one", on)
		}
	}
}
