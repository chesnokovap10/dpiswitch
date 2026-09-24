package ctl

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dpiswitch/internal/probe"
)

// The list follows memory even when no verdict changes: a CLEAN expiring
// leaves it, and one re-confirmed after that comes back.
func TestSyncListFollowsExpiry(t *testing.T) {
	var reloads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			reloads.Add(1)
		}
	}))
	defer srv.Close()
	a := newAPI(strings.TrimPrefix(srv.URL, "http://"), "")

	dir := t.TempDir()
	cfg := Config{Apply: true, Provider: "p", ListPath: filepath.Join(dir, "d.txt"),
		AddrProvider: "pi", AddrListPath: filepath.Join(dir, "ip.txt")}
	e := &entry{Verdict: probe.Clean, ExpiresAt: time.Now().Add(time.Hour), TestedIP: "192.0.2.1"}
	st := &state{Networks: map[string]map[string]*entry{"n": {"a.example": e}}}

	step := func(name string, wantReloads int32, wantRules []string) {
		t.Helper()
		reloads.Store(0)
		syncList(cfg, a, st, "n", false)
		if got := reloads.Load(); got != wantReloads {
			t.Errorf("%s: %d reloads, want %d", name, got, wantReloads)
		}
		if got := listRules(cfg.ListPath); !reflect.DeepEqual(got, wantRules) {
			t.Errorf("%s: list %v, want %v", name, got, wantRules)
		}
	}
	step("first write", 2, []string{"a.example"})
	step("nothing changed", 0, []string{"a.example"})
	e.ExpiresAt = time.Now().Add(-time.Minute)
	step("expired", 2, nil)
	e.ExpiresAt = time.Now().Add(time.Hour)
	step("re-confirmed with the same verdict", 2, []string{"a.example"})
}

// A name seen only over QUIC is probed over TCP on the same port too.
func TestWithTCP(t *testing.T) {
	got := withTCP([]endpoint{{udp: true, port: 443}, {port: 20000}})
	want := []endpoint{{udp: true, port: 443}, {port: 20000}, {port: 443}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// already there: nothing added
	both := []endpoint{{port: 443}, {udp: true, port: 443}}
	if got := withTCP(both); !reflect.DeepEqual(got, both) {
		t.Fatalf("got %v, want %v", got, both)
	}
}

// The probe journal is bounded: past its limit it moves to .1 and starts
// over, and every line stays whole JSON.
func TestReportsRotate(t *testing.T) {
	old := reportsMax
	reportsMax = 1000
	defer func() { reportsMax = old }()
	p := filepath.Join(t.TempDir(), "reports.jsonl")
	line, _ := json.Marshal(probe.Report{Domain: "a.example", Verdict: probe.Clean})
	for i := 0; i < 10; i++ {
		appendJSONL(p, probe.Report{Domain: "a.example", Verdict: probe.Clean})
	}
	cur, _ := os.ReadFile(p)
	prev, err := os.ReadFile(p + ".1")
	if err != nil {
		t.Fatalf("no .1 after going past the limit: %v", err)
	}
	// checked before each append, so a file may pass the limit by one line
	if max := reportsMax + int64(len(line)) + 1; int64(len(cur)) > max || int64(len(prev)) > max {
		t.Fatalf("current %d bytes, previous %d, limit %d", len(cur), len(prev), max)
	}
	for _, l := range strings.Split(strings.TrimSpace(string(cur)+string(prev)), "\n") {
		if !json.Valid([]byte(l)) {
			t.Fatalf("a broken line: %q", l)
		}
	}
}
