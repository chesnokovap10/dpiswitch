package ctl

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"dpiswitch/internal/probe"
)

func backoffCfg() Config {
	return Config{TTL: 7 * 24 * time.Hour, FailTTL: time.Hour, MaxBackoff: 24 * time.Hour}
}

func TestFailTerm(t *testing.T) {
	cfg := backoffCfg()
	for _, tc := range []struct {
		streak, reverts int
		want            time.Duration
	}{
		{0, 0, time.Hour},
		{1, 0, 2 * time.Hour},
		{3, 0, 8 * time.Hour},
		{5, 0, 24 * time.Hour}, // 32 h, capped
		{40, 0, 24 * time.Hour},
		{0, 3, 3 * time.Hour}, // a reverted name waits at least reverts*FailTTL
		{2, 3, 4 * time.Hour},
		{0, 30, 24 * time.Hour},
	} {
		if got := failTerm(cfg, tc.streak, tc.reverts); got != tc.want {
			t.Errorf("streak %d, reverts %d: %s, want %s", tc.streak, tc.reverts, got, tc.want)
		}
	}
	// a cap set below FailTTL does not shorten the first term
	cfg.MaxBackoff = 30 * time.Minute
	if got := failTerm(cfg, 3, 0); got != time.Hour {
		t.Errorf("cap below FailTTL: %s, want 1h", got)
	}
}

// wantTerm checks when an entry expires, give or take the test's own runtime.
func wantTerm(t *testing.T, what string, e *entry, want time.Duration) {
	t.Helper()
	if got := time.Until(e.ExpiresAt); got < want-time.Minute || got > want {
		t.Errorf("%s: expires in %s, want %s", what, got.Round(time.Minute), want)
	}
}

// The same finding again doubles the wait; a check our side could not make
// neither grows the streak nor resets it; anything new starts over.
func TestRecordStreak(t *testing.T) {
	cfg := backoffCfg()
	st := &state{Networks: map[string]map[string]*entry{}}
	eps := []endpoint{{port: 443}}
	blocked := probe.Report{Verdict: probe.BlockedTLS, Reason: "tls: EOF", TestedIP: "192.0.2.1"}
	step := func(what string, rep probe.Report, wantVerdict probe.Verdict, wantStreak int, want time.Duration) {
		t.Helper()
		record(cfg, st, "n", "a.example", rep, eps, false, false)
		e, _ := st.get("n", "a.example")
		if e.Verdict != wantVerdict || e.Streak != wantStreak {
			t.Fatalf("%s: %s streak %d, want %s streak %d", what, e.Verdict, e.Streak, wantVerdict, wantStreak)
		}
		wantTerm(t, what, e, want)
	}
	step("first", blocked, probe.BlockedTLS, 0, time.Hour)
	step("again", blocked, probe.BlockedTLS, 1, 2*time.Hour)
	quic := blocked
	quic.Verdict = probe.BlockedQUIC
	step("blocked on another port", quic, probe.BlockedQUIC, 2, 4*time.Hour)
	unmeasured := probe.Report{Verdict: probe.Inconcl, Reason: "direct DNS did not answer", Unmeasured: true}
	step("our side failed", unmeasured, probe.BlockedQUIC, 2, time.Hour)
	both := probe.Report{Verdict: probe.Inconcl, Reason: "fails the same on both paths: tls: EOF"}
	step("measured, not overturned", both, probe.BlockedQUIC, 3, 8*time.Hour)
	slower := probe.Report{Verdict: probe.Slower, Reason: "slower"}
	step("something new", slower, probe.Slower, 0, time.Hour)
	clean := probe.Report{Verdict: probe.Clean, TestedIP: "192.0.2.1"}
	step("clean", clean, probe.Clean, 0, cfg.TTL)
}

// An INCONCLUSIVE name that stays so -- an IPv6 node the direct path does not
// reach -- backs off like any other repeat.
func TestRecordInconclusiveRepeat(t *testing.T) {
	cfg := backoffCfg()
	st := &state{Networks: map[string]map[string]*entry{}}
	rep := probe.Report{Verdict: probe.Inconcl, DirectNoV6: true, TestedIP: "2001:db8::1"}
	for i, want := range []time.Duration{time.Hour, 2 * time.Hour, 4 * time.Hour} {
		record(cfg, st, "n", "v6.example", rep, []endpoint{{port: 443}}, true, true)
		e, _ := st.get("n", "v6.example")
		if e.Streak != i || !e.DirectDown {
			t.Fatalf("check %d: streak %d, direct down %v", i, e.Streak, e.DirectDown)
		}
		wantTerm(t, "repeat", e, want)
	}
}

// One SLOWER keeps a CLEAN and looks again soon; the second in a row reverts it.
func TestRecordSlowOnce(t *testing.T) {
	cfg := backoffCfg()
	st := &state{Networks: map[string]map[string]*entry{}}
	eps := []endpoint{{port: 443}}
	clean := probe.Report{Verdict: probe.Clean, TestedIP: "192.0.2.1"}
	slower := probe.Report{Verdict: probe.Slower, Reason: "direct path is slower"}

	record(cfg, st, "n", "a.example", clean, eps, false, false)
	if record(cfg, st, "n", "a.example", slower, eps, false, false) {
		t.Fatal("the first SLOWER changed the verdict")
	}
	e, _ := st.get("n", "a.example")
	if e.Verdict != probe.Clean || !e.SlowOnce || e.Reverts != 0 {
		t.Fatalf("after one SLOWER: %s, slow once %v, reverts %d", e.Verdict, e.SlowOnce, e.Reverts)
	}
	wantTerm(t, "kept CLEAN", e, cfg.FailTTL)

	// clean on the next look: the mark goes
	record(cfg, st, "n", "a.example", clean, eps, false, false)
	if e, _ := st.get("n", "a.example"); e.SlowOnce {
		t.Fatal("a CLEAN check left the slow mark")
	}

	record(cfg, st, "n", "a.example", slower, eps, false, false)
	if !record(cfg, st, "n", "a.example", slower, eps, false, false) {
		t.Fatal("the second SLOWER in a row did not change the verdict")
	}
	if e, _ := st.get("n", "a.example"); e.Verdict != probe.Slower || e.Reverts != 1 {
		t.Fatalf("after two SLOWER: %s, reverts %d", e.Verdict, e.Reverts)
	}

	// the direct path failing somewhere is not a slow moment: no second chance
	st2 := &state{Networks: map[string]map[string]*entry{}}
	record(cfg, st2, "n", "b.example", clean, eps, false, false)
	record(cfg, st2, "n", "b.example", slower, eps, true, false)
	if e, _ := st2.get("n", "b.example"); e.Verdict == probe.Clean {
		t.Fatal("a SLOWER with the direct path down elsewhere kept CLEAN")
	}
}

func TestLearnV6(t *testing.T) {
	st := &state{Networks: map[string]map[string]*entry{}}
	if _, now := st.learnV6("n", 2, false); now || st.directNoV6("n") {
		t.Fatal("two misses made it")
	}
	if _, now := st.learnV6("n", 1, true); now {
		t.Fatal("a reached node still made it")
	}
	// reached started the count over
	st.learnV6("n", 2, false)
	until, now := st.learnV6("n", 1, false)
	if !now || !st.directNoV6("n") || time.Until(until) < v6Hold-time.Minute {
		t.Fatalf("three misses in a row: now %v, until %s", now, until)
	}
	if _, again := st.learnV6("n", 5, false); again {
		t.Fatal("misses while it holds started it again")
	}
	if st.directNoV6("other") {
		t.Fatal("another network took it")
	}
	st.V6["n"].NoneUntil = time.Now().Add(-time.Second)
	if st.directNoV6("n") {
		t.Fatal("it outlived its hold")
	}
}

func TestGate(t *testing.T) {
	g := &gate{interval: time.Minute}
	up := func() (bool, string, error) { return true, "60 ms", nil }
	down := func() (bool, string, error) { return false, "no answer at 00:37:21", nil }
	broken := func() (bool, string, error) { return false, "", errors.New("connection refused") }
	t0 := time.Date(2026, 9, 24, 8, 0, 0, 0, time.Local)

	for i, tc := range []struct {
		at     time.Duration
		health func() (bool, string, error)
		want   bool
	}{
		{0, up, true},               // the first tick
		{time.Minute, up, true},     // a tick on time
		{10 * time.Hour, up, false}, // woke up: one cycle waits
		{10*time.Hour + time.Minute, up, true},
		{10*time.Hour + 2*time.Minute, down, false},
		{10*time.Hour + 3*time.Minute, broken, false},
		{10*time.Hour + 4*time.Minute, up, true},
	} {
		if got := g.allow(t0.Add(tc.at), tc.health); got != tc.want {
			t.Errorf("tick %d: %v, want %v", i, got, tc.want)
		}
	}
}

func TestTunnelHealth(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/proxies/awg" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(body))
	}))
	defer srv.Close()
	a := newAPI(strings.TrimPrefix(srv.URL, "http://"), "")
	hist := func(ago time.Duration, delay int) string {
		return `{"alive":true,"history":[{"time":"2026-01-01T00:00:00Z","delay":1},{"time":"` +
			time.Now().Add(-ago).Format(time.RFC3339Nano) + `","delay":` + strconv.Itoa(delay) + `}]}`
	}
	now := time.Now().Format(time.RFC3339Nano)
	for _, tc := range []struct {
		name, body string
		want       bool
	}{
		{"core just started", `{"alive":true,"history":[]}`, true},
		{"last check answered", hist(10*time.Second, 64), true},
		{"last check failed", hist(10*time.Second, 0), false},
		{"no fresh check", hist(10*time.Minute, 64), false},
		// the IPv6 check failed last, the liveness one passed: up
		{"by the liveness URL", `{"history":[{"time":"` + now + `","delay":0}],` +
			`"extra":{"` + HealthURL + `":` + hist(10*time.Second, 64) + `}}`, true},
	} {
		body = tc.body
		ok, note, err := a.tunnelHealth("awg")
		if err != nil || ok != tc.want {
			t.Errorf("%s: %v %q %v, want %v", tc.name, ok, note, err, tc.want)
		}
	}
	if _, _, err := a.tunnelHealth("missing"); err == nil {
		t.Error("an unknown proxy gave no error")
	}
}
