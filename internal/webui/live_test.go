package webui

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dpiswitch/internal/ctl"
)

func TestLiveProto(t *testing.T) {
	for _, c := range []struct {
		net     string
		port    int
		sniffed bool
		want    string
		sure    bool
	}{
		{"tcp", 443, true, "TLS", true},
		{"tcp", 443, false, "TLS", false},
		{"tcp", 8443, false, "TLS", false},
		{"udp", 443, true, "QUIC", true},
		{"tcp", 80, true, "HTTP", true},
		{"tcp", 8880, false, "HTTP", false},
		{"udp", 53, false, "DNS", false},
		{"tcp", 53, false, "DNS", false},
		{"udp", 80, false, "UDP", false},
		{"tcp", 22, false, "TCP", false},
		{"udp", 51413, false, "UDP", false},
	} {
		if got, sure := liveProto(c.net, c.port, c.sniffed); got != c.want || sure != c.sure {
			t.Errorf("%s/%d sniffed %v: %s %v, want %s %v", c.net, c.port, c.sniffed, got, sure, c.want, c.sure)
		}
	}
}

func TestLiveRoute(t *testing.T) {
	for chains, want := range map[string]string{
		"DIRECT":        "direct",
		"DIRECT,tunnel": "direct", // the group fell back: the connection went direct
		"awg,tunnel":    "awg",
		"awg2,tunnel2":  "awg2",
		"awg,tunnel2":   "awg",
		"REJECT":        "reject",
		"":              "other",
	} {
		var cs []string
		if chains != "" {
			cs = strings.Split(chains, ",")
		}
		if got := liveRoute(cs); got != want {
			t.Errorf("%q: %s, want %s", chains, got, want)
		}
	}
	if got := liveChain([]string{"awg2", "tunnel2"}); got != "tunnel2 → awg2" {
		t.Errorf("chain: %q", got)
	}
}

// testHub: a hub driven by hand. The core's run it asks is the test's to
// set: the machine's own service may have written one.
func testHub() *liveHub {
	h := newLiveHub(nil)
	h.runOf = func() string { return "" }
	return h
}

// watch: a page on a hub driven by hand, without its loop
func watch(h *liveHub) *liveSub {
	sub := &liveSub{ch: make(chan []byte, 8)}
	h.subs[sub] = struct{}{}
	return sub
}

func next(t *testing.T, sub *liveSub) liveMsg {
	t.Helper()
	select {
	case b := <-sub.ch:
		var m liveMsg
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return m
	default:
		t.Fatal("no message")
	}
	return liveMsg{}
}

// What changed between two answers of the core reaches the page: new
// connections, their bytes and speeds, the ones gone -- and nothing for a
// connection that stood still and was already shown standing.
func TestLiveUpdate(t *testing.T) {
	h := testHub()
	sub := watch(h)
	t0 := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	conn := func(id string, up, down int64, start time.Time) ctl.LiveConn {
		return ctl.LiveConn{ID: id, Host: id + ".example", Port: 443, Network: "tcp",
			Chains: []string{"awg", "tunnel"}, Rule: "Match", Start: start, Upload: up, Download: down}
	}

	h.update(ctl.Live{UploadTotal: 100, DownloadTotal: 1000, Conns: []ctl.LiveConn{
		conn("a", 100, 1000, t0.Add(-5*time.Second)), conn("b", 0, 0, t0.Add(-time.Second))}}, nil, t0)
	m := next(t, sub)
	if !m.Ready || len(m.Add) != 2 || m.Add[0].US != 0 || m.Add[0].DS != 0 || m.Tot.DS != 0 {
		t.Fatalf("first answer: %+v", m)
	}
	if r := m.Add[0]; r.Proto != "TLS" || r.Route != "awg" || r.Chain != "tunnel → awg" || r.Rule != "Match" ||
		r.Start != t0.Add(-5*time.Second).UnixMilli() || r.Act != t0.UnixMilli() {
		t.Errorf("a row: %+v", r)
	}

	t1 := t0.Add(time.Second)
	h.update(ctl.Live{UploadTotal: 450, DownloadTotal: 6500, Conns: []ctl.LiveConn{
		conn("a", 300, 5000, t0.Add(-5*time.Second)), conn("c", 50, 500, t1.Add(-500*time.Millisecond))}}, nil, t1)
	m = next(t, sub)
	if len(m.Upd) != 1 || m.Upd[0] != (liveUpd{"a", 300, 5000, 200, 4000, t1.UnixMilli()}) {
		t.Errorf("a's update: %+v", m.Upd)
	}
	// c lived half a second: its bytes over that half
	if len(m.Add) != 1 || m.Add[0].ID != "c" || m.Add[0].US != 100 || m.Add[0].DS != 1000 {
		t.Errorf("c added: %+v", m.Add)
	}
	if len(m.Gone) != 1 || m.Gone[0] != (liveGone{"b", t1.UnixMilli(), 1}) {
		t.Errorf("b gone: %+v", m.Gone)
	}
	if m.Tot.US != 350 || m.Tot.DS != 5500 {
		t.Errorf("totals: %+v", m.Tot)
	}
	if len(h.closed) != 1 || h.closed[0].ID != "b" || h.closed[0].End != t1.UnixMilli() {
		t.Errorf("closed kept: %+v", h.closed)
	}

	// standing still: the speed drops to nothing once, then no news
	t2 := t1.Add(time.Second)
	h.update(ctl.Live{Conns: []ctl.LiveConn{conn("a", 300, 5000, t0), conn("c", 50, 500, t1)}}, nil, t2)
	m = next(t, sub)
	if len(m.Upd) != 2 || m.Upd[0].US != 0 || m.Upd[0].DS != 0 || m.Upd[0].Act == t2.UnixMilli() {
		t.Errorf("stood still: %+v", m.Upd)
	}
	h.update(ctl.Live{Conns: []ctl.LiveConn{conn("a", 300, 5000, t0), conn("c", 50, 500, t1)}}, nil, t2.Add(time.Second))
	if m = next(t, sub); len(m.Upd)+len(m.Add)+len(m.Gone) != 0 {
		t.Errorf("nothing changed, yet: %+v", m)
	}

	// the core tells more of a connection it tracks: the row follows, and
	// goes to the pages whole
	learnt := conn("a", 300, 5000, t0)
	learnt.Host, learnt.Sniffed, learnt.Process = "a.example.org", true, "chrome.exe"
	h.update(ctl.Live{Conns: []ctl.LiveConn{learnt, conn("c", 50, 500, t1)}}, nil, t2.Add(1500*time.Millisecond))
	if m = next(t, sub); len(m.Add) != 1 || m.Add[0].Host != "a.example.org" || !m.Add[0].Sure || m.Add[0].Proc != "chrome.exe" ||
		m.Add[0].Up != 300 || len(m.Upd) != 0 {
		t.Errorf("metadata learnt later: %+v %+v", m.Add, m.Upd)
	}

	// a core slow to answer still holds its connections
	h.update(ctl.Live{}, errors.New("timeout"), t2.Add(2*time.Second))
	if m = next(t, sub); m.Down != "error" || m.Err != "timeout" || len(m.Gone) != 0 || len(h.open) != 2 {
		t.Errorf("an error: %+v, %d open", m, len(h.open))
	}
	// a core gone holds none
	h.update(ctl.Live{}, ctl.ErrCoreDown, t2.Add(3*time.Second))
	if m = next(t, sub); m.Down != "stopped" || len(m.Gone) != 2 || len(h.open) != 0 || len(h.closed) != 3 {
		t.Errorf("the core gone: %+v, %d open, %d closed", m, len(h.open), len(h.closed))
	}
	// and back: a new run, sent whole
	h.update(ctl.Live{Conns: []ctl.LiveConn{conn("d", 1, 1, t2)}}, nil, t2.Add(4*time.Second))
	if m = next(t, sub); m.Kind != "full" || m.Down != "" || len(m.Conns) != 1 || len(m.Closed) != 0 {
		t.Errorf("the core back: %+v", m)
	}
}

// A new run of the core starts the history anew: seen gone and back, or its
// totals counted from nothing again. A failure its log told already stays.
func TestLiveNewRun(t *testing.T) {
	h := testHub()
	h.failID = "f-"
	sub := watch(h)
	ctx := context.Background()
	t0 := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	conn := func(id string) ctl.LiveConn {
		return ctl.LiveConn{ID: id, Host: id + ".example", Port: 443, Network: "tcp", Chains: []string{"DIRECT"}, Start: t0}
	}
	fail := func(host string, at time.Time) {
		h.failure(ctx, "", ctl.DialErr{Network: "tcp", Proxy: "DIRECT", Host: host, Port: 443, Err: "i/o timeout"}, []string{"DIRECT"}, at)
	}
	h.update(ctl.Live{UploadTotal: 10, DownloadTotal: 10, Conns: []ctl.LiveConn{conn("a"), conn("b")}}, nil, t0)
	h.update(ctl.Live{UploadTotal: 20, DownloadTotal: 20, Conns: []ctl.LiveConn{conn("a")}}, nil, t0.Add(time.Second))
	fail("old.example", t0.Add(1500*time.Millisecond))
	sess := h.sess
	h.update(ctl.Live{}, ctl.ErrCoreDown, t0.Add(2*time.Second))
	if len(h.closed) != 2 || len(h.failed) != 1 || h.sess != sess {
		t.Fatalf("the core gone: %d closed, %d failed -- they stay until it runs anew", len(h.closed), len(h.failed))
	}
	// the new core's log is read before its connections are: the same
	// failure as the old run's is a row of its own
	fail("new.example", t0.Add(3*time.Second))
	fail("old.example", t0.Add(3500*time.Millisecond))
	for len(sub.ch) > 0 {
		<-sub.ch
	}
	h.update(ctl.Live{UploadTotal: 1, DownloadTotal: 1, Conns: []ctl.LiveConn{conn("c")}}, nil, t0.Add(4*time.Second))
	m := next(t, sub)
	if m.Kind != "full" || m.Sess == sess || m.Sess != h.sess || len(m.Conns) != 1 || len(m.Closed) != 0 ||
		len(m.Failed) != 2 || m.Failed[0].Host != "new.example" || m.Failed[1].Host != "old.example" ||
		m.Failed[1].N != 1 || m.Failed[1].Start != t0.Add(3500*time.Millisecond).UnixMilli() {
		t.Fatalf("the new run: %+v", m)
	}
	// restarted between two calls: the totals are counted from nothing again
	h.update(ctl.Live{UploadTotal: 50, DownloadTotal: 50}, nil, t0.Add(5*time.Second))
	if m = next(t, sub); m.Kind != "tick" || len(h.closed) != 1 {
		t.Fatalf("the same run: %+v, %d closed", m, len(h.closed))
	}
	sess = h.sess
	h.update(ctl.Live{UploadTotal: 3, DownloadTotal: 3, Conns: []ctl.LiveConn{conn("d")}}, nil, t0.Add(6*time.Second))
	if m = next(t, sub); m.Kind != "full" || h.sess == sess || len(h.closed) != 0 || len(m.Conns) != 1 || m.Conns[0].ID != "d" {
		t.Fatalf("restarted unseen: %+v, %d closed", m, len(h.closed))
	}
}

// The service names each run of the core. A core started anew between two
// calls is told by it, its totals grown past the last run's and all; and a
// failure the old run counted is not counted on in the new one, though the
// new core's log tells it before the loop sees the core anew.
func TestLiveNewRunByMarker(t *testing.T) {
	h := testHub()
	h.failID = "f-"
	run := "100 1"
	h.runOf = func() string { return run }
	sub := watch(h)
	ctx := context.Background()
	t0 := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	conn := func(id string) ctl.LiveConn {
		return ctl.LiveConn{ID: id, Host: id + ".example", Port: 443, Network: "tcp", Chains: []string{"DIRECT"}, Start: t0}
	}
	e := ctl.DialErr{Network: "tcp", Proxy: "DIRECT", Process: "chrome.exe", Host: "example.com", Port: 443, Err: "i/o timeout"}
	direct := []string{"DIRECT"}
	h.update(ctl.Live{UploadTotal: 100, DownloadTotal: 100, Conns: []ctl.LiveConn{conn("a")}}, nil, t0)
	for i := range 5 {
		h.failure(ctx, run, e, direct, t0.Add(time.Duration(i)*time.Second))
	}
	h.update(ctl.Live{UploadTotal: 200, DownloadTotal: 200}, nil, t0.Add(5*time.Second))
	if len(h.failed) != 1 || h.failed[0].N != 5 || len(h.closed) != 1 {
		t.Fatalf("the old run: %d failed, %d closed", len(h.failed), len(h.closed))
	}
	for len(sub.ch) > 0 {
		<-sub.ch
	}
	sess := h.sess
	run = "200 2"
	h.failure(ctx, run, e, direct, t0.Add(6*time.Second))
	// the old core's stream still held a line, read once the new run is
	// named: it is the old run's all the same
	stale := e
	stale.Host = "stale.example"
	h.failure(ctx, "100 1", stale, direct, t0.Add(6500*time.Millisecond))
	h.update(ctl.Live{UploadTotal: 500, DownloadTotal: 500, Conns: []ctl.LiveConn{conn("b")}}, nil, t0.Add(7*time.Second))
	m := next(t, sub)
	if m.Kind != "full" || m.Sess == sess || len(m.Closed) != 0 || len(m.Conns) != 1 {
		t.Fatalf("started anew, totals grown: %+v", m)
	}
	if len(m.Failed) != 1 || m.Failed[0].N != 1 || m.Failed[0].Start != t0.Add(6*time.Second).UnixMilli() {
		t.Fatalf("the failure in the new run: %+v", m.Failed)
	}
	// counted on in its own run
	h.failure(ctx, run, e, direct, t0.Add(8*time.Second))
	if len(h.failed) != 1 || h.failed[0].N != 2 {
		t.Fatalf("again in the new run: %+v", h.failed)
	}
	// the same run: no new history, whatever the totals
	h.update(ctl.Live{UploadTotal: 1, DownloadTotal: 1, Conns: []ctl.LiveConn{conn("c")}}, nil, t0.Add(9*time.Second))
	if m = next(t, sub); m.Kind != "tick" || h.sess != m.Sess {
		t.Fatalf("the same run: %+v", m)
	}
}

// A run's name not read at one call -- the service replacing the file that
// moment -- is no run of its own: it used to wipe the last one known, and a
// core started anew by the next call went by unseen.
func TestLiveRunNameNotRead(t *testing.T) {
	h := testHub()
	run := "100 1"
	h.runOf = func() string { return run }
	sub := watch(h)
	t0 := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	conn := func(id string) ctl.LiveConn {
		return ctl.LiveConn{ID: id, Port: 443, Network: "tcp", Chains: []string{"DIRECT"}, Start: t0}
	}
	h.update(ctl.Live{UploadTotal: 10, DownloadTotal: 10, Conns: []ctl.LiveConn{conn("a")}}, nil, t0)
	run = ""
	h.update(ctl.Live{UploadTotal: 20, DownloadTotal: 20, Conns: []ctl.LiveConn{conn("a")}}, nil, t0.Add(time.Second))
	for len(sub.ch) > 0 {
		<-sub.ch
	}
	sess := h.sess
	run = "200 2"
	h.update(ctl.Live{UploadTotal: 900, DownloadTotal: 900, Conns: []ctl.LiveConn{conn("b")}}, nil, t0.Add(2*time.Second))
	if m := next(t, sub); m.Kind != "full" || m.Sess == sess || len(m.Closed) != 0 {
		t.Fatalf("a core started anew past a name not read: %+v", m)
	}
}

// A page coming back to the history it holds gets only what came since the
// last it saw; one holding another gets it all.
func TestLiveSince(t *testing.T) {
	h := testHub()
	h.running = true // no loop: the hub is driven by hand
	t0 := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	conn := func(id string) ctl.LiveConn {
		return ctl.LiveConn{ID: id, Port: 443, Network: "tcp", Chains: []string{"DIRECT"}, Start: t0}
	}
	h.update(ctl.Live{Conns: []ctl.LiveConn{conn("a"), conn("b"), conn("c")}}, nil, t0)
	h.update(ctl.Live{Conns: []ctl.LiveConn{conn("c")}}, nil, t0.Add(time.Second))
	seen := h.closed[len(h.closed)-1].Seq
	h.update(ctl.Live{}, nil, t0.Add(2*time.Second))
	take := func(sess string, since int64) liveMsg {
		sub, b := h.join(sess, since)
		h.leave(sub)
		var m liveMsg
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if m := take(h.sess, seen); !m.Part || len(m.Closed) != 1 || m.Closed[0].ID != "c" {
		t.Errorf("coming back: %+v", m)
	}
	if m := take("other", seen); m.Part || len(m.Closed) != 3 {
		t.Errorf("another history: %+v", m)
	}
	if m := take(h.sess, 0); m.Part || len(m.Closed) != 3 {
		t.Errorf("a page new to it: %+v", m)
	}
}

// The closed ones kept are the newest liveKeep, whatever their age.
func TestLiveTrim(t *testing.T) {
	h := testHub()
	old := time.Now().Add(-30 * 24 * time.Hour).UnixMilli()
	for i := range liveKeep + 20 {
		h.closed = append(h.closed, &liveRow{ID: fmt.Sprint(i), End: old})
	}
	h.trim()
	if len(h.closed) != liveKeep || h.closed[0].ID != "20" {
		t.Fatalf("%d kept, the first %s", len(h.closed), h.closed[0].ID)
	}
}

// fakeCore: a core's controller with one connection, counting the calls
type fakeCore struct {
	srv    *httptest.Server
	gets   atomic.Int64
	logs   atomic.Int64 // log streams open
	mu     sync.Mutex
	closed []string
}

func newFakeCore(t *testing.T) *fakeCore {
	c := &fakeCore{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/connections":
			n := c.gets.Add(1)
			fmt.Fprintf(w, `{"downloadTotal":%d,"uploadTotal":%d,"memory":52428800,"connections":[
{"id":"0d5f2a7e-1111-4c3b-9a7e-2b1c3d4e5f60","metadata":{"network":"tcp","type":"Tun","sourceIP":"198.18.0.1",
"destinationIP":"","sourcePort":"50000","destinationPort":"443","host":"example.com","sniffHost":"",
"process":"chrome.exe","processPath":"C:\\chrome.exe","remoteDestination":"93.184.216.34","inboundName":""},
"upload":%d,"download":%d,"start":"2026-09-27T12:00:00.123+03:00","chains":["awg","tunnel"],"rule":"Match","rulePayload":""},
{"id":"0d5f2a7e-2222-4c3b-9a7e-2b1c3d4e5f60","metadata":{"network":"udp","type":"Tun","sourceIP":"198.18.0.1",
"destinationIP":"142.250.74.46","sourcePort":"50001","destinationPort":"443","host":"","sniffHost":"www.youtube.com",
"process":"chrome.exe","processPath":"C:\\chrome.exe","remoteDestination":"203.0.113.9","inboundName":""},
"upload":1,"download":1,"start":"2026-09-27T12:00:01+03:00","chains":["DIRECT"],"rule":"RuleSet","rulePayload":"direct-verified"}]}`,
				n*1000, n*100, n*100, n*1000)
		case r.Method == "GET" && r.URL.Path == "/proxies":
			fmt.Fprint(w, `{"proxies":{"tunnel":{"type":"Fallback","now":"awg"},"awg":{"type":"WireGuard"},"DIRECT":{"type":"Direct"}}}`)
		case r.Method == "GET" && r.URL.Path == "/logs":
			c.logs.Add(1)
			defer c.logs.Add(-1)
			for _, p := range []string{
				"[Metadata] not valid",
				"[TCP] dial tunnel (match Match/) 198.18.0.1:50427(chrome.exe) --> blocked.example:443 error: dial tcp 203.0.113.7:443: i/o timeout",
				"[TCP] dial tunnel (match Match/) 198.18.0.1:50428(chrome.exe) --> blocked.example:443 error: dial tcp 203.0.113.7:443: i/o timeout",
			} {
				fmt.Fprintf(w, "{\"type\":\"warning\",\"payload\":%q}\n", p)
			}
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/connections/"):
			c.mu.Lock()
			c.closed = append(c.closed, strings.TrimPrefix(r.URL.Path, "/connections/"))
			c.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(c.srv.Close)
	return c
}

// liveTest: the UI over a fake core, the loop sped up. The loop is waited
// for at the end: it must not outlive the test, nor read the timings the
// cleanup puts back.
func liveTest(t *testing.T) (*Server, *fakeCore, *httptest.Server) {
	s, _ := testServer(t)
	core := newFakeCore(t)
	oldAddr, oldEvery, oldRetry := apiAddr, liveEvery, liveRetry
	apiAddr = strings.TrimPrefix(core.srv.URL, "http://")
	liveEvery, liveRetry = 20*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { apiAddr, liveEvery, liveRetry = oldAddr, oldEvery, oldRetry })
	ui := httptest.NewServer(s.Handler())
	t.Cleanup(func() {
		ui.Close()
		done := make(chan struct{})
		go func() { s.live.stop(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the loop did not stop")
		}
	})
	return s, core, ui
}

// The stream brings the connections and the failures; the core is asked on
// with no page watching, and what it told is kept for the page coming back.
func TestLiveStream(t *testing.T) {
	s, core, ui := liveTest(t)
	if n := core.gets.Load(); n != 0 {
		t.Fatalf("the core asked %d times before the UI started gathering", n)
	}
	resp, err := http.Get(ui.URL + "/live/stream")
	if err != nil {
		t.Fatal(err)
	}
	if ct := resp.Header.Get("Content-Type"); resp.StatusCode != 200 || ct != "text/event-stream" {
		t.Fatalf("%d %s", resp.StatusCode, ct)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(nil, 1<<20)
	var full, withRows liveMsg
	var fails []*liveRow
	for sc.Scan() && (withRows.Kind == "" || len(fails) == 0 || fails[len(fails)-1].N < 2) {
		data, ok := strings.CutPrefix(sc.Text(), "data: ")
		if !ok {
			continue
		}
		var m liveMsg
		if err := json.Unmarshal([]byte(data), &m); err != nil {
			t.Fatal(err)
		}
		if full.Kind == "" {
			full = m
			continue
		}
		if len(m.Add) > 0 || len(m.Conns) > 0 {
			withRows = m
		}
		fails = append(fails, m.Fail...)
	}
	if full.Kind != "full" {
		t.Fatalf("the first message: %+v", full)
	}
	rows := append(withRows.Add, withRows.Conns...)
	if len(rows) != 2 {
		t.Fatalf("rows: %+v", withRows)
	}
	byID := map[string]*liveRow{}
	for _, r := range rows {
		byID[r.ID[9:13]] = r
	}
	// the address a name went to is the one its TCP outbound dialled; a UDP
	// one names the tunnel's server there, and its own stays
	if r := byID["1111"]; r.Host != "example.com" || r.IP != "93.184.216.34" || r.Proto != "TLS" || r.Sure ||
		r.Route != "awg" || r.Chain != "tunnel → awg" || r.Proc != "chrome.exe" || r.Port != 443 {
		t.Errorf("tcp row: %+v", r)
	}
	if r := byID["2222"]; r.Host != "www.youtube.com" || r.IP != "142.250.74.46" || r.Proto != "QUIC" || !r.Sure ||
		r.Route != "direct" || r.Rule != "RuleSet direct-verified" {
		t.Errorf("udp row: %+v", r)
	}
	if withRows.Tot.Mem != 52428800 {
		t.Errorf("totals: %+v", withRows.Tot)
	}
	// the same failure twice is one row, counted twice; the other warning
	// is none
	if len(fails) == 0 {
		t.Fatal("no failure came")
	}
	f := fails[len(fails)-1]
	for _, g := range fails {
		if g.ID != f.ID {
			t.Errorf("the same failure on two rows: %s, %s", g.ID, f.ID)
		}
	}
	if f.N != 2 || f.Why != "timeout" || f.Host != "blocked.example" || f.IP != "203.0.113.7" || f.Route != "awg" ||
		f.Chain != "tunnel → awg" || f.Proc != "chrome.exe" || f.Proto != "TLS" || f.Rule != "Match" || f.Probe {
		t.Errorf("the failure: %+v", f)
	}

	resp.Body.Close()
	// no page watches: the core is asked all the same, and the state stays
	n := core.gets.Load()
	time.Sleep(10 * liveEvery)
	if m := core.gets.Load(); m == n {
		t.Error("the core no longer asked with no page open: what closes meanwhile is lost")
	}
	s.live.mu.Lock()
	open, failed := len(s.live.open), len(s.live.failed)
	s.live.mu.Unlock()
	if open != 2 || failed != 1 {
		t.Errorf("state with no page: %d open, %d failed", open, failed)
	}
	// once stopped, the core's log is no longer read
	s.live.stop()
	for deadline := time.Now().Add(5 * time.Second); core.logs.Load() != 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d log streams still open after the loop stopped", core.logs.Load())
		}
	}
}

// The UI gathers from its start, before any page opens.
func TestLiveGathersFromStart(t *testing.T) {
	s, core, _ := liveTest(t)
	s.live.start()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		s.live.mu.Lock()
		open := len(s.live.open)
		s.live.mu.Unlock()
		if open == 2 && core.gets.Load() > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("nothing gathered with no page: %d open", open)
		}
	}
}

// Two pages share one loop.
func TestLiveTwoPages(t *testing.T) {
	s, _, _ := liveTest(t)
	a, _ := s.live.join("", 0)
	b, _ := s.live.join("", 0)
	// the page left open reads its ticks: one that does not is dropped
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range b.ch {
		}
	}()
	s.live.leave(a)
	time.Sleep(5 * liveEvery)
	s.live.mu.Lock()
	running, subs := s.live.running, len(s.live.subs)
	s.live.mu.Unlock()
	if !running || subs != 1 {
		t.Errorf("one page still open: running %v, %d watching", running, subs)
	}
	// it leaves; its channel is closed here, unless the hub dropped it first
	s.live.mu.Lock()
	if _, ok := s.live.subs[b]; ok {
		delete(s.live.subs, b)
		close(b.ch)
	}
	s.live.mu.Unlock()
	<-done
}

func TestLiveClose(t *testing.T) {
	s, core, _ := liveTest(t)
	h := s.Handler()
	id := "0d5f2a7e-1111-4c3b-9a7e-2b1c3d4e5f60"
	if w := do(t, h, "POST", "/act/liveclose", url.Values{"id": {id}}, nil); w.Code != 204 {
		t.Fatalf("close: %d %s", w.Code, w.Body)
	}
	core.mu.Lock()
	got := core.closed
	core.mu.Unlock()
	if len(got) != 1 || got[0] != id {
		t.Errorf("the core closed %v", got)
	}
	for _, bad := range []string{"", "../configs", "a b", strings.Repeat("a", 65)} {
		if w := do(t, h, "POST", "/act/liveclose", url.Values{"id": {bad}}, nil); w.Code != 400 {
			t.Errorf("id %q: %d", bad, w.Code)
		}
	}
	if w := do(t, h, "GET", "/act/liveclose?id="+id, nil, nil); w.Code != 405 {
		t.Errorf("GET: %d", w.Code)
	}
	// from another site's page
	if w := do(t, h, "POST", "/act/liveclose", url.Values{"id": {id}}, map[string]string{"Origin": "http://evil.example"}); w.Code != 403 {
		t.Errorf("cross-origin: %d", w.Code)
	}
}

// The stream and the close want the key like every other request.
func TestLiveKey(t *testing.T) {
	s, core, _ := liveTest(t)
	s.Key = strings.Repeat("ab", 32)
	h := s.Handler()
	if w := do(t, h, "GET", "/live/stream", nil, nil); w.Code != 403 {
		t.Errorf("the stream without the key: %d", w.Code)
	}
	if w := do(t, h, "POST", "/act/liveclose", url.Values{"id": {"0d5f2a7e-1111-4c3b-9a7e-2b1c3d4e5f60"}}, nil); w.Code != 403 {
		t.Errorf("a close without the key: %d", w.Code)
	}
	if n := core.gets.Load(); n != 0 {
		t.Errorf("the core asked %d times for a refused page", n)
	}
	core.mu.Lock()
	defer core.mu.Unlock()
	if len(core.closed) != 0 {
		t.Errorf("closed without the key: %v", core.closed)
	}
}

// The page's script gets its words in the page's language.
func TestLiveWords(t *testing.T) {
	s, _ := testServer(t)
	w := do(t, s.Handler(), "GET", "/live", nil, map[string]string{"Cookie": "lang=ru"})
	body := w.Body.String()
	i := strings.Index(body, `<script type="application/json" id="lwords">`)
	j := strings.Index(body[max(i, 0):], "</script>")
	if i < 0 || j < 0 {
		t.Fatalf("no words in the page:\n%s", body)
	}
	var words map[string]string
	raw := body[i+len(`<script type="application/json" id="lwords">`) : i+j]
	if err := json.Unmarshal([]byte(raw), &words); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
	if words["direct"] != "Напрямую" || words["closedAgo"] != "закрыто %s назад" {
		t.Errorf("words: %v", words)
	}
	if !strings.Contains(body, `<a href="/live" class="on">Live</a>`) {
		t.Error("the menu does not mark the live page")
	}
}

// A failure is a row; the same one again, while its row is listed, is
// counted on it and goes to the pages once a tick however often it came.
func TestLiveFailure(t *testing.T) {
	h := testHub()
	h.failID = "f-"
	sub := watch(h)
	ctx := context.Background()
	t0 := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	e := ctl.DialErr{Network: "tcp", Proxy: "DIRECT", Rule: "RuleSet", RulePayload: "direct-verified", Process: "svchost.exe",
		Host: "login.live.com", Port: 443, Err: "interface not found"}
	direct := []string{"DIRECT"}

	h.failure(ctx, "", e, direct, t0)
	h.failure(ctx, "", e, direct, t0.Add(10*time.Second))
	// hours apart, the row still listed: the same one
	h.failure(ctx, "", e, direct, t0.Add(5*time.Minute))
	if len(h.failed) != 1 {
		t.Fatalf("%d rows for one failure", len(h.failed))
	}
	r := h.failed[0]
	if r.N != 3 || r.Start != t0.UnixMilli() || r.End != t0.Add(5*time.Minute).UnixMilli() || r.Why != "nonet" ||
		r.Route != "direct" || r.Rule != "RuleSet direct-verified" || r.Proto != "TLS" {
		t.Errorf("the row: %+v", r)
	}
	h.update(ctl.Live{}, nil, t0.Add(5*time.Minute+time.Second))
	if m := next(t, sub); len(m.Fail) != 1 || m.Fail[0].N != 3 {
		t.Errorf("sent: %+v", m.Fail)
	}
	h.update(ctl.Live{}, nil, t0.Add(5*time.Minute+2*time.Second))
	if m := next(t, sub); len(m.Fail) != 0 {
		t.Errorf("sent again with nothing new: %+v", m.Fail)
	}

	// another reason, another rule, another route: other rows
	at := t0.Add(6 * time.Minute)
	other := e
	other.Err = "dns resolve failed: couldn't find ip"
	h.failure(ctx, "", other, direct, at)
	byB := e
	byB.RulePayload = "force-direct"
	h.failure(ctx, "", byB, direct, at)
	h.failure(ctx, "", e, []string{"awg", "tunnel"}, at)
	if len(h.failed) != 4 || h.failed[1].Why != "dns" || h.failed[2].Rule != "RuleSet force-direct" ||
		h.failed[3].Route != "awg" || h.failed[3].Chain != "tunnel → awg" {
		t.Errorf("rows: %+v %+v %+v", h.failed[1], h.failed[2], h.failed[3])
	}

	// read after the loop stopped: not taken in
	done, cancel := context.WithCancel(ctx)
	cancel()
	h.failure(done, "", e, direct, t0.Add(7*time.Minute))
	if len(h.failed) != 4 || r.N != 3 {
		t.Errorf("a failure taken in after the loop stopped: %d rows, n %d", len(h.failed), r.N)
	}
}

// A failure counted again moves to the end, with the history's newest
// count: past liveKeep the rows cut are the ones failed longest ago, and a
// failure is never cut for its age.
func TestLiveFailedTrim(t *testing.T) {
	h := testHub()
	h.failID = "f-"
	ctx := context.Background()
	t0 := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	a := ctl.DialErr{Network: "tcp", Proxy: "DIRECT", Host: "a.example", Port: 443, Err: "i/o timeout"}
	b := a
	b.Host = "b.example"
	h.failure(ctx, "", a, []string{"DIRECT"}, t0)
	h.failure(ctx, "", b, []string{"DIRECT"}, t0.Add(time.Minute))
	h.failure(ctx, "", a, []string{"DIRECT"}, t0.Add(9*time.Minute))
	if h.failed[0].Host != "b.example" || h.failed[1].Host != "a.example" || h.failed[1].Seq <= h.failed[0].Seq {
		t.Fatalf("not in the order they last failed: %+v, %+v", h.failed[0], h.failed[1])
	}
	h.update(ctl.Live{}, nil, t0.Add(48*time.Hour))
	if len(h.failed) != 2 {
		t.Fatalf("failures cut for their age: %d left", len(h.failed))
	}
	// past liveKeep: b, failed longest ago, goes first, and is forgotten
	for i := range liveKeep - 1 {
		h.failed = append(h.failed, &liveRow{ID: fmt.Sprint(i)})
	}
	h.trim()
	if len(h.failed) != liveKeep || h.failed[0].Host != "a.example" {
		t.Fatalf("after the cut: %d rows, the first %s", len(h.failed), h.failed[0].Host)
	}
	h.failure(ctx, "", b, []string{"DIRECT"}, t0.Add(49*time.Hour))
	if r := h.failed[len(h.failed)-1]; r.Host != "b.example" || r.N != 1 {
		t.Errorf("b again: %+v", r)
	}
}

func TestKeepLast(t *testing.T) {
	var rows []*liveRow
	for i := range liveKeep + 3 {
		rows = append(rows, &liveRow{ID: fmt.Sprint(i)})
	}
	if kept := keepLast(rows); len(kept) != liveKeep || kept[0].ID != "3" {
		t.Fatalf("%d kept, the first %s", len(kept), kept[0].ID)
	}
	few := rows[:3]
	if got := keepLast(few); &got[0] != &few[0] || len(got) != 3 {
		t.Error("nothing to cut, yet copied")
	}
}

// Clear forgets the failures: the same one after it is a new row, counted
// from one -- it used to come back with the count and the first time from
// before -- and every page is told.
func TestLiveClear(t *testing.T) {
	h := testHub()
	h.failID = "f-"
	ctx := context.Background()
	t0 := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	e := ctl.DialErr{Network: "tcp", Proxy: "DIRECT", Host: "a.example", Port: 443, Err: "i/o timeout"}
	h.failure(ctx, "", e, []string{"DIRECT"}, t0)
	h.failure(ctx, "", e, []string{"DIRECT"}, t0.Add(10*time.Second))
	h.closed = []*liveRow{{ID: "x", End: t0.UnixMilli()}}
	first, sess := h.failed[0].ID, h.sess
	sub := watch(h)
	h.clear()
	if len(h.failed)+len(h.closed)+len(h.failKey)+len(h.failNew) != 0 {
		t.Fatalf("left after clear: %d failed, %d closed", len(h.failed), len(h.closed))
	}
	// every page drops what it held: a new history, sent whole
	if m := next(t, sub); m.Kind != "full" || m.Part || m.Sess == sess || len(m.Closed)+len(m.Failed) != 0 {
		t.Errorf("the pages after clear: %+v", m)
	}
	h.failure(ctx, "", e, []string{"DIRECT"}, t0.Add(20*time.Second))
	if r := h.failed[0]; r.N != 1 || r.ID == first || r.Start != t0.Add(20*time.Second).UnixMilli() {
		t.Errorf("after clear: %+v", r)
	}
}

func TestGroupChain(t *testing.T) {
	groups := map[string]string{"tunnel": "awg", "tunnel2": "tunnel", "fell": "DIRECT", "a": "b", "b": "a"}
	for name, want := range map[string]string{
		"tunnel":  "tunnel → awg",
		"tunnel2": "tunnel2 → tunnel → awg",
		"fell":    "fell → DIRECT",
		"DIRECT":  "DIRECT",
		"a":       "a → b", // a loop is cut
		"unknown": "unknown",
	} {
		if got := liveChain(groupChain(name, groups)); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
	// a tunnel group gone direct is direct
	if r := liveRoute(groupChain("fell", groups)); r != "direct" {
		t.Errorf("fell back: %s", r)
	}
	if r := liveRoute(groupChain("tunnel", nil)); r != "awg" {
		t.Errorf("no choices known: %s", r)
	}
}
