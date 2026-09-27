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
	h := newLiveHub(nil)
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
	if len(m.Gone) != 1 || m.Gone[0] != (liveGone{"b", t1.UnixMilli()}) {
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
	// and back
	h.update(ctl.Live{Conns: []ctl.LiveConn{conn("d", 1, 1, t2)}}, nil, t2.Add(4*time.Second))
	if m = next(t, sub); m.Down != "" || len(m.Add) != 1 {
		t.Errorf("the core back: %+v", m)
	}
}

// The closed ones kept are the newest, none older than liveClosedAge.
func TestLiveTrim(t *testing.T) {
	h := newLiveHub(nil)
	now := time.Now()
	for i := range liveClosedMax + 20 {
		h.closed = append(h.closed, &liveRow{ID: fmt.Sprint(i), End: now.UnixMilli()})
	}
	h.trim(now)
	if len(h.closed) != liveClosedMax || h.closed[0].ID != "20" {
		t.Fatalf("%d kept, the first %s", len(h.closed), h.closed[0].ID)
	}
	h.closed[0].End = now.Add(-liveClosedAge - time.Second).UnixMilli()
	h.trim(now)
	if len(h.closed) != liveClosedMax-1 || h.closed[0].ID != "21" {
		t.Fatalf("too old: %d kept, the first %s", len(h.closed), h.closed[0].ID)
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
	oldAddr, oldEvery, oldGrace, oldRetry := apiAddr, liveEvery, liveGrace, liveRetry
	apiAddr = strings.TrimPrefix(core.srv.URL, "http://")
	liveEvery, liveGrace, liveRetry = 20*time.Millisecond, 60*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { apiAddr, liveEvery, liveGrace, liveRetry = oldAddr, oldEvery, oldGrace, oldRetry })
	ui := httptest.NewServer(s.Handler())
	t.Cleanup(func() {
		ui.Close()
		done := make(chan struct{})
		go func() { s.live.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the loop still runs with no page watching")
		}
	})
	return s, core, ui
}

// The core is asked only while a page watches: the stream brings the
// connections, and once it closes the loop stops -- no call to the core
// after the grace.
func TestLiveStream(t *testing.T) {
	s, core, ui := liveTest(t)
	if n := core.gets.Load(); n != 0 {
		t.Fatalf("the core asked %d times before any page opened", n)
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
	// the loop stops after the grace; a call on the way may still land
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.live.mu.Lock()
		running := s.live.running
		s.live.mu.Unlock()
		if !running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the loop did not stop after the page left")
		}
		time.Sleep(10 * time.Millisecond)
	}
	n := core.gets.Load()
	time.Sleep(10 * liveEvery)
	if m := core.gets.Load(); m != n {
		t.Errorf("the core asked %d more times with no page open", m-n)
	}
	// nor is its log read
	s.live.wg.Wait()
	for deadline := time.Now().Add(5 * time.Second); core.logs.Load() != 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d log streams still open with no page", core.logs.Load())
		}
	}
	if len(s.live.open) != 0 || len(s.live.closed) != 0 || len(s.live.failed) != 0 || len(s.live.failKey) != 0 {
		t.Errorf("state kept with no page: %d open, %d closed, %d failed", len(s.live.open), len(s.live.closed), len(s.live.failed))
	}
}

// Two pages share one loop, and it outlives one of them.
func TestLiveTwoPages(t *testing.T) {
	s, _, _ := liveTest(t)
	a, _ := s.live.join()
	b, _ := s.live.join()
	// the page left open reads its ticks: one that does not is dropped
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range b.ch {
		}
	}()
	s.live.leave(a)
	time.Sleep(3 * liveGrace)
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
		s.live.left()
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
	h := newLiveHub(nil)
	h.failID = "f-"
	sub := watch(h)
	ctx := context.Background()
	t0 := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	e := ctl.DialErr{Network: "tcp", Proxy: "DIRECT", Rule: "RuleSet", RulePayload: "direct-verified", Process: "svchost.exe",
		Host: "login.live.com", Port: 443, Err: "interface not found"}
	direct := []string{"DIRECT"}

	h.failure(ctx, e, direct, t0)
	h.failure(ctx, e, direct, t0.Add(10*time.Second))
	// minutes apart, the row still listed: the same one
	h.failure(ctx, e, direct, t0.Add(5*time.Minute))
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
	h.failure(ctx, other, direct, at)
	byB := e
	byB.RulePayload = "force-direct"
	h.failure(ctx, byB, direct, at)
	h.failure(ctx, e, []string{"awg", "tunnel"}, at)
	if len(h.failed) != 4 || h.failed[1].Why != "dns" || h.failed[2].Rule != "RuleSet force-direct" ||
		h.failed[3].Route != "awg" || h.failed[3].Chain != "tunnel → awg" {
		t.Errorf("rows: %+v %+v %+v", h.failed[1], h.failed[2], h.failed[3])
	}

	// read after the loop stopped: not taken in
	done, cancel := context.WithCancel(ctx)
	cancel()
	h.failure(done, e, direct, t0.Add(7*time.Minute))
	if len(h.failed) != 4 || r.N != 3 {
		t.Errorf("a failure taken in after the loop stopped: %d rows, n %d", len(h.failed), r.N)
	}
}

// A failure counted again moves to the end, and the rows behind it are cut
// all the same: once one counted again stood first, and shielded the rows
// behind it from the cut.
func TestLiveFailedTrim(t *testing.T) {
	h := newLiveHub(nil)
	h.failID = "f-"
	ctx := context.Background()
	t0 := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	a := ctl.DialErr{Network: "tcp", Proxy: "DIRECT", Host: "a.example", Port: 443, Err: "i/o timeout"}
	b := a
	b.Host = "b.example"
	h.failure(ctx, a, []string{"DIRECT"}, t0)
	h.failure(ctx, b, []string{"DIRECT"}, t0.Add(time.Minute))
	h.failure(ctx, a, []string{"DIRECT"}, t0.Add(9*time.Minute))
	if h.failed[0].Host != "b.example" || h.failed[1].Host != "a.example" {
		t.Fatalf("not in the order they last failed: %s, %s", h.failed[0].Host, h.failed[1].Host)
	}
	h.trim(t0.Add(time.Minute + liveClosedAge + time.Second))
	if len(h.failed) != 1 || h.failed[0].Host != "a.example" {
		t.Fatalf("after the cut: %d rows, the first %s", len(h.failed), h.failed[0].Host)
	}
	// b is forgotten with its row: failing again, it starts a new one
	h.failure(ctx, b, []string{"DIRECT"}, t0.Add(12*time.Minute))
	if len(h.failed) != 2 || h.failed[1].N != 1 {
		t.Errorf("b again: %+v", h.failed)
	}
}

// keepNewest takes no order on trust.
func TestKeepNewest(t *testing.T) {
	var rows []*liveRow
	for i := range liveClosedMax + 3 {
		// the ends out of order: 2, 1, 4, 3, ...
		rows = append(rows, &liveRow{ID: fmt.Sprint(i), End: int64(1000 + i + 1 - 2*(i%2))})
	}
	rows = append(rows, &liveRow{ID: "old", End: 10})
	kept := keepNewest(rows, 100)
	if len(kept) != liveClosedMax {
		t.Fatalf("%d kept", len(kept))
	}
	for _, r := range kept {
		if r.ID == "old" || r.End < 1003 {
			t.Errorf("kept %s, ended %d", r.ID, r.End)
		}
	}
	few := rows[:3]
	if got := keepNewest(few, 0); &got[0] != &few[0] || len(got) != 3 {
		t.Error("nothing to cut, yet copied")
	}
}

// Clear forgets the failures: the same one after it is a new row, counted
// from one -- it used to come back with the count and the first time from
// before.
func TestLiveClear(t *testing.T) {
	h := newLiveHub(nil)
	h.failID = "f-"
	ctx := context.Background()
	t0 := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	e := ctl.DialErr{Network: "tcp", Proxy: "DIRECT", Host: "a.example", Port: 443, Err: "i/o timeout"}
	h.failure(ctx, e, []string{"DIRECT"}, t0)
	h.failure(ctx, e, []string{"DIRECT"}, t0.Add(10*time.Second))
	h.closed = []*liveRow{{ID: "x", End: t0.UnixMilli()}}
	first := h.failed[0].ID
	h.clear()
	if len(h.failed)+len(h.closed)+len(h.failKey)+len(h.failNew) != 0 {
		t.Fatalf("left after clear: %d failed, %d closed", len(h.failed), len(h.closed))
	}
	h.failure(ctx, e, []string{"DIRECT"}, t0.Add(20*time.Second))
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
