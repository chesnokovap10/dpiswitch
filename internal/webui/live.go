package webui

// The live page: the core's connections, refreshed every second. The core
// is asked by one loop for as long as the UI runs, whether a page watches or
// not: the connections closed and the failures are kept for the whole of the
// core's run, and a page opened later gets them all. A new run of the core
// starts the history anew. A tab in the background closes its stream (see
// live.js); coming back, it takes only what came meanwhile.
//
// The core keeps only open connections. Closed is what left its list
// between two calls: the time it closed is known to the second, and a
// connection that opened and closed between two calls is never seen.
//
// A connection the core failed to make is not among them at all: the core
// only logs it. The core's warnings are read too, and each failed dial is a
// row of its own -- the same one again counted on its row rather than added.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
)

var (
	// liveEvery: how often the core is asked
	liveEvery = time.Second
	// liveRetry: how soon the core's log is opened again after it closed --
	// the core restarted, or was not up yet
	liveRetry = 2 * time.Second
)

// liveKeep: the closed ones and the failures kept, of each. Nothing goes for
// its age -- a core's run is kept whole -- but a core running for weeks must
// not fill the memory: past this many, the oldest go.
const liveKeep = 100000

// liveSource: the core, or a fake one in tests
type liveSource interface {
	Connections() (ctl.Live, error)
	Close(id string) error
	DialErrors(ctx context.Context, opened func(), each func(ctl.DialErr)) error
	Groups() (map[string]string, error)
	Release()
}

func coreSource() liveSource {
	return ctl.NewLiveClient(apiAddr, ctl.SecretFromConfig(paths.Config()))
}

// liveRow: one connection as the page draws it. Times are Unix milliseconds.
type liveRow struct {
	ID    string `json:"id"`
	Host  string `json:"host,omitempty"`
	Dom   string `json:"dom,omitempty"` // the domain the host is under, for the page's menu
	IP    string `json:"ip,omitempty"`
	Port  int    `json:"port"`
	Net   string `json:"net"`
	Proto string `json:"proto"`
	Sure  bool   `json:"sure,omitempty"` // the protocol was read from the traffic, not taken from the port
	Route string `json:"route"`          // direct, awg1, awg2, reject, other
	Chain string `json:"chain"`          // the groups and the outbound, in the order they were passed
	Rule  string `json:"rule,omitempty"`
	Probe bool   `json:"probe,omitempty"`
	Proc  string `json:"proc,omitempty"`
	Path  string `json:"path,omitempty"`
	Start int64  `json:"start"`
	Up    int64  `json:"up"`
	Down  int64  `json:"down"`
	US    int64  `json:"us"` // bytes a second over the last interval
	DS    int64  `json:"ds"`
	Act   int64  `json:"act"` // the last time its bytes moved
	End   int64  `json:"end,omitempty"`
	// a failed dial: what the core said, what it comes to (ctl.FailKind),
	// how many times; Start is the first, End the last
	Err string `json:"err,omitempty"`
	Why string `json:"why,omitempty"`
	N   int    `json:"n,omitempty"`
	// the history's own count, taken when the row closed or last failed: a
	// page coming back asks for what came after the last it saw
	Seq int64 `json:"seq,omitempty"`

	queued bool   // among the failures the next tick sends
	run    string // the core's run a failure came in, see coreRun
}

type liveUpd struct {
	ID   string `json:"id"`
	Up   int64  `json:"up"`
	Down int64  `json:"down"`
	US   int64  `json:"us"`
	DS   int64  `json:"ds"`
	Act  int64  `json:"act"`
}

type liveGone struct {
	ID  string `json:"id"`
	End int64  `json:"end"`
	Seq int64  `json:"seq"`
}

type liveTotals struct {
	Up   int64  `json:"up"` // since the core started
	Down int64  `json:"down"`
	US   int64  `json:"us"`
	DS   int64  `json:"ds"`
	Mem  uint64 `json:"mem"`
	// Since: when the core's run started, Unix ms, as the service named the
	// run; 0 unknown, or the core not running
	Since int64 `json:"since,omitempty"`
}

// runStart: when a run named as the service names them ("pid unixnano",
// see supervisor) started, Unix ms; 0 for a name that says no time
func runStart(run string) int64 {
	f := strings.Fields(run)
	if len(f) != 2 {
		return 0
	}
	ns, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil || ns <= 0 {
		return 0
	}
	return ns / int64(time.Millisecond)
}

// liveMsg: what a page gets. "full" first -- everything as it stands, or
// what came since the page last saw this history (Part) -- then a "tick" a
// second with what changed since the one before.
type liveMsg struct {
	Kind  string     `json:"kind"`
	T     int64      `json:"t"`
	Ready bool       `json:"ready"`          // the core was asked at least once
	Down  string     `json:"down,omitempty"` // "stopped": nothing listens; "error": it does not answer
	Err   string     `json:"err,omitempty"`
	Tot   liveTotals `json:"tot"`
	Sess  string     `json:"sess"` // the history this is of
	Keep  int        `json:"keep"` // how many closed ones and failures are kept
	// full
	Part   bool       `json:"part,omitempty"` // the page keeps what it holds of this history
	Conns  []*liveRow `json:"conns,omitempty"`
	Closed []*liveRow `json:"closed,omitempty"`
	Failed []*liveRow `json:"failed,omitempty"`
	// tick
	Add  []*liveRow `json:"add,omitempty"`
	Upd  []liveUpd  `json:"upd,omitempty"`
	Gone []liveGone `json:"gone,omitempty"`
	Fail []*liveRow `json:"fail,omitempty"` // new failures, and ones counted again
}

type liveSub struct{ ch chan []byte }

type liveHub struct {
	source func() liveSource
	runOf  func() string // which run of the core this is: coreRun, or a test's

	mu      sync.Mutex
	subs    map[*liveSub]struct{}
	running bool
	stopFn  context.CancelFunc
	wg      sync.WaitGroup // the loop and its log reader; tests wait on it

	ready   bool
	at      time.Time // the last answer
	open    map[string]*liveRow
	closed  []*liveRow // in the order they closed
	tot     liveTotals
	down    string
	err     string
	downAt  time.Time // when the core was seen gone; zero while it answers
	lastRun string    // the core's run at the last answer

	// the history: a new one when the core runs anew.
	// seq counts what closed and failed in it.
	sess string
	seq  int64

	failed  []*liveRow          // in the order they last failed
	failKey map[string]*liveRow // the listed row of each failure, to count the same one again on
	failNew []*liveRow          // for the next tick
	failID  string              // the loop's own prefix: a page keeps rows over a restart
	failSeq int

	// told every tick what came through the tunnels (see tunnelpulse.go);
	// nil in tests that do not look at it
	pulse *tunnelPulse
}

func newLiveHub(source func() liveSource) *liveHub {
	return &liveHub{source: source, runOf: coreRun, subs: map[*liveSub]struct{}{}, open: map[string]*liveRow{},
		failKey: map[string]*liveRow{}, sess: newLiveSess()}
}

// coreRun: which run of the core this is, as the service wrote it when it
// started the core -- "" from a service that writes none
func coreRun() string {
	b, err := os.ReadFile(paths.CoreRun())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// newLiveSess: a history's name. Not the clock's: on Windows it may read
// the same twice in a row.
func newLiveSess() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// start: the loop runs from the UI's start on, for as long as the UI runs
func (h *liveHub) start() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.startLocked()
}

func (h *liveHub) startLocked() {
	if h.running {
		return
	}
	h.running = true
	ctx, cancel := context.WithCancel(context.Background())
	h.stopFn = cancel
	log.Printf("ui: live: the core is asked every %v", liveEvery)
	h.wg.Add(1)
	go h.run(ctx)
}

// stop ends the loop and waits for it -- tests only: the UI gathers for as
// long as it runs
func (h *liveHub) stop() {
	h.mu.Lock()
	stop := h.stopFn
	h.mu.Unlock()
	if stop != nil {
		stop()
	}
	h.wg.Wait()
}

// join: a page starts watching. It gets the state as it stands -- only what
// came since, when it saw this history up to since -- then every tick after
// it; both are taken under one lock, so none is lost or doubled.
func (h *liveHub) join(sess string, since int64) (*liveSub, []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	sub := &liveSub{ch: make(chan []byte, 8)}
	h.subs[sub] = struct{}{}
	h.startLocked()
	b, _ := json.Marshal(h.full(time.Now(), sess, since))
	return sub, b
}

// full: the state as it stands. The closed ones and the failures are in the
// order of their Seq: what came after since is a tail of each.
func (h *liveHub) full(now time.Time, sess string, since int64) liveMsg {
	m := h.msg("full", now)
	m.Conns = make([]*liveRow, 0, len(h.open))
	for _, r := range h.open {
		m.Conns = append(m.Conns, r)
	}
	m.Closed, m.Failed = h.closed, h.failed
	if sess == h.sess && since > 0 {
		m.Part = true
		m.Closed, m.Failed = afterSeq(h.closed, since), afterSeq(h.failed, since)
	}
	return m
}

func afterSeq(rows []*liveRow, seq int64) []*liveRow {
	return rows[sort.Search(len(rows), func(i int) bool { return rows[i].Seq > seq }):]
}

// leave: a page stopped watching -- closed, reloaded, gone to the background
func (h *liveHub) leave(sub *liveSub) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.subs, sub)
}

func (h *liveHub) run(ctx context.Context) {
	defer h.wg.Done()
	src := h.source()
	defer func() { src.Release() }()
	h.mu.Lock()
	h.failID = fmt.Sprintf("f%x-", time.Now().UnixNano())
	h.mu.Unlock()
	h.wg.Add(1)
	go h.watchFailures(ctx, h.source(), liveRetry)
	t := time.NewTicker(liveEvery)
	defer t.Stop()
	for {
		// the call is made outside the lock: a core slow to answer must not
		// hold up a page joining meanwhile
		live, err := src.Connections()
		if err != nil && !errors.Is(err, ctl.ErrCoreDown) {
			// the secret is read again: a new config could have brought one
			src.Release()
			src = h.source()
		}
		h.update(live, err, time.Now())
		select {
		case <-ctx.Done():
			h.mu.Lock()
			h.running, h.stopFn = false, nil
			h.mu.Unlock()
			return
		case <-t.C:
		}
	}
}

func (h *liveHub) msg(kind string, now time.Time) liveMsg {
	return liveMsg{Kind: kind, T: now.UnixMilli(), Ready: h.ready, Down: h.down, Err: h.err, Tot: h.tot,
		Sess: h.sess, Keep: liveKeep}
}

// update takes one answer of the core and sends the pages what changed.
func (h *liveHub) update(live ctl.Live, err error, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ready = true
	m := h.msg("tick", now)
	if err != nil {
		h.down, h.err = "error", err.Error()
		if errors.Is(err, ctl.ErrCoreDown) {
			// nothing listens: the core is gone, and so is every connection
			// it held. A core slow to answer still holds them.
			h.down, h.err = "stopped", ""
			if h.downAt.IsZero() {
				h.downAt = now
			}
			for id, r := range h.open {
				m.Gone = append(m.Gone, h.close(id, r, now))
			}
			h.tot.US, h.tot.DS, h.tot.Since = 0, 0, 0
		}
		m.Down, m.Err, m.Tot = h.down, h.err, h.tot
		h.trim()
		m.Fail = h.takeFailures()
		h.send(m)
		h.pulseSaw(now, nil, m.Fail)
		return
	}
	// a new run of the core: seen gone and back, or started anew between
	// two calls -- the service names each run it starts. What the last run
	// left goes, and the pages are sent the state anew. From a service that
	// names none, a run is known by its totals counted from nothing again
	// with not one of the connections held before left: totals alone may
	// have grown past the last run's by the next call.
	run := h.runOf()
	anew := !h.downAt.IsZero() || run != "" && h.lastRun != "" && run != h.lastRun
	if !anew && run == "" && !h.at.IsZero() && (live.UploadTotal < h.tot.Up || live.DownloadTotal < h.tot.Down) {
		anew = !slices.ContainsFunc(live.Conns, func(c ctl.LiveConn) bool { return h.open[c.ID] != nil })
	}
	if anew {
		cut := h.downAt
		if cut.IsZero() {
			cut = h.at
		}
		h.newRun(run, cut.UnixMilli())
	}
	h.downAt = time.Time{}
	// a name not read -- the service replacing the file that moment -- is
	// no run of its own: the next one read is told from the last known
	if run != "" {
		h.lastRun = run
	}
	h.down, h.err = "", ""
	m.Down, m.Err = "", ""
	dt := now.Sub(h.at).Seconds()
	first := h.at.IsZero()
	seen := make(map[string]bool, len(live.Conns))
	// the routes bytes came in on this tick -- not on the first, which
	// knows nothing of when they came
	recv := map[string]bool{}
	for _, c := range live.Conns {
		seen[c.ID] = true
		r, ok := h.open[c.ID]
		if !first && (ok && c.Download > r.Down || !ok && c.Download > 0) {
			recv[liveRoute(c.Chains)] = true
		}
		if !ok {
			r = newLiveRow(c, now)
			// its bytes so far, over the part of the interval it lived; on
			// the first call nothing is known of when they moved
			if !first {
				if span := min(now.Sub(c.Start).Seconds(), dt); span > 0 {
					r.US, r.DS = rate(c.Upload, span), rate(c.Download, span)
				}
			}
			h.open[c.ID] = r
			m.Add = append(m.Add, r)
			continue
		}
		us, ds := rate(c.Upload-r.Up, dt), rate(c.Download-r.Down, dt)
		moved := c.Upload != r.Up || c.Download != r.Down
		// the core fills a connection in before it tracks it, but should
		// it learn more later -- a name, the program -- the row follows
		meta := r.takeMeta(newLiveRow(c, now))
		if !meta && !moved && us == r.US && ds == r.DS {
			continue
		}
		if moved {
			r.Act = now.UnixMilli()
		}
		r.Up, r.Down, r.US, r.DS = c.Upload, c.Download, us, ds
		if meta {
			m.Add = append(m.Add, r) // drawn anew
			continue
		}
		m.Upd = append(m.Upd, liveUpd{r.ID, r.Up, r.Down, r.US, r.DS, r.Act})
	}
	for id, r := range h.open {
		if !seen[id] {
			m.Gone = append(m.Gone, h.close(id, r, now))
		}
	}
	h.trim()
	tot := liveTotals{Up: live.UploadTotal, Down: live.DownloadTotal, Mem: live.Memory, Since: runStart(h.lastRun)}
	if !first {
		tot.US, tot.DS = rate(tot.Up-h.tot.Up, dt), rate(tot.Down-h.tot.Down, dt)
	}
	h.tot, m.Tot = tot, tot
	h.at = now
	m.Fail = h.takeFailures()
	h.pulseSaw(now, recv, m.Fail)
	if anew {
		// the failures queued are in the state sent
		h.send(h.full(now, "", 0))
		return
	}
	h.send(m)
}

// pulseSaw tells the tunnels' pulse what came through them this tick
func (h *liveHub) pulseSaw(now time.Time, recv map[string]bool, failed []*liveRow) {
	if h.pulse == nil {
		return
	}
	fail := map[string]bool{}
	for _, r := range failed {
		fail[r.Route] = true
	}
	h.pulse.saw(now, recv, fail)
}

// newRun: the core runs anew. Its last run's connections, the ones closed
// and the failures go, and with them what counts a failure again; a failure
// the new run's log told already stays -- its own run's, or, where the
// service names no runs, one that came after cut, the last the old run was
// seen.
func (h *liveHub) newRun(run string, cut int64) {
	h.open, h.closed = map[string]*liveRow{}, nil
	h.keepFailed(slices.DeleteFunc(h.failed, func(r *liveRow) bool {
		if run != "" && r.run != "" {
			return r.run != run
		}
		return r.End <= cut
	}))
	h.at, h.tot = time.Time{}, liveTotals{}
	h.sess = newLiveSess()
	log.Printf("ui: live: the core runs anew: the history starts over")
}

// watchFailures reads the core's log for the dials it failed, for as long
// as the loop runs, opening it again after the core restarts.
func (h *liveHub) watchFailures(ctx context.Context, src liveSource, retry time.Duration) {
	defer h.wg.Done()
	defer func() { src.Release() }()
	var groups map[string]string
	var groupsAt time.Time
	// the run of the core a stream is of, asked when the core has taken it:
	// the service names a run before its core listens. A line an old core's
	// stream still holds once the new one runs keeps the old name.
	var run string
	opened := func() { run = h.runOf() }
	each := func(e ctl.DialErr) {
		// the groups' choices, asked again when a few seconds old: failures
		// come in bursts, and a fallback group changes its mind rarely
		if time.Since(groupsAt) > 5*time.Second {
			if g, err := src.Groups(); err == nil {
				groups = g
			}
			groupsAt = time.Now()
		}
		h.failure(ctx, run, e, groupChain(e.Proxy, groups), time.Now())
	}
	for {
		err := src.DialErrors(ctx, opened, each)
		if ctx.Err() != nil {
			return
		}
		if err != nil && !errors.Is(err, ctl.ErrCoreDown) {
			// the secret is read again: a new config could have brought one
			src.Release()
			src = h.source()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(retry):
		}
	}
}

// failure takes one failed dial, read from the log of the core's run named
// run: a row of its own, or one more on the row of the same failure -- a
// program retrying a blocked site fails dozens of times a minute. The same
// is the same program, destination, route and rule, failing for the same
// reason, in the same run: a list or config changed between two tries is
// another failure.
func (h *liveHub) failure(ctx context.Context, run string, e ctl.DialErr, chain []string, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ctx.Err() != nil {
		return // the loop stopped: this is not for the next one
	}
	why := ctl.FailKind(e.Err)
	dst := e.Host
	if dst == "" {
		dst = e.IP
	}
	route := liveChain(chain)
	rule := strings.TrimSpace(e.Rule + " " + e.RulePayload)
	key := strings.Join([]string{e.Network, route, rule, e.Process, dst, fmt.Sprint(e.Port), fmt.Sprint(e.Probe), why}, "|")
	ms := now.UnixMilli()
	h.seq++
	// a failure of another run is not counted on: the new core's log may
	// tell one before the loop sees the core anew. Where the service names no
	// runs, one from before the core was seen gone is another run's.
	other := func(r *liveRow) bool {
		if r.run != "" && run != "" {
			return r.run != run
		}
		return !h.downAt.IsZero() && r.End <= h.downAt.UnixMilli()
	}
	if r := h.failKey[key]; r != nil && !other(r) {
		r.N++
		r.End, r.Err, r.Seq = ms, e.Err, h.seq
		if e.IP != "" {
			r.IP = e.IP
		}
		// the newest last: the list is kept in the order the rows last
		// failed, which trim and a page coming back rely on
		if i := slices.Index(h.failed, r); i >= 0 {
			h.failed = append(slices.Delete(h.failed, i, i+1), r)
		}
		h.queue(r)
		return
	}
	h.failSeq++
	r := &liveRow{ID: h.failID + fmt.Sprint(h.failSeq), Host: e.Host, Dom: liveDomain(e.Host), IP: e.IP, Port: e.Port,
		Net: e.Network, Route: liveRoute(chain), Chain: route, Rule: rule, Probe: e.Probe, Proc: liveProc(e.Probe, e.Process), Path: livePath(e.Probe, ""),
		Start: ms, Act: ms, End: ms, Err: e.Err, Why: why, N: 1, Seq: h.seq, run: run}
	r.Proto, _ = liveProto(r.Net, e.Port, false)
	h.failed = append(h.failed, r)
	h.failKey[key] = r
	h.queue(r)
	h.trim()
}

func (h *liveHub) queue(r *liveRow) {
	if !r.queued {
		r.queued = true
		h.failNew = append(h.failNew, r)
	}
}

// takeFailures: the failures new or counted again since the last tick
func (h *liveHub) takeFailures() []*liveRow {
	out := h.failNew
	for _, r := range out {
		r.queued = false
	}
	h.failNew = nil
	return out
}

func (h *liveHub) close(id string, r *liveRow, now time.Time) liveGone {
	delete(h.open, id)
	h.seq++
	r.End, r.US, r.DS, r.Seq = now.UnixMilli(), 0, 0, h.seq
	h.closed = append(h.closed, r)
	return liveGone{id, r.End, r.Seq}
}

// trim keeps the newest liveKeep closed ones and failures -- nothing goes for
// its age. The pages drop the same on their side.
func (h *liveHub) trim() {
	h.closed = keepLast(h.closed)
	if kept := keepLast(h.failed); len(kept) != len(h.failed) {
		h.keepFailed(kept)
	}
}

// keepLast: the last liveKeep rows. Both lists are in the order their rows
// last ended, the newest last.
func keepLast(rows []*liveRow) []*liveRow {
	if n := len(rows) - liveKeep; n > 0 {
		return rows[n:]
	}
	return rows
}

// keepFailed: the failures listed are these. The others are forgotten: the
// same one again starts a row of its own, counted from one.
func (h *liveHub) keepFailed(kept []*liveRow) {
	h.failed = kept
	listed := make(map[*liveRow]bool, len(kept))
	for _, r := range kept {
		listed[r] = true
	}
	for k, r := range h.failKey {
		if !listed[r] {
			delete(h.failKey, k)
		}
	}
	h.failNew = slices.DeleteFunc(h.failNew, func(r *liveRow) bool {
		if listed[r] {
			return false
		}
		r.queued = false
		return true
	})
}

// pathOf: the file of the program behind a connection, open or closed
func (h *liveHub) pathOf(id string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if r := h.open[id]; r != nil {
		return r.Path
	}
	for _, r := range h.closed {
		if r.ID == id {
			return r.Path
		}
	}
	return ""
}

// liveDomain: the domain a name is under -- its registrable part, a private
// suffix counted (github.io) -- for "the whole domain" in the page's menu
func liveDomain(host string) string {
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return d
}

// groupChain: the chain a failed dial took -- the group it was sent to, then
// the group's choice, down to an outbound -- outbound first, as the core
// gives an open connection's.
func groupChain(name string, groups map[string]string) []string {
	chain := []string{name}
	for range 8 {
		next, ok := groups[chain[0]]
		if !ok || slices.Contains(chain, next) {
			break
		}
		chain = append([]string{next}, chain...)
	}
	return chain
}

// takeMeta takes what a fresh look at the connection says of it, and
// whether anything differed.
func (r *liveRow) takeMeta(f *liveRow) bool {
	same := r.Host == f.Host && r.IP == f.IP && r.Port == f.Port && r.Net == f.Net && r.Proto == f.Proto &&
		r.Sure == f.Sure && r.Route == f.Route && r.Chain == f.Chain && r.Rule == f.Rule && r.Probe == f.Probe &&
		r.Proc == f.Proc && r.Path == f.Path
	if !same {
		r.Host, r.Dom, r.IP, r.Port, r.Net, r.Proto, r.Sure = f.Host, f.Dom, f.IP, f.Port, f.Net, f.Proto, f.Sure
		r.Route, r.Chain, r.Rule, r.Probe, r.Proc, r.Path = f.Route, f.Chain, f.Rule, f.Probe, f.Proc, f.Path
	}
	return !same
}

// send: one message to every page. A page that does not take it is dropped
// rather than waited for: its stream ends, and the browser reopens it and
// gets the whole state again.
func (h *liveHub) send(m liveMsg) {
	if len(h.subs) == 0 {
		return
	}
	b, err := json.Marshal(m)
	if err != nil {
		log.Printf("ui: live: %v", err)
		return
	}
	for sub := range h.subs {
		select {
		case sub.ch <- b:
		default:
			delete(h.subs, sub)
			close(sub.ch)
		}
	}
}

func rate(bytes int64, secs float64) int64 {
	if bytes <= 0 || secs <= 0 {
		return 0
	}
	return int64(float64(bytes)/secs + 0.5)
}

// liveProc: the program behind a connection. The detector's checks are the
// service's own, through listeners that send straight to an outbound: the
// core looks no program up for them.
func liveProc(probe bool, proc string) string {
	if probe && proc == "" {
		return "dpiswitch.exe"
	}
	return proc
}

// livePath: the program's file -- the detector's checks are this program's,
// the service's file and the tray's one and the same
func livePath(probe bool, path string) string {
	if probe && path == "" {
		return paths.Exe()
	}
	return path
}

func newLiveRow(c ctl.LiveConn, now time.Time) *liveRow {
	r := &liveRow{ID: c.ID, Host: c.Host, Dom: liveDomain(c.Host), IP: c.DstIP, Port: c.Port, Net: strings.ToLower(c.Network),
		Route: liveRoute(c.Chains), Chain: liveChain(c.Chains), Probe: c.Probe,
		Proc: liveProc(c.Probe, c.Process), Path: livePath(c.Probe, c.ProcessPath), Up: c.Upload, Down: c.Download,
		// on the first sight its bytes may have moved a moment ago: it is
		// not called idle until they have stood still for a while
		Act: now.UnixMilli()}
	r.Proto, r.Sure = liveProto(r.Net, c.Port, c.Sniffed)
	r.Rule = strings.TrimSpace(c.Rule + " " + c.RulePayload)
	if !c.Start.IsZero() {
		r.Start = c.Start.UnixMilli()
	} else {
		r.Start = now.UnixMilli()
	}
	return r
}

// liveProto: what speaks over a connection, by its port. The core's sniffer
// reads the name from TLS, QUIC and HTTP on these same ports (see sniffer
// in awgconf): a connection it read a name from is that protocol for sure.
// Most connections come by a fake-ip name and are not read at all -- for
// them the port is all there is.
func liveProto(network string, port int, sniffed bool) (string, bool) {
	udp := network == "udp"
	switch {
	case port == 53:
		return "DNS", false
	case !udp && (port == 443 || port == 8443):
		return "TLS", sniffed
	case udp && port == 443:
		return "QUIC", sniffed
	case !udp && (port == 80 || port == 8080 || port == 8880):
		return "HTTP", sniffed
	case udp:
		return "UDP", false
	}
	return "TCP", false
}

// liveRoute: where a connection went, by its outbound -- the first of its
// chain; the groups that picked it follow
func liveRoute(chains []string) string {
	if len(chains) == 0 {
		return "other"
	}
	// the groups too, for a failed dial whose group's choice is not known
	switch chains[0] {
	case "DIRECT":
		return "direct"
	case ctl.SplitOutbound:
		return "split"
	case "awg1", "tunnel", "tunnel-rest", "tunnel-soft-any", "tunnel-lists", "tunnel-one", "tunnel-any":
		return "awg1"
	case "awg2", "tunnel2", "tunnel2-soft", "tunnel2-strict":
		return "awg2"
	case "REJECT", "REJECT-DROP":
		return "reject"
	}
	return "other"
}

// liveChain: the chain in the order it was passed -- group, then outbound
func liveChain(chains []string) string {
	out := make([]string, 0, len(chains))
	for i := len(chains) - 1; i >= 0; i-- {
		out = append(out, chains[i])
	}
	return strings.Join(out, " → ")
}

// handleLive streams the connections to a page as server-sent events.
func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	// a page coming back names the history it holds and the last it saw of it
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	sub, first := s.live.join(r.URL.Query().Get("sess"), since)
	defer s.live.leave(sub)
	// a stream dropped comes back within two seconds
	if _, err := w.Write([]byte("retry: 2000\n")); err != nil {
		return
	}
	for b, ok := first, true; ok; {
		if _, err := w.Write(append(append([]byte("data: "), b...), '\n', '\n')); err != nil {
			return
		}
		if err := rc.Flush(); err != nil {
			return
		}
		select {
		case b, ok = <-sub.ch:
		case <-r.Context().Done():
			return
		}
	}
}

var liveID = regexp.MustCompile(`^[0-9a-fA-F-]{8,64}$`)

// actLiveClose: the core drops a connection -- one, or the rows picked at
// once; the program opens a new one, routed by the rules as they are now.
// Asked by the page's script, which only wants to know whether it worked:
// one failing, the others are closed all the same, and the first failure
// is the answer.
func (s *Server) actLiveClose(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	ids := r.Form["id"]
	if len(ids) == 0 || len(ids) > maxSend {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	for _, id := range ids {
		if !liveID.MatchString(id) {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}
	}
	src := coreSource()
	defer src.Release()
	var first error
	for _, id := range ids {
		if err := src.Close(id); err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		log.Printf("ui: live: connection %s closed by hand", id)
	}
	if first != nil {
		http.Error(w, first.Error(), http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// liveData: the words the page's script puts together itself
type liveData struct {
	Words map[string]string
	// Split: the DPI bypass is on -- its filter is shown, and its rows are
	// its own; off, the rows left of it are direct ones
	Split bool
}

func liveWords(v *view) liveData {
	split := ctl.LoadSettings(paths.Settings()).SplitHello
	on := ""
	if split {
		on = "1"
	}
	return liveData{Split: split, Words: map[string]string{
		"splitOn":       on,
		"tunnel":        v.T("Tunnels"),
		"direct":        v.T("Direct"),
		"split":         v.T("DPI bypass"),
		"awg1":          v.T("Tunnel"),
		"awg2":          v.T("Tunnel 2"),
		"reject":        v.T("Forbidden"),
		"other":         v.T("Other"),
		"probe":         v.T("check"),
		"noname":        v.T("no name"),
		"open":          v.T("open"),
		"idle":          v.T("idle: no traffic for over 30 s"),
		"closedAgo":     v.T("closed %s ago"),
		"sure":          v.T("read from the traffic"),
		"byPort":        v.T("by the port"),
		"B":             v.T("B"),
		"KB":            v.T("KB"),
		"MB":            v.T("MB"),
		"GB":            v.T("GB"),
		"perSec":        v.T("/s"),
		"sec":           v.T("%d s"),
		"min":           v.T("%d min"),
		"hour":          v.T("%d h %d min"),
		"openedAt":      v.T("opened %s"),
		"closedAt":      v.T("closed %s"),
		"lasted":        v.T("lasted %s"),
		"openFor":       v.T("open for %s"),
		"loading":       v.T("Connecting to the core…"),
		"reconnect":     v.T("The stream dropped, reconnecting…"),
		"stopped":       v.T("The core is not running: the service is stopped or starting."),
		"error":         v.T("The core does not answer:"),
		"live":          v.T("live"),
		"liveHint":      v.T("The table follows the core every second"),
		"paused":        v.T("on pause"),
		"pausedHint":    v.T("The table stands still until you resume; the program gathers what closes and fails all the same"),
		"noOpen":        v.T("No open connections."),
		"noClosed":      v.T("None closed yet: they show here as they close while the page is open."),
		"noMatch":       v.T("Nothing matches the filter."),
		"shown":         v.T("Shown %d of %d: narrow the filter."),
		"close":         v.T("Close the connection: the program opens a new one, routed by the rules as they are now"),
		"closeFail":     v.T("Not closed:"),
		"pause":         v.T("Pause"),
		"resume":        v.T("Resume"),
		"memory":        v.T("core memory %s"),
		"sinceStart":    v.T("since the core started"),
		"sinceAt":       v.T("since the core started at %s"),
		"sinceOn":       v.T("since the core started on %s"),
		"day":           v.T("%d d %d h"),
		"coreStarted":   v.T("The core started %s"),
		"failed":        v.T("failed: the core could not make the connection"),
		"noFailed":      v.T("No failures yet: they show here as the core fails to make a connection while the page is open."),
		"blocked":       v.T("forbidden: refused by the Forbidden list"),
		"noBlocked":     v.T("Nothing forbidden tried yet: the tries the Forbidden list refuses show here while the page is open."),
		"why.forbidden": v.T("forbidden"),
		"attempts":      v.T("attempts: %d"),
		"firstAt":       v.T("the first at %s"),
		"why.timeout":   v.T("timed out"),
		"why.refused":   v.T("refused"),
		"why.reset":     v.T("reset"),
		"why.dns":       v.T("name not found"),
		"why.nonet":     v.T("no network interface"),
		"why.unreach":   v.T("network unreachable"),
		"why.eof":       v.T("closed by the other side"),
		"why.canceled":  v.T("canceled"),
		"why.other":     v.T("connection failed"),
		"whatDomain":    v.T("the whole domain: the site and everything under it"),
		"whatName":      v.T("this name only"),
		"whatAddr":      v.T("the address: for connections made to it by address"),
		"whatProg":      v.T("the program: everything it sends"),
		"whatDomains":   v.T("Whole domains: %d"),
		"whatNames":     v.T("Names only: %d"),
		"whatAddrs":     v.T("Addresses: %d"),
		"whatProgs":     v.T("Programs: %d"),
		"closeMany":     v.T("Close the %d connections picked"),
		"noPresets":     v.T("No presets"),
		"presetOff":     v.T("switched off: routes nothing until switched on"),
		"sending":       v.T("Saving…"),
		"notSent":       v.T("Not saved:"),
		"notOpened":     v.T("Not opened:"),
	}}
}
