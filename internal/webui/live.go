package webui

// The live page: the core's connections, refreshed every second -- only
// while a page watches. The core is asked by one loop for every tab open on
// the page; it starts with the first one and stops a little after the last
// one leaves. A tab in the background closes its stream (see live.js), so
// a window left open on another tab costs nothing either.
//
// The core keeps only open connections. Closed is what left its list
// between two calls: the time it closed is known to the second, and a
// connection that opened and closed between two calls is never seen.

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
)

var (
	// liveEvery: how often the core is asked while a page watches
	liveEvery = time.Second
	// liveGrace: how long the loop outlives the last page. A reload, or a
	// tab switched away from and back, keeps the connections seen closed.
	liveGrace = 10 * time.Second
)

const (
	// the closed ones kept: the newest this many, none older than this
	liveClosedMax = 500
	liveClosedAge = 10 * time.Minute
)

// liveSource: the core, or a fake one in tests
type liveSource interface {
	Connections() (ctl.Live, error)
	Close(id string) error
	Release()
}

func coreSource() liveSource {
	return ctl.NewLiveClient(apiAddr, ctl.SecretFromConfig(paths.Config()))
}

// liveRow: one connection as the page draws it. Times are Unix milliseconds.
type liveRow struct {
	ID    string `json:"id"`
	Host  string `json:"host,omitempty"`
	IP    string `json:"ip,omitempty"`
	Port  int    `json:"port"`
	Net   string `json:"net"`
	Proto string `json:"proto"`
	Sure  bool   `json:"sure,omitempty"` // the protocol was read from the traffic, not taken from the port
	Route string `json:"route"`          // direct, awg, awg2, reject, other
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
}

type liveTotals struct {
	Up   int64  `json:"up"` // since the core started
	Down int64  `json:"down"`
	US   int64  `json:"us"`
	DS   int64  `json:"ds"`
	Mem  uint64 `json:"mem"`
}

// liveMsg: what a page gets. "full" first -- everything as it stands --
// then a "tick" a second with what changed since the one before.
type liveMsg struct {
	Kind  string     `json:"kind"`
	T     int64      `json:"t"`
	Ready bool       `json:"ready"`          // the core was asked at least once
	Down  string     `json:"down,omitempty"` // "stopped": nothing listens; "error": it does not answer
	Err   string     `json:"err,omitempty"`
	Tot   liveTotals `json:"tot"`
	// full
	Conns  []*liveRow `json:"conns,omitempty"`
	Closed []*liveRow `json:"closed,omitempty"`
	Keep   [2]int64   `json:"keep"` // how many closed ones are kept, and for how many seconds
	// tick
	Add  []*liveRow `json:"add,omitempty"`
	Upd  []liveUpd  `json:"upd,omitempty"`
	Gone []liveGone `json:"gone,omitempty"`
}

type liveSub struct{ ch chan []byte }

type liveHub struct {
	source func() liveSource

	mu      sync.Mutex
	subs    map[*liveSub]struct{}
	running bool
	leftAt  time.Time // the last page left

	ready  bool
	at     time.Time // the last answer
	open   map[string]*liveRow
	closed []*liveRow // oldest first
	tot    liveTotals
	down   string
	err    string
}

func newLiveHub(source func() liveSource) *liveHub {
	return &liveHub{source: source, subs: map[*liveSub]struct{}{}, open: map[string]*liveRow{}}
}

// join: a page starts watching. It gets the state as it stands, then every
// tick after it -- both taken under one lock, so none is lost or doubled.
func (h *liveHub) join() (*liveSub, []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	sub := &liveSub{ch: make(chan []byte, 8)}
	h.subs[sub] = struct{}{}
	if !h.running {
		h.running = true
		log.Printf("ui: live: a page opened, the core is asked every %v", liveEvery)
		go h.run()
	}
	m := h.msg("full", time.Now())
	m.Conns = make([]*liveRow, 0, len(h.open))
	for _, r := range h.open {
		m.Conns = append(m.Conns, r)
	}
	m.Closed = h.closed
	b, _ := json.Marshal(m)
	return sub, b
}

// leave: a page stopped watching -- closed, reloaded, gone to the background
func (h *liveHub) leave(sub *liveSub) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.subs[sub]; ok {
		delete(h.subs, sub)
		h.left()
	}
}

func (h *liveHub) left() {
	if len(h.subs) == 0 {
		h.leftAt = time.Now()
	}
}

func (h *liveHub) run() {
	src := h.source()
	defer func() { src.Release() }()
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
		<-t.C
		h.mu.Lock()
		if len(h.subs) == 0 && time.Since(h.leftAt) >= liveGrace {
			// no one watches: what was gathered goes, and nothing is gathered
			h.running = false
			h.ready, h.at, h.down, h.err = false, time.Time{}, "", ""
			h.open, h.closed, h.tot = map[string]*liveRow{}, nil, liveTotals{}
			h.mu.Unlock()
			log.Printf("ui: live: no page open, the core is no longer asked")
			return
		}
		h.mu.Unlock()
	}
}

func (h *liveHub) msg(kind string, now time.Time) liveMsg {
	return liveMsg{Kind: kind, T: now.UnixMilli(), Ready: h.ready, Down: h.down, Err: h.err, Tot: h.tot,
		Keep: [2]int64{liveClosedMax, int64(liveClosedAge / time.Second)}}
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
			for id, r := range h.open {
				m.Gone = append(m.Gone, h.close(id, r, now))
			}
			h.tot.US, h.tot.DS = 0, 0
		}
		m.Down, m.Err, m.Tot = h.down, h.err, h.tot
		h.trim(now)
		h.send(m)
		return
	}
	h.down, h.err = "", ""
	m.Down, m.Err = "", ""
	dt := now.Sub(h.at).Seconds()
	first := h.at.IsZero()
	seen := make(map[string]bool, len(live.Conns))
	for _, c := range live.Conns {
		seen[c.ID] = true
		r, ok := h.open[c.ID]
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
		if !moved && us == r.US && ds == r.DS {
			continue
		}
		if moved {
			r.Act = now.UnixMilli()
		}
		r.Up, r.Down, r.US, r.DS = c.Upload, c.Download, us, ds
		m.Upd = append(m.Upd, liveUpd{r.ID, r.Up, r.Down, r.US, r.DS, r.Act})
	}
	for id, r := range h.open {
		if !seen[id] {
			m.Gone = append(m.Gone, h.close(id, r, now))
		}
	}
	h.trim(now)
	tot := liveTotals{Up: live.UploadTotal, Down: live.DownloadTotal, Mem: live.Memory}
	if !first {
		tot.US, tot.DS = rate(tot.Up-h.tot.Up, dt), rate(tot.Down-h.tot.Down, dt)
	}
	h.tot, m.Tot = tot, tot
	h.at = now
	h.send(m)
}

func (h *liveHub) close(id string, r *liveRow, now time.Time) liveGone {
	delete(h.open, id)
	r.End, r.US, r.DS = now.UnixMilli(), 0, 0
	h.closed = append(h.closed, r)
	return liveGone{id, r.End}
}

// trim keeps the newest closed ones -- the pages drop the same on their side
func (h *liveHub) trim(now time.Time) {
	cut := now.Add(-liveClosedAge).UnixMilli()
	i := 0
	for i < len(h.closed) && (len(h.closed)-i > liveClosedMax || h.closed[i].End < cut) {
		i++
	}
	if i > 0 {
		h.closed = append([]*liveRow(nil), h.closed[i:]...)
	}
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
			h.left()
		}
	}
}

func rate(bytes int64, secs float64) int64 {
	if bytes <= 0 || secs <= 0 {
		return 0
	}
	return int64(float64(bytes)/secs + 0.5)
}

func newLiveRow(c ctl.LiveConn, now time.Time) *liveRow {
	r := &liveRow{ID: c.ID, Host: c.Host, IP: c.DstIP, Port: c.Port, Net: strings.ToLower(c.Network),
		Route: liveRoute(c.Chains), Chain: liveChain(c.Chains), Probe: c.Probe,
		Proc: c.Process, Path: c.ProcessPath, Up: c.Upload, Down: c.Download,
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
	switch chains[0] {
	case "DIRECT":
		return "direct"
	case "awg":
		return "awg"
	case "awg2":
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
	sub, first := s.live.join()
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

// actLiveClose: the core drops one connection; the program opens a new
// one, routed by the rules as they are now. Asked by the page's script,
// which only wants to know whether it worked.
func (s *Server) actLiveClose(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	if !liveID.MatchString(id) {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	src := coreSource()
	defer src.Release()
	if err := src.Close(id); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	log.Printf("ui: live: connection %s closed by hand", id)
	w.WriteHeader(http.StatusNoContent)
}

// liveData: the words the page's script puts together itself
type liveData struct {
	Words map[string]string
}

func liveWords(v *view) liveData {
	return liveData{Words: map[string]string{
		"direct":     v.T("Direct"),
		"awg":        v.T("Tunnel"),
		"awg2":       v.T("Tunnel 2"),
		"reject":     v.T("Rejected"),
		"other":      v.T("Other"),
		"probe":      v.T("check"),
		"noname":     v.T("no name"),
		"open":       v.T("open"),
		"idle":       v.T("idle: no traffic for over 30 s"),
		"closedAgo":  v.T("closed %s ago"),
		"sure":       v.T("read from the traffic"),
		"byPort":     v.T("by the port"),
		"B":          v.T("B"),
		"KB":         v.T("KB"),
		"MB":         v.T("MB"),
		"GB":         v.T("GB"),
		"perSec":     v.T("/s"),
		"sec":        v.T("%d s"),
		"min":        v.T("%d min"),
		"hour":       v.T("%d h %d min"),
		"started":    v.T("started"),
		"loading":    v.T("Connecting to the core…"),
		"reconnect":  v.T("The stream dropped, reconnecting…"),
		"stopped":    v.T("The core is not running: the service is stopped or starting."),
		"error":      v.T("The core does not answer:"),
		"live":       v.T("live"),
		"liveHint":   v.T("The core is asked every second while this page is in view"),
		"paused":     v.T("on pause"),
		"pausedHint": v.T("Nothing is asked of the core until you resume"),
		"noOpen":     v.T("No open connections."),
		"noClosed":   v.T("None closed yet: they show here as they close while the page is open."),
		"noMatch":    v.T("Nothing matches the filter."),
		"shown":      v.T("Shown %d of %d: narrow the filter."),
		"close":      v.T("Close the connection: the program opens a new one, routed by the rules as they are now"),
		"closeFail":  v.T("Not closed:"),
		"pause":      v.T("Pause"),
		"resume":     v.T("Resume"),
		"memory":     v.T("core memory %s"),
		"sinceStart": v.T("since the core started"),
	}}
}
