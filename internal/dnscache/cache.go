// Package dnscache: the program's own DNS cache for the direct path.
//
// The core asks it for every name it sends direct (its direct-nameserver),
// and the detector asks it in-process (probe.Local): one answer for both,
// so the node probed is the node the traffic goes to.
//
// A name it has is answered at once, from memory. An answer is kept for a
// week from when it was last fetched -- across the core's restarts, which
// emptied the core's own cache a dozen times a day, and the service's (the
// file) -- and one past its TTL is given at once all the same, with a short
// TTL, while it is fetched again behind it. A name it has not is asked of
// the fastest server of the direct list, the others joining in when that
// one is slow to answer.
//
// Answers are kept per network: a CDN node one ISP's resolver names may not
// be reachable from another's network.
package dnscache

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"dpiswitch/internal/paths"
	"dpiswitch/internal/probe"
)

const (
	// Addr: where the core asks the cache
	Addr = "127.0.0.1:1054"
	// keepFor: how long an answer is kept from when it was last fetched
	keepFor = 7 * 24 * time.Hour
	// staleTTL: the TTL an answer past its own is given with, seconds: the
	// core asks again soon, and by then it is fetched anew
	staleTTL = 5
	// maxNames: the answers kept per network; past it the ones asked for
	// longest ago go
	maxNames = 30000
	// fetchTimeout: how long a name not kept is waited for
	fetchTimeout = 4 * time.Second
	// raceEvery: how often a fetch goes to every server at once, their
	// speed measured again -- the fastest one asked alone otherwise
	raceEvery = 2 * time.Minute
)

var (
	// how often the cache is written to its file, when it has changed, and
	// what the UI shows of it
	saveEvery  = 5 * time.Minute
	statsEvery = 30 * time.Second
)

// entry: one answer kept
type entry struct {
	Msg  []byte    `json:"m"`
	At   time.Time `json:"at"`   // fetched
	TTL  uint32    `json:"ttl"`  // its smallest TTL then, seconds
	Used time.Time `json:"used"` // last asked for
}

// upstream: a server of the direct list, and how fast it has answered
type upstream struct {
	r     probe.Resolver
	rtt   time.Duration // smoothed; 0 not measured yet
	fails int           // failures in a row
}

// score: what the servers are ordered by -- a failing one last
func (u *upstream) score() time.Duration { return u.rtt + time.Duration(u.fails)*time.Second }

type flight struct {
	done chan struct{}
	msg  []byte
	err  error
}

// flightKey: one fetch per question, and per network and servers -- a
// question asked again after they changed is a fetch of its own
type flightKey struct {
	gen uint64
	q   string
}

// Server: the cache, its listeners and the servers it asks
type Server struct {
	file, statsFile string

	mu      sync.Mutex
	nets    map[string]map[string]*entry // by network, then by question
	net     string
	list    []string // the servers as the settings write them: the answers kept are theirs
	ups     []*upstream
	dialer  probe.Dialer
	flights map[flightKey]*flight
	// gen: counted up when the network or the servers change. A fetch begun
	// under another one is no answer for now: it is given to those who
	// asked for it, and not kept -- it was asked in another network, or of
	// other servers, and their answers differ (a CDN's, by the network)
	gen      uint64
	dirty    bool
	lastRace time.Time
	counts   Counts
	changed  bool            // counts since the stats were written
	holes    map[string]bool // the sinkholes said in the log, see noteHole

	lmu     sync.Mutex
	addr    string // listened on
	udp     *net.UDPConn
	tcp     net.Listener
	stop    chan struct{}
	stopped chan struct{}
}

// Counts: what the cache answered, since the service started
type Counts struct {
	Fresh  int64 `json:"fresh"`  // kept, within its TTL
	Stale  int64 `json:"stale"`  // kept, past its TTL: given, and fetched again
	Missed int64 `json:"missed"` // not kept: asked of a server
	Failed int64 `json:"failed"` // not kept, and no server answered
}

// New: the cache, with what its file kept
func New(file, statsFile string) *Server {
	s := &Server{file: file, statsFile: statsFile, nets: map[string]map[string]*entry{}, flights: map[flightKey]*flight{}}
	s.load()
	return s
}

// Usable: the servers of the list the cache can ask -- the ones given by
// address. One given by name would have to be resolved, and the core asks
// the cache for that: it would wait on itself.
func Usable(list []string) []probe.Resolver {
	var out []probe.Resolver
	for _, s := range list {
		r, err := probe.ParseResolver(s)
		if err != nil || r.Scheme == "local" || net.ParseIP(r.Host) == nil {
			continue
		}
		out = append(out, r)
	}
	return out
}

// Configure: the servers to ask, and the path to them -- the core's direct
// listener. The answers kept from other servers go: they are not the ones
// these give.
func (s *Server) Configure(list []string, d probe.Dialer) {
	ups := Usable(list)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dialer = d
	if slices.Equal(s.list, list) && s.ups != nil {
		return
	}
	if !slices.Equal(s.list, list) {
		if n := s.namesLocked(); n > 0 {
			log.Printf("DNS cache: the direct servers changed, the %d answers kept are dropped", n)
		}
		s.nets = map[string]map[string]*entry{}
		s.dirty = true
		s.gen++
	}
	s.list = slices.Clone(list)
	s.ups = []*upstream{}
	for _, r := range ups {
		s.ups = append(s.ups, &upstream{r: r})
	}
	s.lastRace = time.Time{}
}

// SetNetwork: the network the answers are kept and given for
func (s *Server) SetNetwork(id string) {
	if id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.net != id && s.net != "" {
		log.Printf("DNS cache: network %s, %d answers kept for it", id, len(s.nets[id]))
	}
	if s.net != id {
		s.gen++
	}
	s.net = id
}

func (s *Server) namesLocked() int {
	n := 0
	for _, m := range s.nets {
		n += len(m)
	}
	return n
}

// Exchange answers one query: from what is kept, else from a server.
// A query that is not one gets an error; a name no server answered for, a
// SERVFAIL.
func (s *Server) Exchange(q []byte) ([]byte, error) {
	key, qend, ok := question(q)
	if !ok {
		return nil, errors.New("not a DNS query")
	}
	if op := q[2] >> 3 & 0x0f; op != 0 {
		return failure(q, qend, rcodeNotImp), nil
	}
	now := time.Now()
	s.mu.Lock()
	e := s.nets[s.net][key]
	if e != nil && now.Sub(e.At) < keepFor {
		e.Used = now
		msg, age := e.Msg, now.Sub(e.At)
		fresh := age < time.Duration(e.TTL)*time.Second
		if fresh {
			s.counts.Fresh++
		} else {
			s.counts.Stale++
		}
		s.changed = true
		s.mu.Unlock()
		if fresh {
			// the TTLs as they are now: counted down by the time kept
			gone := uint32(age / time.Second)
			return reply(q, qend, msg, func(t uint32) uint32 { return max(t-min(t, gone), 1) }), nil
		}
		go s.fetch(key, append([]byte(nil), q...))
		return reply(q, qend, msg, func(uint32) uint32 { return staleTTL }), nil
	}
	s.counts.Missed++
	s.changed = true
	s.mu.Unlock()
	msg, err := s.fetch(key, q)
	if err != nil {
		s.mu.Lock()
		s.counts.Failed++
		s.mu.Unlock()
		return failure(q, qend, rcodeServFail), nil
	}
	return reply(q, qend, msg, func(t uint32) uint32 { return t }), nil
}

// fetch asks a server for the question, once however many ask at the same
// time, and keeps the answer
func (s *Server) fetch(key string, q []byte) ([]byte, error) {
	s.mu.Lock()
	fk := flightKey{s.gen, key}
	if f, ok := s.flights[fk]; ok {
		s.mu.Unlock()
		<-f.done
		return f.msg, f.err
	}
	f := &flight{done: make(chan struct{})}
	s.flights[fk] = f
	netID := s.net
	s.mu.Unlock()

	var hole bool
	f.msg, hole, f.err = s.ask(q)
	s.mu.Lock()
	// a sinkhole every server gave is passed on, not kept: the name is
	// asked again next time, and a server that has it right by then wins.
	// Nor is an answer kept that came after the network or the servers
	// changed: see gen
	if f.err == nil && !hole && s.gen == fk.gen {
		if ttl, ok := keepable(f.msg); ok {
			s.keepLocked(netID, key, f.msg, ttl)
		}
	}
	delete(s.flights, fk)
	s.mu.Unlock()
	close(f.done)
	return f.msg, f.err
}

func (s *Server) keepLocked(netID, key string, msg []byte, ttl uint32) {
	m := s.nets[netID]
	if m == nil {
		m = map[string]*entry{}
		s.nets[netID] = m
	}
	now := time.Now()
	m[key] = &entry{Msg: msg, At: now, TTL: min(ttl, uint32(keepFor/time.Second)), Used: now}
	s.dirty = true
	if len(m) > maxNames {
		// the tenth asked for longest ago goes
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return m[keys[i]].Used.Before(m[keys[j]].Used) })
		for _, k := range keys[:len(keys)/10] {
			delete(m, k)
		}
	}
}

// ask: the answer of the fastest server; the others are asked too when it
// fails, or has not answered in a few times what it usually takes. Every
// so often all are asked at once, and each one's time is measured.
//
// A sinkhole -- loopback for a name the server blocks, see sinkhole -- is
// no answer while another server may have one: the others are asked, and
// the first real answer is taken. Only when none has one is the sinkhole
// given (hole), for a name that does live on localhost.
func (s *Server) ask(q []byte) (msg []byte, hole bool, err error) {
	s.mu.Lock()
	ups := slices.Clone(s.ups)
	d := s.dialer
	race := time.Since(s.lastRace) >= raceEvery
	for _, u := range ups {
		race = race || u.rtt == 0
	}
	if race {
		s.lastRace = time.Now()
	}
	sort.SliceStable(ups, func(i, j int) bool { return ups[i].score() < ups[j].score() })
	hedge := hedgeAfter(ups)
	s.mu.Unlock()
	if len(ups) == 0 {
		return nil, false, errors.New("no direct DNS server given by address")
	}

	// an ID of its own: the asker's is put back in the answer (see reply)
	uq := append([]byte(nil), q...)
	_, _ = rand.Read(uq[:2])
	type result struct {
		u   *upstream
		msg []byte
		err error
	}
	ch := make(chan result, len(ups))
	ex := exchangeVia
	sent := 0
	sendNext := func(all bool) {
		for ; sent < len(ups) && (all || sent == 0); sent++ {
			u := ups[sent]
			go func() {
				t := time.Now()
				msg, err := ex(u.r, d, uq)
				s.measured(u, time.Since(t), err)
				ch <- result{u, msg, err}
			}()
		}
	}
	sendNext(race)
	ht := time.NewTimer(hedge)
	defer ht.Stop()
	dt := time.NewTimer(fetchTimeout)
	defer dt.Stop()
	var errs []string
	var holed []byte   // the first sinkhole, see above
	var holedBy string // the server that gave it
	for got := 0; ; {
		select {
		case r := <-ch:
			got++
			if r.err == nil {
				if rc := r.msg[3] & 0x0f; rc == rcodeOK || rc == rcodeNXDomain {
					if !sinkhole(r.msg) {
						if holed != nil {
							s.noteHole(holedBy, uq)
						}
						return r.msg, false, nil
					}
					if holed == nil {
						holed, holedBy = r.msg, r.u.r.Raw
					}
					r.err = errors.New("a loopback address: the name is blocked there")
				} else {
					r.err = fmt.Errorf("rcode %d", r.msg[3]&0x0f)
				}
			}
			errs = append(errs, r.u.r.Raw+": "+r.err.Error())
			sendNext(true)
			if got == sent {
				if holed != nil {
					return holed, true, nil
				}
				return nil, false, errors.New(strings.Join(errs, "; "))
			}
		case <-ht.C:
			sendNext(true)
		case <-dt.C:
			if holed != nil {
				return holed, true, nil
			}
			return nil, false, fmt.Errorf("no answer in %s", fetchTimeout)
		}
	}
}

// noteHole: a server's sinkhole passed over for another server's answer,
// said once per server and name
func (s *Server) noteHole(server string, q []byte) {
	key, _, _ := question(q)
	var labels []string
	for i := 0; i < len(key) && key[i] != 0 && i+1+int(key[i]) <= len(key); i += 1 + int(key[i]) {
		labels = append(labels, key[i+1:i+1+int(key[i])])
	}
	name := strings.Join(labels, ".")
	s.mu.Lock()
	if s.holes == nil {
		s.holes = map[string]bool{}
	}
	seen := s.holes[server+" "+key]
	s.holes[server+" "+key] = true
	s.mu.Unlock()
	if !seen {
		log.Printf("DNS cache: %s answers %s with a loopback address -- blocked there; another server's answer taken", server, name)
	}
}

// exchangeVia: a query asked of a server; a var for tests
var exchangeVia = func(r probe.Resolver, d probe.Dialer, q []byte) ([]byte, error) { return r.Exchange(d, q) }

// hedgeAfter: how long the fastest server is waited for alone -- three
// times what it usually takes, within bounds
func hedgeAfter(ups []*upstream) time.Duration {
	if len(ups) == 0 {
		return 0
	}
	return min(max(3*ups[0].rtt, 40*time.Millisecond), 500*time.Millisecond)
}

// measured: how long a server took to answer, or that it failed
func (s *Server) measured(u *upstream, took time.Duration, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		u.fails++
		return
	}
	u.fails = 0
	if u.rtt == 0 {
		u.rtt = took
	} else {
		u.rtt = (7*u.rtt + 3*took) / 10
	}
}

// --- listeners ---

var (
	servingMu sync.Mutex
	serving   *Server
)

// Serving: the address the cache answers on, "" when it does not -- not
// listening, or with no server it can ask: the core then asks the direct
// list itself
func Serving() string {
	servingMu.Lock()
	s := serving
	servingMu.Unlock()
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ups) == 0 {
		return ""
	}
	return s.addr
}

// listenAddr: where Serve listens; a var for tests
var listenAddr = Addr

// Serve starts the listeners, if they are not running yet, and the writing
// of the file. The detector asks the cache in-process from now on.
func (s *Server) Serve() error {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	if s.udp != nil {
		return nil
	}
	ua, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return err
	}
	var u *net.UDPConn
	var t net.Listener
	for attempt := 0; ; attempt++ {
		if u, err = net.ListenUDP("udp", ua); err != nil {
			return fmt.Errorf("DNS cache: %w", err)
		}
		// TCP on the port UDP got: the one a truncated answer is asked again on
		if t, err = net.Listen("tcp", u.LocalAddr().String()); err == nil {
			break
		}
		u.Close()
		// a port picked by the system may be another program's over TCP:
		// another one is picked
		if ua.Port != 0 || attempt == 4 {
			return fmt.Errorf("DNS cache: %w", err)
		}
	}
	s.udp, s.tcp = u, t
	s.mu.Lock()
	s.addr = u.LocalAddr().String()
	s.mu.Unlock()
	s.stop, s.stopped = make(chan struct{}), make(chan struct{})
	go s.serveUDP(u)
	go s.serveTCP(t)
	go s.keep(s.stop, s.stopped)
	probe.SetLocal(s.Exchange)
	servingMu.Lock()
	serving = s
	servingMu.Unlock()
	s.mu.Lock()
	log.Printf("DNS cache: answering on %s, %d answers kept", s.addr, s.namesLocked())
	s.mu.Unlock()
	return nil
}

// Close stops the listeners and writes the file
func (s *Server) Close() {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	if s.udp == nil {
		return
	}
	servingMu.Lock()
	serving = nil
	servingMu.Unlock()
	probe.SetLocal(nil)
	s.udp.Close()
	s.tcp.Close()
	close(s.stop)
	<-s.stopped
	s.udp, s.tcp = nil, nil
	log.Println("DNS cache: stopped")
}

// maxUDP: the largest answer sent over UDP. The core reads 4096 bytes
// whatever it advertises, and nothing but the machine itself asks here;
// a larger answer is truncated, and asked again over TCP.
const maxUDP = 4096

func (s *Server) serveUDP(c *net.UDPConn) {
	buf := make([]byte, 64<<10)
	for {
		n, from, err := c.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue // an ICMP error of an earlier answer, on Windows
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			resp := s.respond(q)
			if resp == nil {
				return
			}
			if len(resp) > maxUDP {
				if _, qend, ok := question(q); ok {
					resp = truncate(resp, qend)
				}
			}
			_, _ = c.WriteToUDP(resp, from)
		}()
	}
}

func (s *Server) serveTCP(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go s.serveConn(c)
	}
}

// serveConn: queries one after another on a connection, until it is
// closed or quiet for a while
func (s *Server) serveConn(c net.Conn) {
	defer c.Close()
	var l [2]byte
	for {
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		q := make([]byte, int(l[0])<<8|int(l[1]))
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		resp := s.respond(q)
		if resp == nil {
			return
		}
		if _, err := c.Write(append([]byte{byte(len(resp) >> 8), byte(len(resp))}, resp...)); err != nil {
			return
		}
	}
}

// respond: the answer to a message received, nil for one not answered
func (s *Server) respond(q []byte) []byte {
	if len(q) < 12 || q[2]&0x80 != 0 {
		return nil // not a query
	}
	resp, err := s.Exchange(q)
	if err != nil {
		return failure(q, 12, rcodeFormErr)
	}
	return resp
}

// --- the file ---

// fileData: the file -- the servers the answers are of, and the answers by
// network. An answer's key is its question: read back from the answer.
type fileData struct {
	Servers []string            `json:"servers"`
	Nets    map[string][]*entry `json:"nets"`
}

func (s *Server) load() {
	b, err := os.ReadFile(s.file)
	if err != nil {
		return
	}
	var f fileData
	if err := json.Unmarshal(b, &f); err != nil {
		log.Printf("DNS cache: %s not read: %v", s.file, err)
		return
	}
	now := time.Now()
	for id, es := range f.Nets {
		m := map[string]*entry{}
		for _, e := range es {
			// a sinkhole kept before they were told apart goes: the name
			// is asked anew, and another server's answer taken
			if e == nil || now.Sub(e.At) >= keepFor || e.At.After(now) || sinkhole(e.Msg) {
				continue
			}
			if key, _, ok := answerQuestion(e.Msg); ok {
				m[key] = e
			}
		}
		if len(m) > 0 {
			s.nets[id] = m
		}
	}
	s.list = f.Servers
}

// answerQuestion: the key of an answer's question, as question gives a
// query's
func answerQuestion(m []byte) (string, int, bool) {
	if len(m) < 12 {
		return "", 0, false
	}
	q := append([]byte(nil), m...)
	q[2] &^= 0x80
	return question(q)
}

// keep writes the file and the stats every so often, until stopped; and
// once more then
func (s *Server) keep(stop <-chan struct{}, stopped chan<- struct{}) {
	defer close(stopped)
	save := time.NewTicker(saveEvery)
	defer save.Stop()
	stats := time.NewTicker(statsEvery)
	defer stats.Stop()
	s.writeStats(true)
	for {
		select {
		case <-save.C:
			s.save(false)
		case <-stats.C:
			s.writeStats(false)
		case <-stop:
			s.save(true)
			s.writeStats(true)
			return
		}
	}
}

// save writes the file when anything was kept since it last was, or always;
// the answers a week old go first
func (s *Server) save(always bool) {
	s.mu.Lock()
	now := time.Now()
	for id, m := range s.nets {
		for k, e := range m {
			if now.Sub(e.At) >= keepFor {
				delete(m, k)
				s.dirty = true
			}
		}
		if len(m) == 0 {
			delete(s.nets, id)
		}
	}
	if !s.dirty && !always {
		s.mu.Unlock()
		return
	}
	f := fileData{Servers: s.list, Nets: map[string][]*entry{}}
	for id, m := range s.nets {
		es := make([]*entry, 0, len(m))
		for _, e := range m {
			c := *e
			es = append(es, &c)
		}
		f.Nets[id] = es
	}
	s.dirty = false
	s.mu.Unlock()
	b, err := json.Marshal(f)
	if err == nil {
		err = paths.ReplaceFile(s.file, b)
	}
	if err != nil {
		log.Printf("DNS cache: %s not written: %v", s.file, err)
	}
}

// Stats: what the UI shows of the cache
type Stats struct {
	At      time.Time    `json:"at"`
	Network string       `json:"network"`
	Names   int          `json:"names"` // kept for the network
	Counts  Counts       `json:"counts"`
	Servers []ServerStat `json:"servers"` // the fastest first
}

// Asked: the queries answered since the service started
func (st Stats) Asked() int64 { return st.Counts.Fresh + st.Counts.Stale + st.Counts.Missed }

// HitPct: how many of them, in percent, were answered from the cache
func (st Stats) HitPct() int64 {
	if st.Asked() == 0 {
		return 0
	}
	return (st.Counts.Fresh + st.Counts.Stale) * 100 / st.Asked()
}

// Fastest: the server asked first, nil while none is measured
func (st Stats) Fastest() *ServerStat {
	if len(st.Servers) == 0 || st.Servers[0].Ms == 0 {
		return nil
	}
	return &st.Servers[0]
}

type ServerStat struct {
	Addr  string  `json:"addr"`
	Ms    float64 `json:"ms"` // 0 not measured yet
	Fails int     `json:"fails"`
}

func (s *Server) writeStats(always bool) {
	if s.statsFile == "" {
		return
	}
	s.mu.Lock()
	if !s.changed && !always {
		s.mu.Unlock()
		return
	}
	s.changed = false
	s.mu.Unlock()
	if b, err := json.Marshal(s.stats()); err == nil {
		_ = paths.ReplaceFile(s.statsFile, b)
	}
}

// stats: the cache as it is now
func (s *Server) stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Stats{At: time.Now(), Network: s.net, Names: len(s.nets[s.net]), Counts: s.counts}
	ups := slices.Clone(s.ups)
	sort.SliceStable(ups, func(i, j int) bool { return ups[i].score() < ups[j].score() })
	for _, u := range ups {
		st.Servers = append(st.Servers, ServerStat{u.r.Raw, float64(u.rtt.Microseconds()) / 1000, u.fails})
	}
	return st
}

// LoadStats: the stats the service last wrote; ok false for none
func LoadStats(file string) (Stats, bool) {
	var st Stats
	b, err := os.ReadFile(file)
	if err != nil || json.Unmarshal(b, &st) != nil {
		return st, false
	}
	return st, true
}
