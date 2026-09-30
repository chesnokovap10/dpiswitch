// Local web UI. A native Win32 window would need lists and fields
// laid out by hand -- hundreds of lines for what a browser
// does better. The pages are embedded and rendered here (see ui.go).
package webui

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"dpiswitch/internal/session"
)

type Server struct {
	mu   sync.Mutex
	ln   net.Listener
	addr string
	// elevation is requested by the tray: the web process runs as the user
	// and cannot elevate itself
	Elevate func(verb string) error

	// Key: the secret every request must carry (see auth.go); empty in
	// tests, where the UI is open
	Key string

	// LangFile keeps the language switched to on a page, for the tray's next
	// start; empty in tests. OnLang: the pages' language changed (see lang.go).
	LangFile string
	OnLang   func()
	lang     string

	flashes map[string]flash
	// statusFn replaces collectStatus in tests
	statusFn func() status
	// listMu: a list's save -- read the old one, write, read back what moved
	// -- is one step. Two tabs saving at once shared one ".tmp" file, and
	// one's change could be lost or its rename fail.
	listMu sync.Mutex

	// live: the loop asking the core for its connections while the live
	// page is open; a fake core's in tests
	live *liveHub
}

func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

// Start serves on a port that is stable within the logon session:
// an open tab and a bookmark must survive a program restart.
// Never listens outside -- loopback only.
func (s *Server) Start() error {
	ln, err := session.Listen()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.ln = ln
	s.addr = "http://" + ln.Addr().String()
	s.mu.Unlock()

	go http.Serve(ln, s.Handler())
	// the live page's history is of the core's whole run: gathered from the
	// start, not from the first time the page is opened
	s.live.start()
	return nil
}

// Handler: every page, fragment and action of the UI.
func (s *Server) Handler() http.Handler {
	if s.live == nil {
		s.live = newLiveHub(coreSource)
	}
	mux := http.NewServeMux()
	for _, p := range pageNames {
		mux.HandleFunc("/"+p, s.handlePage)
	}
	mux.HandleFunc("/", s.handlePage)
	mux.HandleFunc("/frag/", s.handleFrag)
	mux.HandleFunc("/static/", s.handleStatic)
	mux.HandleFunc("/favicon.ico", s.handleIcon)
	mux.HandleFunc("/lang", s.handleLang)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/live/stream", s.handleLive)
	mux.HandleFunc("/live/presets", s.handleLivePresets)
	mux.HandleFunc(helloPath, s.handleHello)
	for path, h := range map[string]http.HandlerFunc{
		"/act/auto":          s.actAuto,
		"/act/service":       s.actService,
		"/act/autostart":     s.actAutostart,
		"/act/config":        s.actConfig,
		"/act/config2":       s.actConfig2,
		"/act/detach2":       s.actDetach2,
		"/act/delete1":       s.actDelete1,
		"/act/awg2":          s.actAwg2,
		"/act/reset":         s.actReset,
		"/act/list":          s.actList,
		"/act/preset":        s.actPreset,
		"/act/presetsave":    s.actPresetSave,
		"/act/presetdel":     s.actPresetDel,
		"/act/presetrestore": s.actPresetRestore,
		"/act/set":           s.actSet,
		"/act/dns":           s.actDNS,
		"/act/dnstest":       s.actDNSTest,
		"/act/defaults":      s.actDefaults,
		"/act/liveclose":     s.actLiveClose,
		"/act/liveclear":     s.actLiveClear,
		"/act/liveadd":       s.actLiveAdd,
		"/act/livereveal":    s.actLiveReveal,
	} {
		mux.HandleFunc(path, post(h))
	}
	return guard(s.auth(s.withLang(mux)))
}

// withLang: a browser that has not switched the language yet (no cookie)
// gets the tray's -- the one last switched to, else Windows' -- not its own
// Accept-Language, so the first start speaks one language throughout. Not in
// tests (no LangFile): their pages stay English whatever the machine's.
func (s *Server) withLang(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.LangFile != "" {
			if c, err := r.Cookie("lang"); err != nil || (c.Value != "ru" && c.Value != "en") {
				r.AddCookie(&http.Cookie{Name: "lang", Value: SavedLang(s.LangFile)})
			}
		}
		h.ServeHTTP(w, r)
	})
}

// URL: the address to open the UI at, with the key a browser trades for
// its cookie on the first request.
func (s *Server) URL() string {
	return WithKey(s.Addr()+"/", s.Key)
}

// Find: the address of the running DPI Switch UI in this logon session,
// key included, or "" if none answers. It is on one of the session's
// candidate ports, not necessarily the first: Listen steps past a taken
// one -- or on the port it fell back to past all of them. Another user's UI
// does not answer: it has another key.
func Find(key string) string {
	// all at once: one after another, ports held by something that takes a
	// connection and never answers cost 700 ms each -- 45 s for 64 of them.
	// Of those that answer, the first in Listen's order wins.
	cl := &http.Client{Timeout: 700 * time.Millisecond}
	ports := session.Ports()
	ok := make([]bool, len(ports))
	var wg sync.WaitGroup
	for i, p := range ports {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok[i] = answers(cl, fmt.Sprintf("127.0.0.1:%d", p), key)
		}()
	}
	wg.Wait()
	for i, p := range ports {
		if ok[i] {
			return WithKey(fmt.Sprintf("http://127.0.0.1:%d/", p), key)
		}
	}
	return ""
}

// answers: whether our DPI Switch UI answers on addr. It is asked to prove
// it holds the key (see helloProof), and the key itself is never sent: it
// used to go in a header to every candidate port before anything was known
// of what listened there, and a process of another account holding the
// first one got it -- and with it the real UI.
func answers(cl *http.Client, addr, key string) bool {
	var b [16]byte
	rand.Read(b[:])
	nonce := hex.EncodeToString(b[:])
	resp, err := cl.Get("http://" + addr + helloPath + "?n=" + nonce)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	_, port, _ := net.SplitHostPort(addr)
	return err == nil && resp.StatusCode == http.StatusOK &&
		hmac.Equal(bytes.TrimSpace(body), []byte(helloProof(key, port, nonce)))
}

func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		s.ln.Close()
	}
}

// handleStatus: what Find asks to tell this UI from another program on
// the port
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.status())
}

func readList(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{}
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	sort.Strings(out)
	if out == nil {
		out = []string{}
	}
	return out
}

// tailWindow: how much of a log's end tail reads. The log tab refreshes
// every three seconds, and reading all of mihomo.log for 400 lines took
// 4.4 ms and 8.7 MB each time; 400 lines are some 80 KB.
const tailWindow = 256 << 10

// tail: the last lines of a log, read from its end only. A log rotated
// goes on in its previous copy, path.1: the service's is rotated as it
// starts, the core's as it grows, and a log just rotated showed a few lines
// -- the end of the run before the restart, the very lines looked for, was
// out of sight.
func tail(path string, lines int) (string, error) {
	ls, err := tailLines(path, lines)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if len(ls) < lines {
		prev, perr := tailLines(path+".1", lines-len(ls))
		if perr == nil {
			ls, err = append(prev, ls...), nil
		}
	}
	if err != nil {
		return "", err
	}
	return strings.Join(ls, "\n"), nil
}

// tailLines: the last lines of one file, none for an empty one.
func tailLines(path string, lines int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	off := max(fi.Size()-tailWindow, 0)
	b := make([]byte, fi.Size()-off)
	n, err := f.ReadAt(b, off)
	if err != nil && err != io.EOF {
		return nil, err
	}
	b = b[:n]
	if off > 0 {
		// the window starts mid-line
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	text := strings.TrimRight(string(b), "\r\n")
	if text == "" {
		return nil, nil
	}
	ls := strings.Split(text, "\n")
	if len(ls) > lines {
		ls = ls[len(ls)-lines:]
	}
	for i, l := range ls {
		ls[i] = strings.TrimSuffix(l, "\r")
	}
	return ls, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}
