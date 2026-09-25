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
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"dpiswitch/internal/paths"
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

	flashes map[string]flash
	// statusFn replaces collectStatus in tests
	statusFn func() status
	// presetMu: a preset's settings and its files are written as one step
	presetMu sync.Mutex
	// listMu: a list's save -- read the old one, write, read back what moved
	// -- is one step. Two tabs saving at once shared one ".tmp" file, and
	// one's change could be lost or its rename fail.
	listMu sync.Mutex
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
	return nil
}

// Handler: every page, fragment and action of the UI.
func (s *Server) Handler() http.Handler {
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
	mux.HandleFunc(helloPath, s.handleHello)
	for path, h := range map[string]http.HandlerFunc{
		"/act/auto":      s.actAuto,
		"/act/service":   s.actService,
		"/act/autostart": s.actAutostart,
		"/act/config":    s.actConfig,
		"/act/config2":   s.actConfig2,
		"/act/detach2":   s.actDetach2,
		"/act/reset":     s.actReset,
		"/act/list":      s.actList,
		"/act/apps":      s.actApps,
		"/act/preset":    s.actPreset,
		"/act/awg2hosts": s.actAwg2Hosts,
		"/act/set":       s.actSet,
		"/act/dns":       s.actDNS,
		"/act/dnstest":   s.actDNSTest,
		"/act/defaults":  s.actDefaults,
	} {
		mux.HandleFunc(path, post(h))
	}
	return guard(s.auth(mux))
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
	cl := &http.Client{Timeout: 700 * time.Millisecond}
	for _, p := range session.Ports() {
		if addr := fmt.Sprintf("127.0.0.1:%d", p); answers(cl, addr, key) {
			return WithKey("http://"+addr+"/", key)
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

func writeList(path, kind string, hosts []string) error {
	seen := map[string]bool{}
	var clean []string
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		h = strings.TrimPrefix(h, "http://")
		h = strings.TrimPrefix(h, "https://")
		if i := strings.IndexAny(h, "/:"); i > 0 {
			h = h[:i]
		}
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		clean = append(clean, h)
	}
	sort.Strings(clean)

	var b strings.Builder
	fmt.Fprintf(&b, "# always %s -- list maintained by the user\n", kind)
	b.WriteString("# +.example.com also covers subdomains\n")
	for _, h := range clean {
		b.WriteString(h + "\n")
	}
	return paths.ReplaceFile(path, []byte(b.String()))
}

// excluded programs. The file holds ready classical core rules:
// a name without a path -> PROCESS-NAME (survives updates to a new path),
// a full path -> PROCESS-PATH (when several exes share a name).
// The core watches the file itself, no API reload needed.
func writeApps(path string, apps []string) error {
	seen := map[string]bool{}
	var rules []string
	for _, a := range apps {
		a = strings.Trim(strings.TrimSpace(a), `"`)
		if a == "" {
			continue
		}
		// a comma is the field separator in a core rule
		if strings.Contains(a, ",") {
			return fmt.Errorf("%q: commas in the name are not supported", a)
		}
		if !strings.HasSuffix(strings.ToLower(a), ".exe") {
			return fmt.Errorf("%q: a program name with .exe is required, e.g. telegram.exe", a)
		}
		kind := "PROCESS-NAME"
		if strings.ContainsAny(a, `\/`) {
			kind = "PROCESS-PATH"
			a = filepath.Clean(a)
		}
		if seen[strings.ToLower(a)] {
			continue
		}
		seen[strings.ToLower(a)] = true
		rules = append(rules, kind+","+a)
	}
	sort.Slice(rules, func(i, j int) bool { return strings.ToLower(rules[i]) < strings.ToLower(rules[j]) })

	var b strings.Builder
	b.WriteString("# programs whose traffic bypasses the tunnel -- list maintained by the user\n")
	for _, r := range rules {
		b.WriteString(r + "\n")
	}
	return paths.ReplaceFile(path, []byte(b.String()))
}

// tailWindow: how much of a log's end tail reads. The log tab refreshes
// every five seconds, and reading all of mihomo.log for 400 lines took
// 4.4 ms and 8.7 MB each time; 400 lines are some 80 KB.
const tailWindow = 256 << 10

// tail: the last lines of a log, read from its end only.
func tail(path string, lines int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	off := max(fi.Size()-tailWindow, 0)
	b := make([]byte, fi.Size()-off)
	n, err := f.ReadAt(b, off)
	if err != nil && err != io.EOF {
		return "", err
	}
	b = b[:n]
	if off > 0 {
		// the window starts mid-line
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	ls := strings.Split(strings.TrimRight(string(b), "\r\n"), "\n")
	if len(ls) > lines {
		ls = ls[len(ls)-lines:]
	}
	for i, l := range ls {
		ls[i] = strings.TrimSuffix(l, "\r")
	}
	return strings.Join(ls, "\n"), nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}
