// Local web UI. A native Win32 window would need lists and fields
// laid out by hand -- hundreds of lines for what a browser
// does better. The pages are embedded and rendered here (see ui.go).
package webui

import (
	"bufio"
	"bytes"
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

	"dpiswitch/internal/session"
)

type Server struct {
	mu   sync.Mutex
	ln   net.Listener
	addr string
	// elevation is requested by the tray: the web process runs as the user
	// and cannot elevate itself
	Elevate func(verb string) error

	flashes map[string]flash
	// statusFn replaces collectStatus in tests
	statusFn func() status
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
	mux.HandleFunc("/lang", s.handleLang)
	mux.HandleFunc("/api/status", s.handleStatus)
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
	return guard(mux)
}

// Find: the address of the running DPI Switch UI in this logon session, or
// "" if none answers. It is on one of the session's candidate ports, not
// necessarily the first: Listen steps past a taken one.
func Find() string {
	cl := &http.Client{Timeout: 700 * time.Millisecond}
	for _, p := range session.Candidates() {
		if addr := fmt.Sprintf("127.0.0.1:%d", p); answers(cl, addr) {
			return "http://" + addr + "/"
		}
	}
	return ""
}

// answers: whether a DPI Switch UI answers on addr -- its status carries a
// version and a data directory; another program on the port does not.
func answers(cl *http.Client, addr string) bool {
	resp, err := cl.Get("http://" + addr + "/api/status")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var st struct {
		Version string `json:"version"`
		DataDir string `json:"data_dir"`
	}
	return resp.StatusCode == http.StatusOK &&
		json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&st) == nil &&
		st.Version != "" && st.DataDir != ""
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
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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
