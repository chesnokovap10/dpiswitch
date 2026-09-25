// Local web UI. A native Win32 window would need lists and fields
// laid out by hand -- hundreds of lines for what a browser
// does better. The page is embedded and weighs kilobytes.
package webui

import (
	"bufio"
	"bytes"
	"embed"
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

	"golang.org/x/sys/windows/svc"

	"dpiswitch/internal/autostart"
	"dpiswitch/internal/awgconf"
	"dpiswitch/internal/ctl"
	"dpiswitch/internal/netprocs"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/probe"
	"dpiswitch/internal/session"
	"dpiswitch/internal/supervisor"
	"dpiswitch/internal/version"
	"dpiswitch/internal/winsvc"
)

//go:embed index.html
var assets embed.FS

type Server struct {
	mu   sync.Mutex
	ln   net.Listener
	addr string
	// elevation is requested by the tray: the web process runs as the user
	// and cannot elevate itself
	Elevate func(verb string) error
	Reload  func() error
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

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/service/", s.handleService)
	mux.HandleFunc("/api/autostart", s.handleAutostart)
	mux.HandleFunc("/api/hosts", s.handleHosts)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/verdicts", s.handleVerdicts)
	mux.HandleFunc("/api/log", s.handleLog)
	mux.HandleFunc("/api/settings", s.handleSettings)
	mux.HandleFunc("/api/apps", s.handleApps)
	mux.HandleFunc("/api/dns/test", s.handleDNSTest)
	mux.HandleFunc("/api/awg2", s.handleAwg2)
	mux.HandleFunc("/api/config2", s.handleConfig2)
	mux.HandleFunc("/api/apps/active", s.handleActiveApps)

	go http.Serve(ln, mux)
	return nil
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

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, err := assets.ReadFile("index.html")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b)
}

type status struct {
	Installed   bool           `json:"installed"`
	PathOK      bool           `json:"path_ok"`
	BinPath     string         `json:"bin_path"`
	ExePath     string         `json:"exe_path"`
	ServiceRun  bool           `json:"service_running"`
	ServiceText string         `json:"service_text"`
	Autostart   bool           `json:"autostart"`
	HasConfig   bool           `json:"has_config"`
	DataDir     string         `json:"data_dir"`
	NetworkID   string         `json:"network_id"`
	Counts      map[string]int `json:"counts"`
	DirectCount int            `json:"direct_count"`
	Blocked     int            `json:"blocked_count"`
	TunnelAlive bool           `json:"tunnel_alive"`
	TunnelNote  string         `json:"tunnel_note"`
	NetworkUp   bool           `json:"network_up"`
	Version     string         `json:"version"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	st := status{
		Installed: winsvc.Installed(),
		ExePath:   paths.Exe(),
		BinPath:   winsvc.BinPath(),
		Autostart: autostart.Enabled(),
		DataDir:   paths.DataDir(),
		Version:   version.Version,
	}
	st.PathOK = !st.Installed || winsvc.PathMatches()
	if _, err := os.Stat(paths.Config()); err == nil {
		st.HasConfig = true
	}
	if st.Installed {
		if state, err := winsvc.State(); err == nil {
			st.ServiceRun = state == svc.Running
			st.ServiceText = winsvc.StateText(state)
		}
	}
	// a running service and a working tunnel are different things: TUN may
	// be up with a dead peer, and then traffic goes nowhere
	if st.ServiceRun {
		st.TunnelAlive, st.TunnelNote = ctl.TunnelHealth(
			"127.0.0.1:9090", ctl.SecretFromConfig(paths.Config()), "awg")
	}
	st.NetworkUp = supervisor.NetworkUp()

	snap := ctl.LoadCached(paths.State())
	st.NetworkID = snap.NetworkID
	st.Counts = snap.Counts
	st.DirectCount = len(snap.Direct)
	st.Blocked = snap.Blocked()
	writeJSON(w, st)
}

func (s *Server) handleService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	action := strings.TrimPrefix(r.URL.Path, "/api/service/")
	var err error
	switch action {
	case "install", "uninstall", "reinstall":
		// needs administrator rights -- goes through the tray's elevation
		if s.Elevate == nil {
			err = fmt.Errorf("elevation unavailable")
		} else {
			err = s.Elevate(action)
		}
	case "start":
		err = winsvc.Start()
	case "stop":
		err = winsvc.Stop()
	default:
		http.NotFound(w, r)
		return
	}
	writeResult(w, err)
}

func (s *Server) handleAutostart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	writeResult(w, autostart.Set(body.Enabled))
}

// user lists are read and written as a whole -- simpler
// and more honest than partial edits through the API
func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	var path string
	switch kind {
	case "direct":
		path = paths.ForceDirect()
	case "tunnel":
		path = paths.ForceTunnel()
	default:
		http.Error(w, "kind must be direct or tunnel", 400)
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]any{"hosts": readList(path)})
	case http.MethodPost:
		var body struct {
			Hosts []string `json:"hosts"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeResult(w, err)
			return
		}
		if err := writeList(path, kind, body.Hosts); err != nil {
			writeResult(w, err)
			return
		}
		// the core reloads the provider on file change by itself,
		// but ask explicitly -- so the change is visible immediately
		var err error
		if s.Reload != nil {
			err = s.Reload()
		}
		writeResult(w, err)
	default:
		http.Error(w, "GET or POST required", 405)
	}
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
func (s *Server) handleApps(w http.ResponseWriter, r *http.Request) {
	path := paths.ForceDirectApps()
	switch r.Method {
	case http.MethodGet:
		var apps []string
		for _, l := range readList(path) {
			if i := strings.IndexByte(l, ','); i > 0 {
				apps = append(apps, strings.TrimSpace(l[i+1:]))
			}
		}
		if apps == nil {
			apps = []string{}
		}
		writeJSON(w, map[string]any{"apps": apps})
	case http.MethodPost:
		var body struct {
			Apps []string `json:"apps"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeResult(w, err)
			return
		}
		writeResult(w, writeApps(path, body.Apps))
	default:
		http.Error(w, "GET or POST required", 405)
	}
}

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

func (s *Server) handleActiveApps(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"apps": netprocs.Active("mihomo.exe", "dpiswitch.exe")})
}

// loading a .conf: convert it and keep the source next to it,
// so the config can be rebuilt without picking the file again
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	var body struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeResult(w, err)
		return
	}
	conf, err := awgconf.Parse(body.Text)
	if err != nil {
		writeResult(w, err)
		return
	}
	out, err := conf.Render()
	if err != nil {
		writeResult(w, err)
		return
	}
	if err := paths.EnsureDataDir(); err != nil {
		writeResult(w, err)
		return
	}
	// both files contain the WireGuard private key: they are written locked
	// down from the start (mode 0600 means nothing on Windows), and not at
	// all if that cannot be done
	for _, f := range []struct {
		path string
		data string
	}{{paths.SourceConf(), body.Text}, {paths.Config(), out}} {
		if err := paths.WriteSecret(f.path, []byte(f.data)); err != nil {
			writeResult(w, err)
			return
		}
	}
	awgconf.EnsureLists()
	writeJSON(w, map[string]any{"ok": true, "note": "config saved, restart the service"})
}

func (s *Server) handleVerdicts(w http.ResponseWriter, r *http.Request) {
	snap := ctl.LoadCached(paths.State())
	writeJSON(w, snap)
}

// controller settings: the service picks them up within seconds
// on its own, no restart needed
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// DNS from the .conf -- what the tunnel uses when the setting is empty
		confDNS := []string{}
		if c, err := awgconf.ParseFile(paths.SourceConf()); err == nil {
			confDNS = c.DNS()
		}
		writeJSON(w, map[string]any{
			"settings": ctl.LoadSettings(paths.Settings()),
			"defaults": ctl.DefaultSettings(),
			"conf_dns": confDNS,
		})
	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeResult(w, err)
			return
		}
		if err := paths.EnsureDataDir(); err != nil {
			writeResult(w, err)
			return
		}
		writeResult(w, ctl.PatchSettings(paths.Settings(), body))
	default:
		http.Error(w, "GET or POST required", 405)
	}
}

// checks resolvers over the same path the core will use:
// direct ones via the prober's listener bypassing the tunnel, tunnel ones via awg
func (s *Server) handleDNSTest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Servers []string `json:"servers"`
		Path    string   `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeResult(w, err)
		return
	}
	cfg := ctl.Defaults()
	d := probe.Dialer{Addr: cfg.DirectAddr, Timeout: 6 * time.Second}
	if body.Path == "tunnel" {
		d.Addr = cfg.TunnelAddr
	}
	type result struct {
		Server string   `json:"server"`
		OK     bool     `json:"ok"`
		Ms     int64    `json:"ms"`
		IPs    []string `json:"ips,omitempty"`
		Error  string   `json:"error,omitempty"`
	}
	out := make([]result, len(body.Servers))
	var wg sync.WaitGroup
	for i, srv := range body.Servers {
		wg.Add(1)
		go func(i int, srv string) {
			defer wg.Done()
			res := result{Server: srv}
			rs, err := probe.ParseResolver(srv)
			if err == nil {
				t := time.Now()
				// whoami.akamai.net answers with the address of the recursive
				// server that queried it: this shows WHO actually
				// resolves. With an ordinary domain the answer
				// looked as if the domain owner were resolving
				res.IPs, err = rs.Lookup(d, "whoami.akamai.net")
				res.Ms = time.Since(t).Milliseconds()
			}
			if err != nil {
				res.Error = err.Error()
			} else {
				res.OK = len(res.IPs) > 0
			}
			out[i] = res
		}(i, srv)
	}
	wg.Wait()
	writeJSON(w, map[string]any{"ok": true, "results": out})
}

func (s *Server) handleLog(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	var path string
	switch name {
	case "mihomo":
		path = paths.MihomoLog()
	case "service":
		path = paths.ServiceLog()
	default:
		path = paths.ControllerLog()
	}
	b, err := tail(path, 400)
	if err != nil {
		// the tab refreshes itself, and an OS error text on every
		// refresh would look like a failure while the file simply doesn't exist yet
		b = "log is empty so far (" + filepath.Base(path) + " not created yet)"
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(b))
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

func writeResult(w http.ResponseWriter, err error) {
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}
