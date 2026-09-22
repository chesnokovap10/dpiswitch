// Local web UI. A native Win32 window would need lists and fields
// laid out by hand -- hundreds of lines for what a browser
// does better. The page is embedded and weighs kilobytes.
package webui

import (
	"bufio"
	"embed"
	"encoding/json"
	"fmt"
	"log"
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
			st.ServiceText = stateText(state)
		}
	}
	// a running service and a working tunnel are different things: TUN may
	// be up with a dead peer, and then traffic goes nowhere
	if st.ServiceRun {
		st.TunnelAlive, st.TunnelNote = supervisor.TunnelAlive(
			"127.0.0.1:9090", ctl.SecretFromConfig(paths.Config()), "awg")
	}
	st.NetworkUp = supervisor.NetworkUp()

	snap := ctl.Load(paths.State())
	st.NetworkID = snap.NetworkID
	st.Counts = snap.Counts
	st.DirectCount = len(snap.Direct)
	writeJSON(w, st)
}

func stateText(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "starting"
	case svc.StopPending:
		return "stopping"
	case svc.Running:
		return "running"
	case svc.Paused:
		return "paused"
	}
	return "unknown"
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
	// both files contain the WireGuard private key, so after
	// writing they are locked down by ACL: mode 0600 means nothing on Windows
	for _, f := range []struct {
		path string
		data string
	}{{paths.SourceConf(), body.Text}, {paths.Config(), out}} {
		if err := os.WriteFile(f.path, []byte(f.data), 0o600); err != nil {
			writeResult(w, err)
			return
		}
		if err := paths.Restrict(f.path); err != nil {
			log.Printf("warning: permissions on %s not restricted: %v", f.path, err)
		}
	}
	awgconf.EnsureLists()
	writeJSON(w, map[string]any{"ok": true, "note": "config saved, restart the service"})
}

func (s *Server) handleVerdicts(w http.ResponseWriter, r *http.Request) {
	snap := ctl.Load(paths.State())
	writeJSON(w, snap)
}

// controller settings: the service picks them up within a minute
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
		var set ctl.Settings
		if err := json.NewDecoder(r.Body).Decode(&set); err != nil {
			writeResult(w, err)
			return
		}
		if err := paths.EnsureDataDir(); err != nil {
			writeResult(w, err)
			return
		}
		writeResult(w, ctl.SaveSettings(paths.Settings(), set))
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

func tail(path string, lines int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var buf []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		buf = append(buf, sc.Text())
		if len(buf) > lines {
			buf = buf[1:]
		}
	}
	return strings.Join(buf, "\n"), nil
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
