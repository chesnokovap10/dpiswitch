// Локальный веб-интерфейс. Нативное окно на Win32 потребовало бы
// руками верстать списки и поля -- сотни строк ради того, что
// браузер делает лучше. Страница вшита, весит килобайты.
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
	// элевация запрашивается треем: веб-процесс работает от пользователя
	// и сам права повысить не может
	Elevate func(verb string) error
	Reload  func() error
}

func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

// Start поднимает сервер на порту, постоянном внутри сеанса входа:
// открытая вкладка и закладка должны переживать перезапуск программы.
// Наружу не слушаем никогда -- только петля.
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
	// поднятая служба и работающий туннель -- разные вещи: TUN может
	// стоять при мёртвом пире, и тогда трафик уходит в никуда
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
		return "остановлена"
	case svc.StartPending:
		return "запускается"
	case svc.StopPending:
		return "останавливается"
	case svc.Running:
		return "работает"
	case svc.Paused:
		return "приостановлена"
	}
	return "неизвестно"
}

func (s *Server) handleService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "нужен POST", 405)
		return
	}
	action := strings.TrimPrefix(r.URL.Path, "/api/service/")
	var err error
	switch action {
	case "install", "uninstall", "reinstall":
		// требует администратора -- уходит через элевацию трея
		if s.Elevate == nil {
			err = fmt.Errorf("элевация недоступна")
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
		http.Error(w, "нужен POST", 405)
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	writeResult(w, autostart.Set(body.Enabled))
}

// списки пользователя: читаются и пишутся целиком, это проще
// и честнее, чем частичные правки через API
func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	var path string
	switch kind {
	case "direct":
		path = paths.ForceDirect()
	case "tunnel":
		path = paths.ForceTunnel()
	default:
		http.Error(w, "kind должен быть direct или tunnel", 400)
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
		// ядро перечитывает провайдер само по изменению файла,
		// но просим явно -- так изменение видно сразу
		var err error
		if s.Reload != nil {
			err = s.Reload()
		}
		writeResult(w, err)
	default:
		http.Error(w, "нужен GET или POST", 405)
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
	fmt.Fprintf(&b, "# принудительно %s -- список ведёт пользователь\n", kind)
	b.WriteString("# +.example.com покрывает и поддомены\n")
	for _, h := range clean {
		b.WriteString(h + "\n")
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// программы-исключения. В файле -- готовые классические правила ядра:
// имя без пути -> PROCESS-NAME (переживает обновления с новым путём),
// полный путь -> PROCESS-PATH (когда одноимённых exe несколько).
// Ядро следит за файлом само, перечитывать через API не нужно.
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
		http.Error(w, "нужен GET или POST", 405)
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
		// запятая -- разделитель полей в правиле ядра
		if strings.Contains(a, ",") {
			return fmt.Errorf("%q: запятая в имени не поддерживается", a)
		}
		if !strings.HasSuffix(strings.ToLower(a), ".exe") {
			return fmt.Errorf("%q: нужно имя программы с .exe, например telegram.exe", a)
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
	b.WriteString("# программы, чей трафик идёт мимо туннеля -- список ведёт пользователь\n")
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

// подгрузка .conf: конвертируем и кладём рядом исходник,
// чтобы конфиг можно было пересобрать без повторного выбора файла
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "нужен POST", 405)
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
	// оба файла содержат приватный ключ WireGuard, поэтому после
	// записи закрываем их правами: режим 0600 на Windows ничего не даёт
	for _, f := range []struct {
		path string
		data string
	}{{paths.SourceConf(), body.Text}, {paths.Config(), out}} {
		if err := os.WriteFile(f.path, []byte(f.data), 0o600); err != nil {
			writeResult(w, err)
			return
		}
		if err := paths.Restrict(f.path); err != nil {
			log.Printf("предупреждение: права на %s не ограничены: %v", f.path, err)
		}
	}
	awgconf.EnsureLists()
	writeJSON(w, map[string]any{"ok": true, "note": "конфиг записан, перезапусти службу"})
}

func (s *Server) handleVerdicts(w http.ResponseWriter, r *http.Request) {
	snap := ctl.Load(paths.State())
	writeJSON(w, snap)
}

// настройки контроллера: служба подхватывает их в течение минуты
// сама, перезапуск не нужен
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// DNS из .conf -- то, что стоит в туннеле при пустой настройке
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
		http.Error(w, "нужен GET или POST", 405)
	}
}

// проверка резолверов тем же путём, каким ими будет пользоваться ядро:
// прямые -- через вход пробника мимо туннеля, туннельные -- через awg
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
				// whoami.akamai.net отвечает адресом того рекурсивного
				// сервера, который к нему пришёл: видно, КТО на самом деле
				// резолвит. на обычном домене (раньше был ya.ru) ответ
				// выглядел так, будто резолвит владелец домена
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
		// вкладка обновляется сама, и текст ошибки ОС на каждом
		// обновлении выглядел бы как поломка, хотя файла просто ещё нет
		b = "журнал пока пуст (" + filepath.Base(path) + " не создан)"
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
