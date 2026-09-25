package webui

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"

	"dpiswitch/internal/autostart"
	"dpiswitch/internal/awgconf"
	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
	"dpiswitch/internal/winsvc"
)

// Every action answers in one of two ways. A form sent in the background
// (data-swap) gets the part of the page it changed, drawn afresh with a
// message in it. A plain form -- one that restarts the service or reloads
// the page anyway -- is redirected back to its page with the message waiting
// there (Post/Redirect/Get: a reload does not send it twice).

func post(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}

// part renders a fragment of a page after an action, with its message.
func (s *Server) part(w http.ResponseWriter, r *http.Request, page, name string, ok bool, msg string) {
	s.fresh()
	v := &view{Lang: lang(r), Page: page, Path: back(r), St: s.status()}
	if msg != "" {
		v.Msg = &flash{ok, msg}
	}
	v.Data = s.pageData(r, page, v)
	render(w, v, name)
}

// done: the message for a result, translated
func done(r *http.Request, err error, okText string, args ...any) (bool, string) {
	if err != nil {
		// the settings' own checks speak in fixed sentences: translated too
		return false, tr(lang(r), err.Error())
	}
	return true, fmt.Sprintf(tr(lang(r), okText), args...)
}

// redirect finishes a plain form: the message waits on the page it came from.
func (s *Server) redirect(w http.ResponseWriter, r *http.Request, err error, okText string, args ...any) {
	to := back(r)
	ok, msg := done(r, err, okText, args...)
	s.setFlash(pageOf(to), ok, msg)
	s.fresh()
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// --- header: auto-switch and the service ---

func (s *Server) actAuto(w http.ResponseWriter, r *http.Request) {
	on := r.FormValue("value") == "on"
	err := ctl.PatchSettings(paths.Settings(), []byte(fmt.Sprintf(`{"auto_switch":%v}`, on)))
	ok, msg := done(r, err, "")
	s.part(w, r, pageOf(back(r)), "header", ok, msg)
}

// actService: start and stop wait for the service to get there (up to
// 30 s); installing and removing ask for administrator rights, and the
// prompt is the user's to answer -- the status follows by itself.
func (s *Server) actService(w http.ResponseWriter, r *http.Request) {
	do := r.FormValue("do")
	var err error
	switch do {
	case "start":
		err = winsvc.Start()
	case "stop":
		err = winsvc.Stop()
	case "install", "uninstall", "reinstall":
		if s.Elevate == nil {
			err = errors.New("elevation unavailable")
		} else {
			err = s.Elevate(do)
		}
		s.redirect(w, r, err, "Confirm the administrator prompt: the status updates by itself")
		return
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	ok, msg := done(r, err, "")
	s.part(w, r, pageOf(back(r)), "header", ok, msg)
}

func (s *Server) actAutostart(w http.ResponseWriter, r *http.Request) {
	err := autostart.Set(r.FormValue("value") == "1")
	ok, msg := done(r, err, "")
	s.part(w, r, pageOf(back(r)), "svcbox", ok, msg)
}

// --- configs ---

// confText: a .conf from the form -- the file picked, else the text pasted
func confText(r *http.Request) (string, error) {
	if err := r.ParseMultipartForm(1 << 20); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		return "", err
	}
	if f, _, err := r.FormFile("file"); err == nil {
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, 256<<10))
		if err != nil {
			return "", err
		}
		if t := strings.TrimSpace(string(b)); t != "" {
			return t, nil
		}
	}
	if t := strings.TrimSpace(r.FormValue("text")); t != "" {
		return t, nil
	}
	return "", errors.New(tr(lang(r), "Paste a .conf or pick the file"))
}

// actConfig loads the first tunnel's .conf and applies it: the service is
// restarted if it runs. It used to be saved only, with "restart the
// service" left for the user to do.
func (s *Server) actConfig(w http.ResponseWriter, r *http.Request) {
	text, err := confText(r)
	if err == nil {
		err = saveConf1(text)
	}
	if err != nil {
		s.redirect(w, r, err, "")
		return
	}
	s.redirect(w, r, restartService(), applyNote())
}

func saveConf1(text string) error {
	conf, err := awgconf.Parse(text)
	if err != nil {
		return err
	}
	out, err := conf.Render()
	if err != nil {
		return err
	}
	if err := paths.EnsureDataDir(); err != nil {
		return err
	}
	// both files contain the WireGuard private key: they are written locked
	// down from the start (mode 0600 means nothing on Windows), and not at
	// all if that cannot be done
	if err := paths.WriteSecret(paths.SourceConf(), []byte(text)); err != nil {
		return err
	}
	if err := paths.WriteSecret(paths.Config(), []byte(out)); err != nil {
		return err
	}
	awgconf.EnsureLists()
	return nil
}

// applyNote: what happened to a saved config, by the state of the service
func applyNote() string {
	if !winsvc.Installed() {
		return "Config saved. Install the service to start the tunnel"
	}
	if st, err := winsvc.State(); err == nil && st == svc.Running {
		return "Config applied: the service restarted"
	}
	return "Config saved. Start the service to use it"
}

func (s *Server) actConfig2(w http.ResponseWriter, r *http.Request) {
	text, err := confText(r)
	if err == nil {
		err = saveConf2(text)
	}
	if err != nil {
		s.redirect(w, r, err, "")
		return
	}
	s.redirect(w, r, restartService(), applyNote())
}

func (s *Server) actDetach2(w http.ResponseWriter, r *http.Request) {
	err := os.Remove(paths.SourceConf2())
	if err != nil && !os.IsNotExist(err) {
		s.redirect(w, r, err, "")
		return
	}
	s.redirect(w, r, restartService(), "Second tunnel detached")
}

// --- verdicts ---

// actReset drops every verdict: all traffic returns to the tunnel. The
// service does it -- it holds the verdicts in memory (see ctl.takeReset);
// the request is a file it looks for every second.
func (s *Server) actReset(w http.ResponseWriter, r *http.Request) {
	if st, err := winsvc.State(); err != nil || st != svc.Running {
		s.redirect(w, r, errors.New(tr(lang(r), "The service is not running: there is nothing to reset")), "")
		return
	}
	req := paths.ResetRequest()
	if err := os.WriteFile(req, []byte(time.Now().Format(time.RFC3339)+"\n"), 0o644); err != nil {
		s.redirect(w, r, err, "")
		return
	}
	for i := 0; i < 40; i++ {
		if _, err := os.Stat(req); os.IsNotExist(err) {
			s.redirect(w, r, nil, "Verdicts reset: everything goes through the tunnel, the detector starts over")
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	s.redirect(w, r, nil, "Reset requested: the service takes it as soon as its controller runs")
}

// --- routing lists ---

// closeMoved closes the open connections a list change moves to another
// route: the core routes a connection once, when it opens, and a browser
// holds its connections for minutes. Not an error if the core is not up --
// then there is nothing open (see ctl.CloseConns). Any other failure is
// reported: the error used to be dropped, and the UI said "Saved" while the
// connections already open kept their old route.
//
// The provider is reloaded first: see ctl.ReloadProviders.
func closeMoved(provider string, match func(ctl.Conn) bool) (int, error) {
	secret := ctl.SecretFromConfig(paths.Config())
	if err := ctl.ReloadProviders(apiAddr, secret, provider); err != nil {
		log.Printf("ui: %v", err)
		return 0, err
	}
	n, err := ctl.CloseConns(apiAddr, secret, match)
	if err != nil {
		log.Printf("ui: open connections a list change moved not closed: %v", err)
	}
	if n > 0 {
		log.Printf("ui: closed %d connections a list change moved", n)
	}
	return n, err
}

// providerOf: the rule-provider a list file is, as the core config names
// it -- the file's name without .txt
func providerOf(path string) string {
	return strings.TrimSuffix(filepath.Base(path), ".txt")
}

// changed: the entries in one of two lists and not the other
func changed(old, cur []string) []string {
	in := func(l []string, x string) bool {
		for _, y := range l {
			if strings.EqualFold(x, y) {
				return true
			}
		}
		return false
	}
	var out []string
	for _, x := range old {
		if !in(cur, x) {
			out = append(out, x)
		}
	}
	for _, x := range cur {
		if !in(old, x) {
			out = append(out, x)
		}
	}
	return out
}

func domainMatch(rules []string) func(ctl.Conn) bool {
	return func(c ctl.Conn) bool {
		for _, rl := range rules {
			if ctl.MatchDomainRule(rl, c.Host) {
				return true
			}
		}
		return false
	}
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// saveDomains writes a domain list and closes what the change moved. err is
// the list's own, closeErr the connections'.
func (s *Server) saveDomains(path, kind string, entries []string) (n int, err, closeErr error) {
	s.listMu.Lock()
	old := readList(path)
	err = writeList(path, kind, entries)
	cur := readList(path)
	s.listMu.Unlock()
	if err != nil {
		return 0, err, nil
	}
	n, closeErr = closeMoved(providerOf(path), domainMatch(changed(old, cur)))
	return n, nil, closeErr
}

func (s *Server) actList(w http.ResponseWriter, r *http.Request) {
	kind := r.FormValue("kind")
	path := map[string]string{"direct": paths.ForceDirect(), "tunnel": paths.ForceTunnel()}[kind]
	if path == "" {
		http.Error(w, "kind must be direct or tunnel", http.StatusBadRequest)
		return
	}
	n, err, cerr := s.saveDomains(path, kind, splitLines(r.FormValue("hosts")))
	ok, msg := saved(r, err, n, cerr)
	s.part(w, r, "lists", "list-"+kind, ok, msg)
}

// actApps saves the program list; "add" puts a program from the online
// list into it and saves at once -- it used to land in the field only,
// waiting for a Save that was easy to miss.
func (s *Server) actApps(w http.ResponseWriter, r *http.Request) {
	apps := splitLines(r.FormValue("apps"))
	if r.FormValue("op") == "add" {
		a := strings.TrimSpace(r.FormValue("add"))
		if a == "" {
			s.part(w, r, "lists", "list-apps", false, tr(lang(r), "Pick a program from the list first"))
			return
		}
		apps = append(apps, a)
	}
	s.listMu.Lock()
	old := readApps()
	err := writeApps(paths.ForceDirectApps(), apps)
	cur := readApps()
	s.listMu.Unlock()
	n := 0
	var cerr error
	if err == nil {
		moved := changed(old, cur)
		n, cerr = closeMoved("force-direct-apps", func(c ctl.Conn) bool {
			for _, a := range moved {
				if strings.EqualFold(a, c.Process) || strings.EqualFold(a, c.ProcessPath) {
					return true
				}
			}
			return false
		})
	}
	ok, msg := saved(r, err, n, cerr)
	s.part(w, r, "lists", "list-apps", ok, msg)
}

// --- second tunnel ---

// actPreset turns one preset on or off at once. Its file is rewritten (the
// core watches it) and the connections it moves are closed.
func (s *Server) actPreset(w http.ResponseWriter, r *http.Request) {
	id, on := r.FormValue("field"), r.FormValue("value") == "1"
	var p *presets.Preset
	for i := range presets.All {
		if presets.All[i].ID == id {
			p = &presets.All[i]
		}
	}
	if p == nil {
		http.Error(w, "unknown preset", http.StatusBadRequest)
		return
	}
	toggle := func(cur []string) []string {
		ids := []string{}
		for _, x := range cur {
			if x != id {
				ids = append(ids, x)
			}
		}
		if on {
			ids = append(ids, id)
		}
		return ids
	}
	// the preset files follow the settings in the same order: two quick
	// clicks could otherwise write their files the other way round. The
	// files go first: settings saved before a file that then failed said
	// the preset was on while its file said off. On any failure the files
	// are put back to what the settings say.
	s.presetMu.Lock()
	err := presets.Write(toggle(ctl.LoadSettings(paths.Settings()).Awg2Presets))
	if err == nil {
		_, err = ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error {
			set.Awg2Presets = toggle(set.Awg2Presets)
			return nil
		})
	}
	if err != nil {
		if werr := presets.Write(ctl.LoadSettings(paths.Settings()).Awg2Presets); werr != nil {
			log.Printf("ui: preset files not put back after a failed change: %v", werr)
		}
	}
	s.presetMu.Unlock()
	n := 0
	var cerr error
	if err == nil {
		n, cerr = closeMoved("preset-"+p.ID, presetMatch(*p))
	}
	ok, msg := saved(r, err, n, cerr)
	s.part(w, r, "awg2", "presets", ok, msg)
}

// presetMatch: the connections a preset's rules take, and the ones it did
func presetMatch(p presets.Preset) func(ctl.Conn) bool {
	var suffixes []string
	var nets []*netPrefix
	for _, rl := range p.Rules() {
		f := strings.Split(rl, ",")
		switch f[0] {
		case "DOMAIN-SUFFIX":
			suffixes = append(suffixes, "+."+f[1])
		case "IP-CIDR", "IP-CIDR6":
			if n := parsePrefix(f[1]); n != nil {
				nets = append(nets, n)
			}
		}
	}
	dm := domainMatch(suffixes)
	return func(c ctl.Conn) bool {
		if c.RulePayload == "preset-"+p.ID || dm(c) {
			return true
		}
		for _, n := range nets {
			if n.contains(c.IP) {
				return true
			}
		}
		return false
	}
}

func (s *Server) actAwg2Hosts(w http.ResponseWriter, r *http.Request) {
	n, err, cerr := s.saveDomains(paths.Awg2Hosts(), "via the second tunnel", splitLines(r.FormValue("hosts")))
	ok, msg := saved(r, err, n, cerr)
	s.part(w, r, "awg2", "hosts", ok, msg)
}

// saved: the result of a list saved, with the connections it moved when
// there were any. A list written whose open connections could not be closed
// is not a plain "Saved": those connections keep their old route.
func saved(r *http.Request, err error, moved int, closeErr error) (bool, string) {
	if err == nil && closeErr != nil {
		return false, tr(lang(r), "Saved, but the open connections were not moved: "+
			"they keep their old route until they reconnect")
	}
	if err == nil && moved > 0 {
		return done(r, nil, "Saved; %d open connections moved", moved)
	}
	return done(r, err, "Saved")
}

// --- settings ---

// actSet changes one setting the moment its control changes. The controller
// picks it up within a second (see ctl.watchSettings).
func (s *Server) actSet(w http.ResponseWriter, r *http.Request) {
	field, val := r.FormValue("field"), strings.TrimSpace(r.FormValue("value"))
	num := func() (int, error) {
		n, err := strconv.Atoi(val)
		if err != nil {
			return 0, errors.New(tr(lang(r), "A number is needed"))
		}
		return n, nil
	}
	switch field {
	case "auto_switch", "families", "ipv6", "clean_ttl_min", "fail_ttl_min", "max_backoff_min", "slow_pct", "attempts":
	default:
		http.Error(w, "unknown setting", http.StatusBadRequest)
		return
	}
	note := "Saved"
	err := paths.EnsureDataDir()
	if err == nil {
		_, err = ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error {
			var err error
			switch field {
			case "auto_switch":
				set.AutoSwitch = val == "1"
			case "families":
				set.Families = val == "1"
			case "ipv6":
				set.IPv6 = val == "1"
				note = "Saved: the core restarts, the tunnel drops for a couple of seconds"
			case "clean_ttl_min":
				set.CleanTTLMin, err = num()
			case "fail_ttl_min":
				set.FailTTLMin, err = num()
				// the pause cap cannot be below the re-check: it follows it
				// up instead of the save being refused
				if err == nil && set.MaxBackoffMin < set.FailTTLMin {
					set.MaxBackoffMin = set.FailTTLMin
					note = "Saved; the pause cap was raised to match"
				}
			case "max_backoff_min":
				set.MaxBackoffMin, err = num()
			case "slow_pct":
				set.SlowPct, err = num()
			case "attempts":
				set.Attempts, err = num()
			}
			return err
		})
	}
	ok, msg := done(r, err, note)
	s.partField(w, r, field, ok, msg)
}

// partField: the settings table with the message beside the row it is about
func (s *Server) partField(w http.ResponseWriter, r *http.Request, field string, ok bool, msg string) {
	s.fresh()
	v := &view{Lang: lang(r), Page: "settings", Path: back(r), St: s.status()}
	d := settingsData()
	d.Field, d.Res = field, &flash{ok, msg}
	v.Data = d
	render(w, v, "form")
}

func (s *Server) actDNS(w http.ResponseWriter, r *http.Request) {
	err := paths.EnsureDataDir()
	if err == nil {
		_, err = ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error {
			set.DirectDNS = splitLines(r.FormValue("direct_dns"))
			set.TunnelDNS = splitLines(r.FormValue("tunnel_dns"))
			if set.TunnelDNS == nil {
				set.TunnelDNS = []string{}
			}
			return nil
		})
	}
	ok, msg := done(r, err, "Saved: the core restarts, the tunnel drops for a couple of seconds")
	s.part(w, r, "settings", "dns", ok, msg)
}

// actDefaults puts every setting back to its default -- the second
// tunnel's presets aside: they are not on this page.
func (s *Server) actDefaults(w http.ResponseWriter, r *http.Request) {
	err := paths.EnsureDataDir()
	if err == nil {
		_, err = ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error {
			d := ctl.DefaultSettings()
			d.Awg2Presets = set.Awg2Presets
			*set = d
			return nil
		})
	}
	s.redirect(w, r, err, "Settings reset to defaults")
}

// actDNSTest checks resolvers over the path the core uses them on.
func (s *Server) actDNSTest(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path != "tunnel" {
		path = "direct"
	}
	servers := splitLines(r.FormValue(path + "_dns"))
	if len(servers) == 0 && path == "tunnel" {
		if c, err := awgconf.ParseFile(paths.SourceConf()); err == nil {
			servers = c.DNS()
		}
	}
	v := &view{Lang: lang(r), Page: "settings"}
	v.Data = testDNS(path, servers)
	render(w, v, "dnsres")
}

// restartService: a stopped service will be started by the user, and the
// config is built on start
func restartService() error {
	if !winsvc.Installed() {
		return nil
	}
	if st, err := winsvc.State(); err != nil || st != svc.Running {
		return nil
	}
	if err := winsvc.Stop(); err != nil {
		return fmt.Errorf("stopping the service: %w", err)
	}
	return winsvc.Start()
}
