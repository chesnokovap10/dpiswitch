package webui

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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
	"dpiswitch/internal/probe"
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
		return false, errText(lang(r), err)
	}
	return true, fmt.Sprintf(tr(lang(r), okText), args...)
}

// errText: an error as the page says it. The settings' own checks speak in
// fixed sentences: translated too. A DNS address refused names itself
// before its reason, which used to stay in English.
func errText(l string, err error) string {
	var re *probe.ResolverError
	switch {
	case !errors.As(err, &re):
		return tr(l, err.Error())
	case re.Raw == "":
		return tr(l, re.Why)
	}
	return fmt.Sprintf("%q: %s", re.Raw, tr(l, re.Why))
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
	_, err := ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error {
		return setMode(set, r.FormValue("value"))
	})
	ok, msg := done(r, err, "")
	s.part(w, r, pageOf(back(r)), "header", ok, msg)
}

// setMode: auto-switch as the header's buttons and the settings' select send
// it. "off", "1" and "0" come from a page served by 1.4.2 or before, where
// off kept everything in the tunnel -- tunnel only now, not observe only,
// which sends everything direct (see ctl.oldObserve).
func setMode(set *ctl.Settings, v string) error {
	switch v {
	case "1":
		v = ctl.ModeOn
	case "0", "off":
		v = ctl.ModeTunnel
	}
	if !set.SetMode(v) {
		return fmt.Errorf("unknown auto-switch mode %q", v)
	}
	return nil
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
	case "install", "uninstall", "reinstall", "remove":
		if s.Elevate == nil {
			err = errors.New("elevation unavailable")
		} else {
			err = s.Elevate(do)
		}
		if do == "remove" {
			s.redirect(w, r, err, "Confirm the administrator prompt: then the program removes itself and this page stops answering")
			return
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
	// rendered here only to refuse a .conf the service could not use: the
	// service renders config.yaml itself -- the user may not write it
	if _, err := conf.Render(); err != nil {
		return err
	}
	// the other way round from saveConf2: one key in both tunnels breaks both
	if c2, err := awgconf.ParseFile(paths.SourceConf2()); err == nil && awgconf.SameKey(conf, c2) {
		return errors.New("this is the same config as the second tunnel: replace or delete that one first")
	}
	if err := paths.UserReady(); err != nil {
		return err
	}
	// the WireGuard private key: written locked down from the start (mode
	// 0600 means nothing on Windows), and not at all if that cannot be done
	return paths.WriteSecret(paths.SourceConf(), []byte(text))
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

// actDelete1 deletes the first tunnel's config. The service runs without
// it: what no list names goes direct, and the detector checks nothing.
func (s *Server) actDelete1(w http.ResponseWriter, r *http.Request) {
	err := os.Remove(paths.SourceConf())
	switch {
	case os.IsNotExist(err):
		// deleted already -- in another window
		s.redirect(w, r, nil, "First tunnel config deleted")
		return
	case err != nil:
		s.redirect(w, r, err, "")
		return
	}
	s.redirect(w, r, restartService(), "First tunnel config deleted")
}

// actDetach2 deletes the second tunnel's config: the button says so. To
// switch awg2 off for a while there is the switch, which keeps the config.
func (s *Server) actDetach2(w http.ResponseWriter, r *http.Request) {
	err := os.Remove(paths.SourceConf2())
	switch {
	case os.IsNotExist(err):
		// deleted already -- in another window: the service has nothing
		// to drop, and is not restarted for it
		s.redirect(w, r, nil, "Second tunnel config deleted")
		return
	case err != nil:
		s.redirect(w, r, err, "")
		return
	}
	s.redirect(w, r, restartService(), "Second tunnel config deleted")
}

// --- verdicts ---

// actReset drops every verdict: all traffic returns to the tunnel. The
// service does it -- it holds the verdicts in memory (see ctl.takeReset);
// the request is a file it looks for every second.
//
// A stopped service keeps its verdicts and applies them when it starts: the
// request waits for it, as the tray's does. The page used to refuse it with
// "there is nothing to reset".
func (s *Server) actReset(w http.ResponseWriter, r *http.Request) {
	req := paths.ResetRequest()
	if err := paths.UserReady(); err != nil {
		s.redirect(w, r, err, "")
		return
	}
	if err := os.WriteFile(req, []byte(time.Now().Format(time.RFC3339)+"\n"), 0o644); err != nil {
		s.redirect(w, r, err, "")
		return
	}
	if !serviceRunning() {
		s.redirect(w, r, nil, "Reset requested: the service takes it when it starts, before it applies a verdict")
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

// actForget resets one verdict, from its row on the verdicts page: the
// name goes back to the tunnel, and the detector checks it anew when it is
// used. The service does it, as it does a reset (see ctl.takeForget): the
// request is a file of its own, and the page is answered once it is taken
// -- then the connections the name has open are closed, or they would go
// on as they went.
func (s *Server) actForget(w http.ResponseWriter, r *http.Request) {
	l := lang(r)
	key := strings.ToLower(strings.TrimSpace(r.FormValue("key")))
	entry, ok := forgetEntry(key)
	if !ok {
		http.Error(w, "not a verdict", http.StatusBadRequest)
		return
	}
	if err := paths.UserReady(); err != nil {
		writeJSON(w, liveAnswer{false, tr(l, err.Error())})
		return
	}
	// whole or not at all: the service looks every second, and a file it
	// met between being made and being written was taken empty -- the page
	// said the verdict was reset, and nothing was
	req := paths.ForgetRequest()
	if err := paths.ReplaceFile(req, []byte(key+"\n")); err != nil {
		writeJSON(w, liveAnswer{false, err.Error()})
		return
	}
	if !serviceRunning() {
		writeJSON(w, liveAnswer{true, tr(l, "Reset requested: the service takes it when it starts, before it applies a verdict")})
		return
	}
	for deadline := time.Now().Add(forgetWait); ; {
		if _, err := os.Stat(req); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			writeJSON(w, liveAnswer{true, tr(l, "Reset requested: the service takes it as soon as its controller runs")})
			return
		}
		time.Sleep(forgetWait / 40)
	}
	msg := fmt.Sprintf(tr(l, "Verdict reset: %s goes through the tunnel until the detector checks it again"), entry)
	n, err := ctl.CloseConns(apiAddr, ctl.SecretFromConfig(paths.Config()), entryMatch([]string{entry}))
	if n > 0 {
		msg += fmt.Sprintf(tr(l, "; open connections moved: %d"), n)
	}
	if err != nil {
		log.Printf("ui: open connections of a verdict reset not closed: %v", err)
		msg += "; " + tr(l, "open connections not closed:") + " " + err.Error()
	}
	writeJSON(w, liveAnswer{true, msg})
}

// forgetEntry: a verdict's key as a list's entry, for the connections it
// routed -- "@address" the address, "+.name" and a name as they are. A key
// no verdict can have is refused: the request is the service's to read.
func forgetEntry(key string) (string, bool) {
	addr := strings.HasPrefix(key, "@")
	kind, v, err := ctl.ParseEntry(strings.TrimPrefix(key, "@"))
	switch {
	case err != nil, kind == ctl.EntryApp, addr != (kind == ctl.EntryIP), len(key) > 260:
		return "", false
	case strings.HasPrefix(key, "+.") && !strings.HasPrefix(v, "+."):
		return "", false
	}
	return v, true
}

// forgetWait: how long a reset of one verdict waits for the service to
// take it -- it looks every second; a var for tests
var forgetWait = 5 * time.Second

// --- routing lists ---

// closeMoved closes the open connections a list change moves to another
// route: the core routes a connection once, when it opens, and a browser
// holds its connections for minutes. Not an error if the core is not up --
// then there is nothing open (see ctl.CloseConns). Any other failure is
// reported: the error used to be dropped, and the UI said "Saved" while the
// connections already open kept their old route.
//
// The service copies the user's list to the file the core reads (see
// ctl.SyncUserFiles): taken tells when it has. The provider is reloaded
// then, and the connections closed: see ctl.ReloadProviders.
func closeMoved(providers []string, match func(ctl.Conn) bool, taken func() bool) (int, error) {
	if !serviceRunning() {
		return 0, nil // no core: nothing is open through it
	}
	for deadline := time.Now().Add(syncWait); !taken(); {
		if time.Now().After(deadline) {
			return 0, errors.New("the service has not taken the change yet")
		}
		time.Sleep(syncWait / 50)
	}
	secret := ctl.SecretFromConfig(paths.Config())
	if err := ctl.ReloadProviders(apiAddr, secret, providers...); err != nil {
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
func providerOf(name string) string {
	return strings.TrimSuffix(filepath.Base(name), ".txt")
}

// syncWait: how long a save waits for the service to take it -- it looks
// every second; a var for tests
var syncWait = 5 * time.Second

// serviceRunning: whether the service -- and with it the core -- runs; a var
// for tests, which must not wait on the machine's real service
var serviceRunning = func() bool {
	st, err := winsvc.State()
	return err == nil && st == svc.Running
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

// --- second tunnel ---

// actPreset turns one preset on or off at once: the settings say which are
// on, the service writes the presets' file within a second (the core
// watches it), and the connections the preset moves are closed.
func (s *Server) actPreset(w http.ResponseWriter, r *http.Request) {
	id, on := r.FormValue("field"), r.FormValue("value") == "1"
	p, ok := findPreset(presets.Load(), id)
	if !ok {
		// deleted in another window meanwhile
		s.part(w, r, "awg2", "presets", false, tr(lang(r), errPresetGone.Error()))
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
	err := paths.UserReady()
	if err == nil {
		_, err = ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error {
			set.Awg2Presets = toggle(set.Awg2Presets)
			return nil
		})
	}
	n := 0
	var cerr error
	if err == nil {
		n, cerr = closeMoved([]string{ctl.PresetsProvider}, rulesMatch(ctl.PresetRules(p)),
			func() bool { return ctl.PresetWritten(p, on) })
	}
	ok, msg := saved(r, err, n, cerr)
	s.part(w, r, "awg2", "presets", ok, msg)
}

// actAwg2 switches the second tunnel on or off in the auto-switch mode
// chosen; each mode keeps its own (see ctl.Settings.Awg2Active). Switched
// off, its presets and list route nothing. What the switch moves is closed,
// as a preset's switch does.
func (s *Server) actAwg2(w http.ResponseWriter, r *http.Request) {
	on := r.FormValue("value") == "1"
	err := paths.UserReady()
	if err == nil {
		_, err = ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error {
			set.SetAwg2(on)
			return nil
		})
	}
	n := 0
	var cerr error
	if err == nil {
		providers := append([]string{ctl.PresetsProvider}, ctl.ListProviders(paths.Awg2List)...)
		n, cerr = closeMoved(providers, ctl.Awg2Moved(), ctl.Awg2Synced)
	}
	ok, msg := saved(r, err, n, cerr)
	s.part(w, r, "awg2", "awg2state", ok, msg)
}

// rulesMatch: the connections a preset's core rules take, or took
func rulesMatch(rules []string) func(ctl.Conn) bool {
	var suffixes, apps []string
	var nets []*netPrefix
	for _, rl := range rules {
		f := strings.Split(rl, ",")
		if len(f) < 2 {
			continue
		}
		if line := ctl.PresetNameLine(rl); line != "" {
			// a name as the lists write it: matched as a list's line
			suffixes = append(suffixes, line)
			continue
		}
		switch f[0] {
		case "IP-CIDR", "IP-CIDR6":
			if n := parsePrefix(f[1]); n != nil {
				nets = append(nets, n)
			}
		case "PROCESS-NAME", "PROCESS-PATH":
			apps = append(apps, f[1])
		}
	}
	dm := domainMatch(suffixes)
	return func(c ctl.Conn) bool {
		if dm(c) {
			return true
		}
		for _, a := range apps {
			if strings.EqualFold(a, c.Process) || strings.EqualFold(a, c.ProcessPath) {
				return true
			}
		}
		// the address rules carry no-resolve: they route a connection made
		// by address, never a named one whose address falls in them (see
		// entryMatch)
		if c.Host == "" {
			for _, n := range nets {
				if n.contains(c.IP) {
					return true
				}
			}
		}
		return false
	}
}

// saved: the result of a list saved, with the connections it moved when
// there were any. A list written whose open connections could not be closed
// is not a plain "Saved": those connections keep their old route.
func saved(r *http.Request, err error, moved int, closeErr error) (bool, string) {
	if err == nil && closeErr != nil {
		return false, tr(lang(r), "Saved, but the open connections were not moved: they keep their old route until they reconnect")
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
	note, restart := "Saved", false
	err := paths.UserReady()
	if err == nil {
		_, err = ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error {
			var err error
			was := *set
			switch field {
			case "auto_switch":
				err = setMode(set, val)
			case "families":
				set.Families = val == "1"
			case "ipv6":
				set.IPv6 = val == "1"
				restart = !set.SameCore(was)
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
	if field == "ipv6" {
		note = s.coreNote(restart)
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

// actDNS saves both boxes. A refused save keeps what was typed: the boxes
// used to come back with the saved servers, and a typo in one line lost
// every line written.
func (s *Server) actDNS(w http.ResponseWriter, r *http.Request) {
	direct, tunnel, tunnel2 := splitLines(r.FormValue("direct_dns")), splitLines(r.FormValue("tunnel_dns")), splitLines(r.FormValue("tunnel_dns2"))
	if tunnel == nil {
		tunnel = []string{}
	}
	if tunnel2 == nil {
		tunnel2 = []string{}
	}
	restart := false
	err := paths.UserReady()
	if err == nil {
		_, err = ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error {
			was := *set
			set.DirectDNS, set.TunnelDNS, set.TunnelDNS2 = direct, tunnel, tunnel2
			restart = !set.SameCore(was)
			return nil
		})
	}
	ok, msg := done(r, err, s.coreNote(restart))
	s.fresh()
	v := &view{Lang: lang(r), Page: "settings", Path: back(r), St: s.status(), Msg: &flash{ok, msg}}
	d := settingsData()
	if err != nil {
		d.S.DirectDNS, d.S.TunnelDNS, d.S.TunnelDNS2 = direct, tunnel, tunnel2
	}
	v.Data = d
	render(w, v, "dns")
}

// coreNote: the message for a save; one that changed what the core is
// built from restarts a running core. It used to be said on every DNS
// save -- one that changed nothing, one with the service stopped.
func (s *Server) coreNote(changed bool) string {
	if changed && s.status().ServiceRun {
		return "Saved: the core restarts, the tunnel drops for a couple of seconds"
	}
	return "Saved"
}

// actDefaults puts every setting back to its default -- the second
// tunnel's presets aside: they are not on this page.
func (s *Server) actDefaults(w http.ResponseWriter, r *http.Request) {
	restart := false
	err := paths.UserReady()
	if err == nil {
		_, err = ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error {
			d := ctl.DefaultSettings()
			d.Awg2Presets = set.Awg2Presets
			restart = !d.SameCore(*set)
			*set = d
			return nil
		})
	}
	note := "Settings reset to defaults"
	if restart && s.status().ServiceRun {
		note = "Settings reset to defaults: the core restarts, the tunnel drops for a couple of seconds"
	}
	s.redirect(w, r, err, note)
}

// actDNSTest checks resolvers over the path the core uses them on.
func (s *Server) actDNSTest(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	field := "direct_dns"
	switch path {
	case "tunnel":
		field = "tunnel_dns"
	case "tunnel2":
		field = "tunnel_dns2"
	default:
		path = "direct"
	}
	servers := splitLines(r.FormValue(field))
	fromConf := false
	// an empty box is the tunnel's .conf: those are tested
	first, _ := awgconf.ParseFile(paths.SourceConf())
	var tun *awgconf.Conf
	switch path {
	case "tunnel":
		tun = first
	case "tunnel2":
		tun, _ = awgconf.Second(first)
	}
	if len(servers) == 0 && tun != nil {
		servers, fromConf = tun.DNS(), true
	}
	t := dnsTest{Results: testDNS(path, servers), Field: field}
	if tun != nil {
		if host, _, err := net.SplitHostPort(tun.Peer["Endpoint"]); err == nil {
			caughtBy(host, t.Results)
		}
	}
	// a fixed address goes into the box in place of the one written; the
	// .conf's own servers are not in the box
	lines, fixed := make([]string, len(servers)), false
	for i, res := range t.Results {
		lines[i] = servers[i]
		if res.Fixed != "" {
			lines[i], fixed = res.Fixed, true
		}
	}
	if fixed && !fromConf {
		t.Fill = strings.Join(lines, "\n")
	}
	v := &view{Lang: lang(r), Page: "settings"}
	v.Data = t
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
