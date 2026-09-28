package webui

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"

	"dpiswitch/internal/autostart"
	"dpiswitch/internal/awgconf"
	"dpiswitch/internal/ctl"
	"dpiswitch/internal/netprocs"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/supervisor"
	"dpiswitch/internal/tray"
	"dpiswitch/internal/version"
	"dpiswitch/internal/winsvc"
)

// The pages are rendered here, in Go: the browser gets finished HTML and a
// small script that sends forms in the background and refreshes the parts
// that change by themselves (see static/ui.js). The page used to build
// itself in JavaScript from a JSON API, and what a button did was spread
// between the two -- the settings form saved every field but one, and that
// one was wiped.

//go:embed tmpl/*.html static/*
var uiFS embed.FS

// pageNames: the pages of the menu, in its order; help sits apart below
// it, and the live connections below help
var pageNames = []string{"overview", "verdicts", "lists", "awg2", "settings", "logs", "help", "live"}

var pageTmpl = map[string]*template.Template{}

func init() {
	funcs := template.FuncMap{
		"lines": func(l []string) string { return strings.Join(l, "\n") },
		"join":  strings.Join,
		// tun: a tunnel's state for the "tunstate" template
		"tun": func(v *view, alive bool, note string) tunArg { return tunArg{v, v.St, alive, note} },
		"dur": func(v *view, opts []durOpt, cur int) durArg { return durArg{v, opts, cur} },
		// row: a verdict row with the page, for the templates that need both
		"row": func(v *view, r vrow) rowArg { return rowArg{v, r} },
		// dl: one of the domain lists for the "domainlist" template
		"el": func(v *view, kind, title, hint string, entries []string, online []netprocs.Proc) entryList {
			return entryList{v, kind, title, hint, entries, online}
		},
	}
	for _, p := range pageNames {
		t := template.New("").Funcs(funcs)
		pats := []string{"tmpl/layout.html", "tmpl/" + p + ".html"}
		if p == "help" {
			pats = append(pats, "tmpl/help_en.html", "tmpl/help_ru.html")
		}
		pageTmpl[p] = template.Must(t.ParseFS(uiFS, pats...))
	}
}

type tunArg struct {
	V     *view
	S     status
	Alive bool
	Note  string
}

type durArg struct {
	V    *view
	Opts []durOpt
	Cur  int
}

type rowArg struct {
	V *view
	R vrow
}

// view: what every template gets. Data holds the page's own values.
type view struct {
	Lang  string
	Page  string
	Path  string // the page's path with its query, for the language links
	St    status
	Flash *flash // a plain form's result, shown atop the page
	Msg   *flash // a background form's result, shown in the part it replaced
	Data  any
}

// dlg: the dialog a .conf is loaded through
type dlg struct{ Name, Title, Hint, Cancel, Load, Busy string }

func (v *view) Dlg(name string) dlg {
	d := dlg{Name: name, Cancel: v.T("Cancel"), Load: v.T("Load and apply"), Busy: v.T("Applying…"),
		Hint: v.T("Paste the .conf, drop the file on the field or pick it below. Keys stay on this machine. A running service restarts: the tunnel drops for a couple of seconds.")}
	d.Title = v.T("Main tunnel config (awg)")
	if name == "config2" {
		d.Title = v.T("Second tunnel config (awg2)")
	}
	return d
}

func (v *view) T(en string) string { return tr(v.Lang, en) }

// TH: a translated string that carries markup of its own (<code>, <b>).
// The strings are the program's, never the user's.
func (v *view) TH(en string) template.HTML { return template.HTML(tr(v.Lang, en)) }

func (v *view) Tf(en string, args ...any) string { return fmt.Sprintf(tr(v.Lang, en), args...) }

// Time: a verdict's time, short.
func (v *view) Time(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Local().Format("02.01 15:04")
}

// Left: how long until a verdict is checked again.
func (v *view) Left(t time.Time) string {
	m := int(time.Until(t).Minutes() + 0.5)
	switch {
	case m <= 0:
		return v.T("due now")
	case m < 60:
		return v.Tf("%d min", m)
	case m < 48*60:
		return v.Tf("%d h", (m+30)/60)
	}
	return v.Tf("%d d", (m+720)/1440)
}

type flash struct {
	OK   bool
	Text string
}

// lang: the page language -- the cookie the switch sets, else the browser's.
func lang(r *http.Request) string {
	if c, err := r.Cookie("lang"); err == nil && (c.Value == "ru" || c.Value == "en") {
		return c.Value
	}
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Accept-Language")), "ru") {
		return "ru"
	}
	return "en"
}

func (s *Server) newView(r *http.Request, page string) *view {
	v := &view{Lang: lang(r), Page: page, Path: r.URL.RequestURI(), St: s.status()}
	s.shownIn(v.Lang, false)
	s.mu.Lock()
	if f, ok := s.flashes[page]; ok {
		v.Flash = &f
		delete(s.flashes, page)
	}
	s.mu.Unlock()
	return v
}

// setFlash leaves a message for the next render of a page: the result of a
// form that reloads it.
func (s *Server) setFlash(page string, ok bool, text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flashes == nil {
		s.flashes = map[string]flash{}
	}
	s.flashes[page] = flash{ok, text}
}

// render executes one template of a page: "layout" for the whole page,
// a fragment's name for the part a form or a refresh replaces.
func render(w http.ResponseWriter, v *view, name string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := pageTmpl[v.Page].ExecuteTemplate(w, name, v); err != nil {
		log.Printf("ui: %s/%s: %v", v.Page, name, err)
		fmt.Fprintf(w, `<div class="msg bad">%s</div>`, template.HTMLEscapeString(err.Error()))
	}
}

func (s *Server) handlePage(w http.ResponseWriter, r *http.Request) {
	page := strings.Trim(r.URL.Path, "/")
	if page == "" {
		http.Redirect(w, r, "/overview", http.StatusFound)
		return
	}
	if _, ok := pageTmpl[page]; !ok {
		http.NotFound(w, r)
		return
	}
	v := s.newView(r, page)
	v.Data = s.pageData(r, page, v)
	render(w, v, "layout")
}

// pageData: the values a page is drawn from. The fragments a page refreshes
// get the same values, so a refresh draws what a reload would.
func (s *Server) pageData(r *http.Request, page string, v *view) any {
	switch page {
	case "overview":
		return overviewData(v)
	case "verdicts":
		return verdictsData(r)
	case "lists":
		return listsData()
	case "awg2":
		return awg2Data()
	case "settings":
		return settingsData()
	case "logs":
		return logsData(r)
	case "live":
		return liveWords(v)
	}
	return nil
}

// frag serves a fragment a page refreshes by itself: /frag/<page>/<name>
func (s *Server) handleFrag(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/frag/"), "/"), "/")
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	page, name := parts[0], parts[1]
	if _, ok := pageTmpl[page]; !ok {
		http.NotFound(w, r)
		return
	}
	// the page the fragment is on, not the fragment's own path: the language
	// links in a refreshed header must lead back to the page
	v := &view{Lang: lang(r), Page: page, Path: back(r), St: s.status()}
	v.Data = s.pageData(r, page, v)
	render(w, v, name)
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	sub, _ := fs.Sub(uiFS, "static")
	http.StripPrefix("/static/", http.FileServer(http.FS(sub))).ServeHTTP(w, r)
}

// handleIcon: the page's icon is the program's, the tray's "off" one
func (s *Server) handleIcon(w http.ResponseWriter, r *http.Request) {
	b, err := tray.IconFile("off.ico")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "max-age=86400")
	w.Write(b)
}

// the language switch: a cookie, then back to the page it was pressed on
func (s *Server) handleLang(w http.ResponseWriter, r *http.Request) {
	l := r.URL.Query().Get("to")
	if l != "ru" {
		l = "en"
	}
	http.SetCookie(w, &http.Cookie{Name: "lang", Value: l, Path: "/", MaxAge: 10 * 365 * 24 * 3600,
		SameSite: http.SameSiteStrictMode})
	s.shownIn(l, true)
	http.Redirect(w, r, localPath(r.URL.Query().Get("back")), http.StatusSeeOther)
}

// localPath: a path on this server to go back to; anything else goes home
func localPath(p string) string {
	u, err := url.Parse(p)
	if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(u.Path, "/") ||
		strings.HasPrefix(u.Path, "//") {
		return "/overview"
	}
	return u.RequestURI()
}

// back: the page a plain form was sent from, to return to after it
func back(r *http.Request) string {
	if ref, err := url.Parse(r.Referer()); err == nil && ref.Host == r.Host {
		return localPath(ref.RequestURI())
	}
	return "/overview"
}

// pageOf: the page name of a path, for the flash it gets
func pageOf(path string) string {
	p := strings.Trim(path, "/")
	if i := strings.IndexAny(p, "/?"); i >= 0 {
		p = p[:i]
	}
	return p
}

// status: what the header, the menu and the overview show. Gathered for
// every page and every refresh of the header; each part costs a
// millisecond or two, the tunnels' health a call to the core's API.
type status struct {
	Installed   bool           `json:"installed"`
	PathOK      bool           `json:"path_ok"`
	BinPath     string         `json:"bin_path"`
	ExePath     string         `json:"exe_path"`
	ServiceRun  bool           `json:"service_running"`
	ServiceText string         `json:"service_text"`
	Pending     bool           `json:"-"` // starting or stopping
	Autostart   bool           `json:"autostart"`
	HasConfig   bool           `json:"has_config"`
	DataDir     string         `json:"data_dir"`
	InstallDir  string         `json:"install_dir"`
	NetworkID   string         `json:"network_id"`
	Counts      map[string]int `json:"counts"`
	DirectCount int            `json:"direct_count"`
	Blocked     int            `json:"blocked_count"`
	Slower      int            `json:"-"`
	Unverified  int            `json:"-"`
	Families    int            `json:"-"`
	TunnelAlive bool           `json:"tunnel_alive"`
	TunnelNote  string         `json:"tunnel_note"`
	NetworkUp   bool           `json:"network_up"`
	Version     string         `json:"version"`
	Mode        string         `json:"-"` // see ctl.Settings.Mode
	Endpoint    string         `json:"-"`
	Awg2        bool           `json:"-"` // a second tunnel is attached
	Awg2Err     string         `json:"-"` // why the .conf loaded for it is not
	Awg2Alive   bool           `json:"-"`
	Awg2Note    string         `json:"-"`
	Endpoint2   string         `json:"-"`
	Presets     int            `json:"-"`
	Awg2Hosts   int            `json:"-"`
}

// apiAddr: the core's controller; a var so tests can point it away from
// the live core -- saving a list there would close real connections
var apiAddr = "127.0.0.1:9090"

func collectStatus() status {
	st := status{
		Installed:  winsvc.Installed(),
		ExePath:    paths.Exe(),
		BinPath:    winsvc.BinPath(),
		Autostart:  autostart.Enabled(),
		DataDir:    paths.DataDir(),
		InstallDir: winsvc.InstallDir(),
		Version:    version.Version,
	}
	st.PathOK = !st.Installed || winsvc.SameBuild()
	if st.Installed {
		if state, err := winsvc.State(); err == nil {
			st.ServiceRun = state == svc.Running
			st.Pending = state == svc.StartPending || state == svc.StopPending
			st.ServiceText = winsvc.StateText(state)
		}
	}
	// a config is loaded when the user's .conf is there: config.yaml, which
	// this used to look for, is built by the service -- one stopped when a
	// .conf was loaded, or not started yet, left the overview saying "No
	// config loaded yet" over the one just loaded
	first, err := awgconf.ParseFile(paths.SourceConf())
	if err == nil {
		st.HasConfig, st.Endpoint = true, first.Peer["Endpoint"]
	}
	// attached is what the service attaches: a .conf it leaves out is said so
	if c, err := awgconf.Second(first); c != nil {
		st.Awg2, st.Endpoint2 = true, c.Peer["Endpoint"]
	} else if err != nil {
		st.Awg2Err = err.Error()
	}
	// a running service and a working tunnel are different things: TUN may
	// be up with a dead peer, and then traffic goes nowhere
	if st.ServiceRun {
		secret := ctl.SecretFromConfig(paths.Config())
		st.TunnelAlive, st.TunnelNote = ctl.TunnelHealth(apiAddr, secret, "awg")
		if st.Awg2 {
			st.Awg2Alive, st.Awg2Note = ctl.TunnelHealth(apiAddr, secret, "awg2")
		}
	}
	st.NetworkUp = supervisor.NetworkUp()
	set := ctl.LoadSettings(paths.Settings())
	st.Mode = set.Mode()
	st.Presets = len(set.Awg2Presets)
	st.Awg2Hosts = len(readEntries(paths.Awg2List))

	snap := ctl.LoadCached(paths.State())
	st.NetworkID = snap.NetworkID
	st.Counts = snap.Counts
	st.DirectCount = len(snap.Direct)
	st.Blocked = snap.Blocked()
	st.Slower = snap.Counts["SLOWER"]
	st.Unverified = snap.Counts["INCONCLUSIVE"]
	st.Families = len(snap.Families)
	return st
}

// statusCache: the header refreshes every five seconds and a page load
// gathers the same; the tunnels' health is not worth asking twice a second.
var statusCache struct {
	sync.Mutex
	at time.Time
	st status
}

func (s *Server) status() status {
	if s.statusFn != nil {
		return s.statusFn()
	}
	statusCache.Lock()
	defer statusCache.Unlock()
	if time.Since(statusCache.at) > time.Second {
		statusCache.st, statusCache.at = collectStatus(), time.Now()
	}
	return statusCache.st
}

// fresh drops the cached status: after an action it must show its result.
func (s *Server) fresh() {
	statusCache.Lock()
	statusCache.at = time.Time{}
	statusCache.Unlock()
}

// guard refuses what did not come from this UI's own pages. The server
// listens on loopback only, but any web page the user opens can send a form
// to 127.0.0.1 -- and stop the tunnel or rewrite a list with it. A browser
// names the page a request comes from in Origin, and a name other than ours
// in Host means DNS rebinding.
func guard(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := strings.Cut(r.Host, ":")
		if host != "127.0.0.1" && host != "localhost" {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if o := r.Header.Get("Origin"); o != "" && o != "http://"+r.Host {
				http.Error(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
			if sf := r.Header.Get("Sec-Fetch-Site"); sf != "" && sf != "same-origin" && sf != "none" {
				http.Error(w, "cross-site request refused", http.StatusForbidden)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}
