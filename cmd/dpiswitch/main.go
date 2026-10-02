// dpiswitch: tray, service and installer in one binary.
// The mode is chosen by an argument; without one -- the tray.
package main

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"dpiswitch/internal/autostart"
	"dpiswitch/internal/ctl"
	"dpiswitch/internal/logfile"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/session"
	"dpiswitch/internal/supervisor"
	"dpiswitch/internal/tray"
	"dpiswitch/internal/version"
	"dpiswitch/internal/webui"
	"dpiswitch/internal/winexec"
	"dpiswitch/internal/winsvc"
)

func main() {
	// a start by the service manager is detected automatically: a shortcut and
	// autostart call the same binary, so the modes cannot be confused
	if winsvc.IsWindowsService() {
		runService()
		return
	}

	cmd := ""
	if len(os.Args) > 1 {
		cmd = strings.ToLower(os.Args[1])
	}
	switch cmd {
	case "service":
		runService()
	case "install":
		report(T("Install service"), winsvc.Install(ownerArg()))
	case "uninstall":
		report(T("Uninstall service"), winsvc.Uninstall())
	case "reinstall":
		_ = winsvc.Uninstall()
		report(T("Reinstall service"), winsvc.Install(ownerArg()))
	case "remove":
		runRemove()
	case "", "tray":
		runTray()
	case "version", "-v", "--version":
		msgBox("DPI Switch", T("Version")+" "+version.Version, 0x40)
	default:
		report("dpiswitch", fmt.Errorf(T("unknown command %q; valid: tray, service, install, uninstall, reinstall, remove, version"), cmd))
	}
}

// logMax: the service and tray logs are rotated at start, the previous one
// kept in .1. Not while running: the service log's handle is also the crash
// output and stderr, which must stay valid for the life of the process --
// and at ~100 KB a day, the restarts every update and reboot brings are
// often enough.
const logMax = 4 << 20

func runService() {
	// the data directory is made the service's before anything is written
	// in it: an older version let every user write there, and a log opened
	// through a link planted in the meantime is SYSTEM writing wherever it
	// points (see paths.SecureDataDir).
	//
	// The owner is the one installing recorded, and no other: an
	// installation from before owners has none, and gets one by being
	// installed again. It used to be guessed from the permissions of the
	// files an older version left -- in a directory every user could write
	// in then.
	owner := paths.Owner()
	secErr := paths.SecureDataDir(owner)
	// again, a few times: an entry held open a moment ago may be free now
	for i := 0; secErr != nil && i < 4; i++ {
		time.Sleep(time.Second)
		secErr = paths.SecureDataDir(owner)
	}
	if fi, err := os.Lstat(paths.LogDir()); err != nil || !fi.IsDir() || fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		// no log directory of our own: nothing is written, the service does
		// not start -- running on would be running in an unlocked directory
		return
	}
	_ = logfile.RotateIfOver(paths.ServiceLog(), logMax)
	if f, err := os.OpenFile(paths.ServiceLog(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		log.SetOutput(f)
		// A panic goes to stderr, and a service has nobody reading it: the
		// service died twice with nothing in any log but Windows' "terminated
		// unexpectedly". The runtime writes the trace here instead.
		if err := debug.SetCrashOutput(f, debug.CrashOptions{}); err != nil {
			log.Printf("crash output not redirected: %v", err)
		}
		// and anything else written to stderr -- the race detector's reports
		// among them -- instead of into a handle nobody holds
		_ = windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(f.Fd()))
	}
	log.SetFlags(log.LstdFlags)
	if secErr != nil {
		// A directory not wholly locked is one a user may have planted a
		// link or a file in: the service ran on in it as SYSTEM, and read
		// and wrote through what it could not remove. It does not start.
		log.Printf("service not started: the data directory is not locked down: %v", secErr)
		return
	}
	if owner == "" {
		log.Println("no owner recorded: only administrators can change the settings -- install the service again from the tray")
	} else if err := winsvc.SecureService(owner); err != nil {
		log.Printf("service permissions not set: %v", err)
	}
	if err := winsvc.RunService(true); err != nil {
		log.Printf("service exited with an error: %v", err)
	}
}

// A second instance is not needed: two tray icons and two copies
// of the web server only confuse. But dying silently is wrong too --
// the user launched the shortcut expecting to see the UI.
// The port is stable within the session, so it is enough to open
// it in the browser and exit.
func alreadyRunning() bool {
	name, err := syscall.UTF16PtrFromString(`Local\dpiswitch-tray`)
	if err != nil {
		return false
	}
	h, err := windows.CreateMutex(nil, false, name)
	if err == windows.ERROR_ALREADY_EXISTS {
		// the handle opened here would keep the mutex alive after the other
		// copy exits: a tray waiting for it (see waitMutex) never got it
		windows.CloseHandle(h)
		return true
	}
	return false // this copy holds it now, until it exits
}

// ownerArg: the user the service is installed for -- "--owner <SID>", which
// the tray passes (the elevated copy may run as another account, an
// administrator's), else whoever runs the install.
func ownerArg() string {
	for i, a := range os.Args {
		if strings.EqualFold(a, "--owner") && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
	}
	if u, err := user.Current(); err == nil {
		return u.Uid
	}
	return ""
}

func runTray() {
	// logging is set up FIRST: the "already running" check used to come
	// earlier, and exiting through it left no trace in the log --
	// exactly the path that needed to be seen
	_ = os.MkdirAll(filepath.Dir(paths.TrayLog()), 0o700)
	// a second copy may hold the file open; then it is simply not renamed
	_ = logfile.RotateIfOver(paths.TrayLog(), logMax)
	if f, err := os.OpenFile(paths.TrayLog(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
		log.SetOutput(f)
		// the tray has no console either: as with the service, panics and
		// stderr -- race reports in a -race build -- go here or nowhere
		if err := debug.SetCrashOutput(f, debug.CrashOptions{}); err != nil {
			log.Printf("crash output not redirected: %v", err)
		}
		_ = windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(f.Fd()))
	}
	log.Printf("tray %s starting: pid %d, args %v", version.Version, os.Getpid(), os.Args[1:])

	// the mutex is a kernel object: it is released when the process dies,
	// so it cannot get "stuck" and needs no extra checks
	key, err := webui.LoadKey()
	if err != nil {
		log.Printf("UI key not kept, an open tab will not outlive a restart: %v", err)
	}
	if hasArg("--moved") {
		// started by the tray it replaces: that one is on its way out
		if !waitMutex() {
			log.Println("tray: the tray this one replaces did not exit")
			return
		}
	} else if alreadyRunning() {
		if updateOffer() {
			return
		}
		log.Println("tray: another copy is already running -- opening the UI and exiting")
		// the first copy may still be starting its UI
		addr := webui.Find(key)
		for i := 0; addr == "" && i < 10; i++ {
			time.Sleep(500 * time.Millisecond)
			addr = webui.Find(key)
		}
		if addr == "" {
			// no UI proved itself ours: the address without the key --
			// whatever holds the port must not be handed it
			log.Println("tray: the running copy's UI did not answer")
			addr = fmt.Sprintf("http://127.0.0.1:%d/", session.Port())
		}
		showUI(addr)
		return
	}

	// the window loop must live on the same thread as the window
	runtime.LockOSThread()

	srv := &webui.Server{Elevate: elevate, Key: key, LangFile: paths.UILang(),
		OnLang: func() {
			select {
			case langChanged <- struct{}{}:
			default:
			}
		}}
	uiLang = srv.Lang
	if err := srv.Start(); err != nil {
		report("dpiswitch", fmt.Errorf(T("the UI failed to start: %w"), err))
		return
	}

	t, err := tray.New("DPI Switch " + version.Version)
	if err != nil {
		report("dpiswitch", fmt.Errorf(T("the tray icon was not created: %w"), err))
		return
	}
	quitTray = t.Quit
	if hasArg("--moved") {
		settle(hasArg("--first"))
	}
	openUI := func() { showUI(srv.URL()) }
	t.OnOpen = openUI

	t.Menu = func() []tray.Item {
		installed := winsvc.Installed()
		running := false
		if installed {
			if st, err := winsvc.State(); err == nil {
				running = st == svc.Running
			}
		}
		items := []tray.Item{
			{ID: 1, Text: T("Settings…"), Do: openUI},
			{Sep: true},
		}
		if !installed {
			items = append(items, tray.Item{ID: 2, Text: T("Install service…"),
				Do: func() { _ = elevate("install") }})
		} else if running {
			items = append(items, tray.Item{ID: 3, Text: T("Stop tunnel"),
				Do: func() { _ = winsvc.Stop() }})
		} else {
			items = append(items, tray.Item{ID: 4, Text: T("Start tunnel"),
				Do: func() { _ = winsvc.Start() }})
		}
		items = append(items,
			tray.Item{ID: 5, Text: T("Everything via tunnel (reset verdicts)"), Grayed: !running,
				Do: func() { go panicTunnel() }},
			tray.Item{Sep: true},
			tray.Item{ID: 6, Text: T("Start with Windows"), Checked: autostart.Enabled(),
				Do: func() { _ = autostart.Set(!autostart.Enabled()) }},
			tray.Item{ID: 7, Text: T("Data folder"), Do: func() { browse(paths.DataDir()) }},
			tray.Item{Sep: true},
			tray.Item{ID: 9, Text: T("Exit"), Do: func() { t.Quit() }},
		)
		return items
	}

	go watchStatus(t)
	t.Loop()
	srv.Close()
}

// the icon reflects the state: otherwise it's unclear whether anything works
func watchStatus(t *tray.Tray) {
	for {
		state, tip := status()
		t.SetState(state, tip)
		// a language switched on a page, and a tunnel's state changed, are
		// shown at once; the rest every ten seconds
		select {
		case <-time.After(10 * time.Second):
		case <-langChanged:
		case <-webui.TunnelChanged():
			// a tunnel's state changed: the icon follows at once (see
			// webui/tunnelpulse.go)
		}
	}
}

// uiLang: the language the tray speaks -- the pages' once the UI runs
var uiLang = func() string { return webui.SavedLang(paths.UILang()) }

var langChanged = make(chan struct{}, 1)

// T: a tray string in the program's language
func T(en string) string { return webui.Tr(uiLang(), en) }

func status() (tray.State, string) {
	if !winsvc.Installed() {
		return tray.StateOff, T("DPI Switch — service not installed")
	}
	st, err := winsvc.State()
	if err != nil {
		return tray.StateError, T("DPI Switch — error: ") + err.Error()
	}
	if st != svc.Running {
		if !supervisor.NetworkUp() {
			return tray.StateOff, T("DPI Switch — off, no network")
		}
		return tray.StateOff, T("DPI Switch — tunnel off")
	}
	// Windows keeping the programs' traffic from the adapter: nothing works
	// through the service, whatever the tunnels do
	if ctl.LoadTunnelIPv6(paths.TunnelIPv6()).TrafficBlocked() {
		return tray.StateError, T("DPI Switch — Windows does not let traffic into the adapter: a third-party network filter takes it")
	}
	// no first tunnel's config: the core runs with no tunnel, and there is
	// none to go dead -- what no list names goes direct
	if _, err := os.Stat(paths.SourceConf()); err != nil {
		return tray.StateOff, T("DPI Switch — no first tunnel's config: what the lists do not name goes direct")
	}
	// a running service and a tunnel that passes traffic are different things:
	// with a dead peer TUN is up but there is no internet
	// as the UI keeps it, in step with the traffic; the core asked only when
	// the UI has not read it lately
	alive, note, ok := webui.Tunnel("awg")
	if !ok {
		alive, note = ctl.TunnelHealth("127.0.0.1:9090", ctl.SecretFromConfig(paths.Config()), "awg")
	}
	note = webui.TunnelNote(uiLang(), note)
	if !alive {
		if !supervisor.NetworkUp() {
			return tray.StateError, T("DPI Switch — no network, waiting")
		}
		return tray.StateError, T("DPI Switch — tunnel not responding: ") + note
	}
	snap := ctl.LoadCached(paths.State())
	return tray.StateOn, fmt.Sprintf(T("DPI Switch — tunnel up (%s)\ndirect: %d, blocked: %d"), note, len(snap.Direct), snap.Blocked())
}

// panic reset: clear verdicts, all traffic returns to the tunnel.
// for when the detector made a mistake and something stopped opening.
//
// The service does it: it holds the verdicts in memory, and emptying the
// files from here was undone by its next sync within a minute (see
// ctl.takeReset). The tray leaves a request and waits for it to be taken.
// It is the current network's, as the verdicts page's button is of the
// network it shows: the verdicts kept for another network stay.
func panicTunnel() {
	req := paths.ResetRequest()
	if err := os.WriteFile(req, []byte(time.Now().Format(time.RFC3339)+"\n"), 0o644); err != nil {
		msgBox("DPI Switch", T("The reset was not requested:")+"\n\n"+err.Error(), 0x10)
		return
	}
	for i := 0; i < 40; i++ {
		if _, err := os.Stat(req); os.IsNotExist(err) {
			if net := ctl.LoadCached(paths.State()).Current; net != "" {
				msgBox("DPI Switch", fmt.Sprintf(T("Verdicts of network %s reset, all traffic goes through the tunnel.\nThe detector will start picking domains again."), net), 0x40)
				return
			}
			msgBox("DPI Switch", T("Verdicts reset, all traffic goes through the tunnel.\nThe detector will start picking domains again."), 0x40)
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	msgBox("DPI Switch", T("The reset is requested, but the service has not taken it yet:\nit will as soon as its controller runs."), 0x30)
}

// installing and removing the service needs administrator rights: a normal
// process cannot do it, so we call ourselves with runas
func elevate(verb string) error {
	if verb == "remove" {
		return removeProgram()
	}
	if verb == "install" || verb == "reinstall" {
		// for this user (the administrator prompt may be answered with
		// another account), and the tray follows to the installed copy
		return installFor(verb)
	}
	exe, _ := syscall.UTF16PtrFromString(paths.Exe())
	args, _ := syscall.UTF16PtrFromString(verb)
	runas, _ := syscall.UTF16PtrFromString("runas")
	dir, _ := syscall.UTF16PtrFromString(paths.ExeDir())
	return windows.ShellExecute(0, runas, exe, args, dir, windows.SW_NORMAL)
}

var (
	user32                    = windows.NewLazySystemDLL("user32.dll")
	pAllowSetForegroundWindow = user32.NewProc("AllowSetForegroundWindow")
)

const asfwAny = ^uintptr(0) // ASFW_ANY: allow any process to take focus

// Windows does not let a process bring itself to the foreground -- otherwise
// windows would steal focus from the user. The only legal way is to
// hand that right in advance to whatever we are launching.
// If the browser is already open, it comes up with the right tab.
func browse(target string) {
	pAllowSetForegroundWindow.Call(asfwAny)

	verb, _ := syscall.UTF16PtrFromString("open")
	file, _ := syscall.UTF16PtrFromString(target)
	if err := windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL); err != nil {
		// fallback: ShellExecute is picky about some schemes
		_ = winexec.Command(winexec.System32("rundll32.exe"), "url.dll,FileProtocolHandler", target).Start()
	}
}

func report(title string, err error) {
	if err != nil {
		msgBox(title, T("Failed:")+"\n\n"+err.Error(), 0x10)
		os.Exit(1)
	}
	msgBox(title, T("Done."), 0x40)
}

func msgBox(title, text string, icon uint32) {
	t, _ := syscall.UTF16PtrFromString(title)
	b, _ := syscall.UTF16PtrFromString(text)
	windows.MessageBox(0, b, t, icon)
}
