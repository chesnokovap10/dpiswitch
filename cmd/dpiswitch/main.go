// dpiswitch: tray, service and installer in one binary.
// The mode is chosen by an argument; without one -- the tray.
package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"
	"unsafe"

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
		report("Install service", winsvc.Install())
	case "uninstall":
		report("Uninstall service", winsvc.Uninstall())
	case "reinstall":
		_ = winsvc.Uninstall()
		report("Reinstall service", winsvc.Install())
	case "", "tray":
		runTray()
	case "version", "-v", "--version":
		msgBox("DPI Switch", "Version "+version.Version, 0x40)
	default:
		report("dpiswitch", fmt.Errorf("unknown command %q; valid: tray, service, install, uninstall, reinstall, version", cmd))
	}
}

// logMax: the service and tray logs are rotated at start, the previous one
// kept in .1. Not while running: the service log's handle is also the crash
// output and stderr, which must stay valid for the life of the process --
// and at ~100 KB a day, the restarts every update and reboot brings are
// often enough.
const logMax = 4 << 20

func runService() {
	_ = paths.EnsureDataDir()
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
	_, err = windows.CreateMutex(nil, false, name)
	return err == windows.ERROR_ALREADY_EXISTS
}

func runTray() {
	// logging is set up FIRST: the "already running" check used to come
	// earlier, and exiting through it left no trace in the log --
	// exactly the path that needed to be seen
	_ = paths.EnsureDataDir()
	// a second copy may hold the file open; then it is simply not renamed
	_ = logfile.RotateIfOver(paths.ControllerLog(), logMax)
	if f, err := os.OpenFile(paths.ControllerLog(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
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
	if alreadyRunning() {
		log.Println("tray: another copy is already running -- opening the UI and exiting")
		browse(fmt.Sprintf("http://127.0.0.1:%d/", session.Port()))
		return
	}

	// the window loop must live on the same thread as the window
	runtime.LockOSThread()

	srv := &webui.Server{
		Elevate: elevate,
		Reload:  func() error { return nil },
	}
	if err := srv.Start(); err != nil {
		report("dpiswitch", fmt.Errorf("the UI failed to start: %w", err))
		return
	}

	t, err := tray.New("DPI Switch " + version.Version)
	if err != nil {
		report("dpiswitch", fmt.Errorf("the tray icon was not created: %w", err))
		return
	}
	openUI := func() { browse(srv.Addr()) }
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
			{ID: 1, Text: "Settings…", Do: openUI},
			{Sep: true},
		}
		if !installed {
			items = append(items, tray.Item{ID: 2, Text: "Install service…",
				Do: func() { _ = elevate("install") }})
		} else if running {
			items = append(items, tray.Item{ID: 3, Text: "Stop tunnel",
				Do: func() { _ = winsvc.Stop() }})
		} else {
			items = append(items, tray.Item{ID: 4, Text: "Start tunnel",
				Do: func() { _ = winsvc.Start() }})
		}
		items = append(items,
			tray.Item{ID: 5, Text: "Everything via tunnel (reset verdicts)", Grayed: !running,
				Do: panicTunnel},
			tray.Item{Sep: true},
			tray.Item{ID: 6, Text: "Start with Windows", Checked: autostart.Enabled(),
				Do: func() { _ = autostart.Set(!autostart.Enabled()) }},
			tray.Item{ID: 7, Text: "Data folder", Do: func() { browse(paths.DataDir()) }},
			tray.Item{Sep: true},
			tray.Item{ID: 9, Text: "Exit", Do: func() { t.Quit() }},
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
		// the tunnel check calls the core API, so it runs less often
		// than a plain label would refresh
		sleep(10)
	}
}

func status() (tray.State, string) {
	if !winsvc.Installed() {
		return tray.StateOff, "DPI Switch — service not installed"
	}
	st, err := winsvc.State()
	if err != nil {
		return tray.StateError, "DPI Switch — error: " + err.Error()
	}
	if st != svc.Running {
		if !supervisor.NetworkUp() {
			return tray.StateOff, "DPI Switch — off, no network"
		}
		return tray.StateOff, "DPI Switch — tunnel off"
	}
	// a running service and a tunnel that passes traffic are different things:
	// with a dead peer TUN is up but there is no internet
	alive, note := ctl.TunnelHealth("127.0.0.1:9090",
		ctl.SecretFromConfig(paths.Config()), "awg")
	if !alive {
		if !supervisor.NetworkUp() {
			return tray.StateError, "DPI Switch — no network, waiting"
		}
		return tray.StateError, "DPI Switch — tunnel not responding: " + note
	}
	snap := snapshot()
	return tray.StateOn, fmt.Sprintf("DPI Switch — tunnel up (%s)\n"+
		"direct: %d, blocked: %d", note, len(snap.Direct), snap.Blocked())
}

// stateCache: the verdict summary the icon's tooltip shows. The state file
// is a few hundred KB and was parsed every ten seconds; it is read again
// when it changes, or once a minute -- the direct count depends on the clock
// too, as verdicts expire. Only watchStatus uses it.
var stateCache struct {
	mod  time.Time
	size int64
	at   time.Time
	snap ctl.Snapshot
}

func snapshot() ctl.Snapshot {
	fi, err := os.Stat(paths.State())
	c := &stateCache
	if err == nil && fi.ModTime().Equal(c.mod) && fi.Size() == c.size && time.Since(c.at) < time.Minute {
		return c.snap
	}
	c.snap, c.at = ctl.Load(paths.State()), time.Now()
	if err == nil {
		c.mod, c.size = fi.ModTime(), fi.Size()
	}
	return c.snap
}

// panic reset: clear verdicts, all traffic returns to the tunnel.
// for when the detector made a mistake and something stopped opening.
func panicTunnel() {
	_ = os.WriteFile(paths.Verified(),
		[]byte("# reset manually from the tray\n"), 0o644)
	_ = os.Remove(paths.State())
	msgBox("DPI Switch", "Verdicts reset, all traffic goes through the tunnel.\n"+
		"The detector will start picking domains again.", 0x40)
}

// installing and removing the service needs administrator rights: a normal
// process cannot do it, so we call ourselves with runas
func elevate(verb string) error {
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
		_ = winexec.Command("rundll32", "url.dll,FileProtocolHandler", target).Start()
	}
}

func report(title string, err error) {
	if err != nil {
		msgBox(title, "Failed:\n\n"+err.Error(), 0x10)
		os.Exit(1)
	}
	msgBox(title, "Done.", 0x40)
}

func msgBox(title, text string, icon uint32) {
	t, _ := syscall.UTF16PtrFromString(title)
	b, _ := syscall.UTF16PtrFromString(text)
	windows.MessageBox(0, b, t, icon)
}

func sleep(sec int) {
	windows.SleepEx(uint32(sec*1000), false)
}

var _ = unsafe.Pointer(nil)
