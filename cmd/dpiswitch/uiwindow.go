package main

import (
	"log"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
)

// The UI opened from the tray -- its icon, its "Settings…", a second start
// of the program -- is the one already open, brought forward, not one more
// tab: the browser made a new one for each, and a page left open was
// joined by a second, a third.
//
// A browser lets no one outside it pick a tab, but its windows are found by
// their titles. The UI opens in a window of its own -- an app window of the
// default browser, where it makes them (Chromium's --app) -- whose title is
// the page's: "DPI Switch" alone. The settings choose a tab of the browser
// instead (ctl.UITab), found by its window's title while it is the tab shown
// ("DPI Switch - Google Chrome"). Each is looked for alone: a tab of the UI
// open somewhere did not let the window chosen come.
func showUI(url string) {
	// one opening at a time: the window takes a second or more to come, and
	// each click meanwhile found none and opened one more -- five clicks,
	// five windows. A click now is the window's on its way.
	if !opening.TryLock() {
		return
	}
	defer opening.Unlock()
	exe := appBrowser()
	// another browser makes no window of its own: a tab there
	tab := exe == "" || ctl.LoadSettings(paths.Settings()).UIOpen == ctl.UITab
	if h := uiWindow(tab); h != 0 {
		if r, _, _ := pIsIconic.Call(uintptr(h)); r != 0 {
			pShowWindow.Call(uintptr(h), swRestore)
		}
		if r, _, err := pSetForegroundWindow.Call(uintptr(h)); r == 0 {
			log.Printf("tray: the UI's window not brought forward: %v", err)
		}
		return
	}
	if tab {
		browse(url)
	} else {
		pAllowSetForegroundWindow.Call(asfwAny)
		verb, _ := syscall.UTF16PtrFromString("open")
		file, _ := syscall.UTF16PtrFromString(exe)
		args, _ := syscall.UTF16PtrFromString("--app=" + url)
		if err := windows.ShellExecute(0, verb, file, args, nil, windows.SW_SHOWNORMAL); err != nil {
			log.Printf("tray: %s did not open the UI's window: %v", exe, err)
			browse(url)
			return
		}
	}
	// a tab is there within a second or two; one whose window is not found
	// by its title -- a browser that writes it another way -- must not hold
	// the next click off for long
	wait := 10 * time.Second
	if tab {
		wait = 3 * time.Second
	}
	for end := time.Now().Add(wait); uiWindow(tab) == 0 && time.Now().Before(end); {
		time.Sleep(50 * time.Millisecond)
	}
}

var opening sync.Mutex

const (
	// uiTitle: the pages' title (layout.html), and so an app window's
	uiTitle   = "DPI Switch"
	swRestore = 9
)

// browser windows, by their class: a message box of this program is titled
// "DPI Switch" too
var browserClasses = map[string]bool{"Chrome_WidgetWin_1": true, "MozillaWindowClass": true}

var (
	pIsIconic            = user32.NewProc("IsIconic")
	pShowWindow          = user32.NewProc("ShowWindow")
	pSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	pGetWindowTextW      = user32.NewProc("GetWindowTextW")
)

// uiWindow: the UI's app window, or with tab the window whose tab shown is
// the UI; 0 for none
func uiWindow(tab bool) windows.HWND {
	enum.Lock()
	defer enum.Unlock()
	enum.tab, enum.found = tab, 0
	windows.EnumWindows(enumCallback(), nil)
	return enum.found
}

// enum: what one look through the windows asks and finds. The callback is
// made once: Go keeps every callback it makes for the life of the process,
// 2,000 of them at most, and one made at every look -- twenty a second while
// a window is waited for -- ended the tray with "too many callback functions"
// after some dozens of openings.
var enum struct {
	sync.Mutex
	tab   bool
	found windows.HWND
}

var enumCallback = sync.OnceValue(func() uintptr {
	return syscall.NewCallback(func(h windows.HWND, _ uintptr) uintptr {
		if isUIWindow(h, enum.tab) {
			enum.found = h
			return 0
		}
		return 1
	})
})

func isUIWindow(h windows.HWND, tab bool) bool {
	if !windows.IsWindowVisible(h) {
		return false
	}
	var cls [64]uint16
	if n, _ := windows.GetClassName(h, &cls[0], int32(len(cls))); n == 0 || !browserClasses[windows.UTF16ToString(cls[:n])] {
		return false
	}
	var buf [256]uint16
	n, _, _ := pGetWindowTextW.Call(uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	title := windows.UTF16ToString(buf[:n])
	if tab {
		return isUITabTitle(title)
	}
	return title == uiTitle
}

// isUITabTitle: a browser window's title while the tab shown is the UI --
// the page's title, a dash, the browser's own name and nothing more: "DPI
// Switch - Google Chrome", "DPI Switch — Mozilla Firefox", "DPI Switch -
// Brave", "DPI Switch — Яндекс Браузер", "DPI Switch - Личный: Microsoft
// Edge". A dash more is another page: "DPI Switch - Поиск в Google - Google
// Chrome". Chrome's and Firefox's titles alone were known by heart: with
// another browser the tab was never found, and every click opened one more.
func isUITabTitle(title string) bool {
	for _, sep := range tabSeps {
		if rest, ok := strings.CutPrefix(title, uiTitle+sep); ok {
			return rest != "" && !slices.ContainsFunc(tabSeps, func(s string) bool { return strings.Contains(rest, s) })
		}
	}
	return false
}

// tabSeps: what a browser puts between the page's title and its own name
var tabSeps = []string{" - ", " — ", " – "}

// chromium: the default browsers that open an app window (--app), by their
// file's name; Yandex's is "browser.exe", told by its folder
var chromium = map[string]bool{"chrome.exe": true, "msedge.exe": true, "brave.exe": true,
	"vivaldi.exe": true, "chromium.exe": true}

// appBrowser: the default browser's program, when it opens app windows; ""
// for another or none known
func appBrowser() string {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	prog, _, err := k.GetStringValue("ProgId")
	k.Close()
	if err != nil || prog == "" {
		return ""
	}
	c, err := registry.OpenKey(registry.CLASSES_ROOT, prog+`\shell\open\command`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	cmd, _, err := c.GetStringValue("")
	c.Close()
	if err != nil {
		return ""
	}
	exe := commandExe(cmd)
	name := strings.ToLower(filepath.Base(exe))
	if chromium[name] || name == "browser.exe" && strings.Contains(strings.ToLower(exe), `\yandex\`) {
		return exe
	}
	return ""
}

// commandExe: the program of a command line as the registry keeps it --
// quoted, or up to the first space
func commandExe(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if rest, ok := strings.CutPrefix(cmd, `"`); ok {
		exe, _, _ := strings.Cut(rest, `"`)
		return exe
	}
	exe, _, _ := strings.Cut(cmd, " ")
	return exe
}
