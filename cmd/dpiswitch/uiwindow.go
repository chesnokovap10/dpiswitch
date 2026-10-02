package main

import (
	"log"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// The UI opened from the tray -- its icon, its "Settings…", a second start
// of the program -- is the one already open, brought forward, not one more
// tab: the browser made a new one for each, and a page left open was
// joined by a second, a third.
//
// A browser lets no one outside it pick a tab, but its windows are found by
// their titles. The UI opens in a window of its own -- an app window of the
// default browser, where it makes them (Chromium's --app) -- whose title is
// the page's: "DPI Switch" alone, found again whatever else is open. A
// window whose tab shown is the UI ("DPI Switch - Google Chrome") is found
// as well; a tab of the UI behind others is not.
func showUI(url string) {
	if h := uiWindow(); h != 0 {
		if r, _, _ := pIsIconic.Call(uintptr(h)); r != 0 {
			pShowWindow.Call(uintptr(h), swRestore)
		}
		if r, _, err := pSetForegroundWindow.Call(uintptr(h)); r == 0 {
			log.Printf("tray: the UI's window not brought forward: %v", err)
		}
		return
	}
	if exe := appBrowser(); exe != "" {
		pAllowSetForegroundWindow.Call(asfwAny)
		verb, _ := syscall.UTF16PtrFromString("open")
		file, _ := syscall.UTF16PtrFromString(exe)
		args, _ := syscall.UTF16PtrFromString("--app=" + url)
		if err := windows.ShellExecute(0, verb, file, args, nil, windows.SW_SHOWNORMAL); err == nil {
			return
		} else {
			log.Printf("tray: %s did not open the UI's window: %v", exe, err)
		}
	}
	browse(url)
}

const (
	// uiTitle: the pages' title (layout.html), and so an app window's
	uiTitle   = "DPI Switch"
	swRestore = 9
)

// a window whose tab shown is the UI: the page's title and the browser's
// name, nothing between -- "DPI Switch - Поиск в Google - Google Chrome" is
// another page
var uiTabTitles = []string{uiTitle + " - Google Chrome", uiTitle + " — Mozilla Firefox", uiTitle + " - Mozilla Firefox"}

// browser windows, by their class: a message box of this program is titled
// "DPI Switch" too
var browserClasses = map[string]bool{"Chrome_WidgetWin_1": true, "MozillaWindowClass": true}

var (
	pIsIconic            = user32.NewProc("IsIconic")
	pShowWindow          = user32.NewProc("ShowWindow")
	pSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	pGetWindowTextW      = user32.NewProc("GetWindowTextW")
)

// uiWindow: the window the UI is open in, an app window first; 0 for none
func uiWindow() windows.HWND {
	var app, tab windows.HWND
	cb := syscall.NewCallback(func(h windows.HWND, _ uintptr) uintptr {
		if !windows.IsWindowVisible(h) {
			return 1
		}
		var cls [64]uint16
		if n, _ := windows.GetClassName(h, &cls[0], int32(len(cls))); n == 0 || !browserClasses[windows.UTF16ToString(cls[:n])] {
			return 1
		}
		var buf [256]uint16
		n, _, _ := pGetWindowTextW.Call(uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		switch title := windows.UTF16ToString(buf[:n]); {
		case title == uiTitle:
			app = h
			return 0 // the one to show
		case tab == 0 && isUITab(title):
			tab = h
		}
		return 1
	})
	windows.EnumWindows(cb, nil)
	if app != 0 {
		return app
	}
	return tab
}

func isUITab(title string) bool {
	for _, t := range uiTabTitles {
		if title == t {
			return true
		}
	}
	return false
}

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
