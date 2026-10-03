package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Clicks on the tray icon while the UI's window is on its way open no other
// window, and the window comes up full screen. It opens a real window of the
// default browser on the desktop, and closes it: run with
// DPISWITCH_LIVE_UI=1, with no UI's window open.
func TestShowUILive(t *testing.T) {
	if os.Getenv("DPISWITCH_LIVE_UI") == "" {
		t.Skip("opens a browser window on the desktop: DPISWITCH_LIVE_UI=1")
	}
	if appBrowser() == "" {
		t.Skip("the default browser makes no app windows")
	}
	if n := len(uiWindows()); n != 0 {
		t.Skipf("%d UI windows open already", n)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<!doctype html><title>DPI Switch</title><p>DPI Switch: the tray's window test")
	}))
	defer srv.Close()

	start := time.Now()
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() { defer wg.Done(); showUI(srv.URL) }()
		time.Sleep(100 * time.Millisecond)
	}
	wg.Wait()
	t.Logf("the window came after %v", time.Since(start))
	time.Sleep(time.Second) // a window a second click opened would be up by now
	hs := uiWindows()
	defer func() {
		for _, h := range hs {
			pPostMessage.Call(uintptr(h), wmClose, 0, 0)
		}
	}()
	if len(hs) != 1 {
		t.Fatalf("%d windows after five clicks, want 1", len(hs))
	}
	if z, _, _ := pIsZoomed.Call(uintptr(hs[0])); z == 0 {
		t.Error("the window is not full screen")
	}
	// a click with the window open brings it forward, and opens nothing
	showUI(srv.URL)
	time.Sleep(500 * time.Millisecond)
	if n := len(uiWindows()); n != 1 {
		t.Errorf("%d windows after a click on an open one", n)
	}
}

var (
	pIsZoomed    = user32.NewProc("IsZoomed")
	pPostMessage = user32.NewProc("PostMessageW")
)

const wmClose = 0x0010

// uiWindows: every browser window titled as the UI's app window
func uiWindows() []windows.HWND {
	var out []windows.HWND
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
		if windows.UTF16ToString(buf[:n]) == uiTitle {
			out = append(out, h)
		}
		return 1
	})
	windows.EnumWindows(cb, nil)
	return out
}
