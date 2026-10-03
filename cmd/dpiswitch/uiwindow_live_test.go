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

	"golang.org/x/sys/windows"
)

// Clicks on the tray icon while the UI's window is on its way open no other
// window. It opens a real window of the default browser on the desktop, and
// closes it: run with DPISWITCH_LIVE_UI=1, with no UI's window open.
func TestShowUILive(t *testing.T) {
	if os.Getenv("DPISWITCH_LIVE_UI") == "" {
		t.Skip("opens a browser window on the desktop: DPISWITCH_LIVE_UI=1")
	}
	if appBrowser() == "" || uiWindow() != 0 {
		t.Skip("no browser making app windows, or a UI's window open already")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<!doctype html><title>DPI Switch</title>the tray's window test")
	}))
	defer srv.Close()
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() { defer wg.Done(); showUI(srv.URL) }()
		time.Sleep(100 * time.Millisecond)
	}
	wg.Wait()
	time.Sleep(time.Second) // a window a second click opened would be up by now
	var hs []windows.HWND
	windows.EnumWindows(syscall.NewCallback(func(h windows.HWND, _ uintptr) uintptr {
		if isUIWindow(h) {
			hs = append(hs, h)
		}
		return 1
	}), nil)
	for _, h := range hs {
		user32.NewProc("PostMessageW").Call(uintptr(h), 0x0010, 0, 0) // WM_CLOSE
	}
	if len(hs) != 1 {
		t.Fatalf("%d windows after five clicks, want 1", len(hs))
	}
}
