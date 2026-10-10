package main

import "testing"

// The default browser's program, as the registry writes its command.
func TestCommandExe(t *testing.T) {
	for cmd, want := range map[string]string{
		`"C:\Program Files\Google\Chrome\Application\chrome.exe" --single-argument %1`: `C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`  "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -- "%1"`:     `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Browsers\chrome.exe %1`: `C:\Browsers\chrome.exe`,
		`C:\Browsers\chrome.exe`:    `C:\Browsers\chrome.exe`,
	} {
		if got := commandExe(cmd); got != want {
			t.Errorf("%s: %q, want %q", cmd, got, want)
		}
	}
}

// A look through the windows makes no callback of its own: Go keeps every one
// it makes, 2,000 at most, and the tray ended with "too many callback
// functions" once its looks had made that many -- some dozens of openings.
func TestUIWindowLooksManyTimes(t *testing.T) {
	for range 2500 {
		uiWindow(false)
	}
}
