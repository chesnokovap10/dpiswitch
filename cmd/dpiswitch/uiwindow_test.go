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

// A window whose tab shown is the UI is told by its whole title: another
// page that only starts with the name is not the UI.
func TestUITabTitle(t *testing.T) {
	for title, want := range map[string]bool{
		"DPI Switch - Google Chrome":                  true,
		"DPI Switch — Mozilla Firefox":                true,
		"DPI Switch - Поиск в Google - Google Chrome": false,
		"DPI Switch":                false, // an app window: told apart before
		"Live - DPI Switch":         false,
		"dpiswitch - Google Chrome": false,
	} {
		if got := isUITab(title); got != want {
			t.Errorf("%q: %v", title, got)
		}
	}
}
