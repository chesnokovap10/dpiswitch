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

// The window whose tab shown is the UI, by its title: the page's own, a dash
// and the browser's name -- whichever browser. A dash more is another page.
func TestIsUITabTitle(t *testing.T) {
	for title, want := range map[string]bool{
		"DPI Switch - Google Chrome":          true,
		"DPI Switch — Mozilla Firefox":        true,
		"DPI Switch - Brave":                  true,
		"DPI Switch — Яндекс Браузер":         true,
		"DPI Switch - Личный: Microsoft Edge": true,
		// Edge with other tabs open says how many, in its own language
		"DPI Switch и ещё 3 страницы — Личный: Microsoft\u200b Edge": true,
		"DPI Switch and 2 more pages - Personal: Microsoft Edge":     true,
		"DPI Switch and 1 more page - Microsoft Edge":                true,
		// a count is Edge's alone, and comes before the first dash
		"DPI Switch and 2 more pages - Google Chrome":                     false,
		"DPI Switch - Bing и ещё 3 страницы — Личный: Microsoft Edge":     false,
		"DPI Switch settings - Личный: Microsoft Edge":                    false,
		"DPI Switch and 2 more pages - Search - Personal: Microsoft Edge": false,
		"DPI Switch":    false, // the app window's, not a tab's
		"DPI Switch - ": false,
		"DPI Switch - Поиск в Google - Google Chrome": false,
		"DPI Switcher - Google Chrome":                false,
		"About DPI Switch - Google Chrome":            false,
	} {
		if got := isUITabTitle(title); got != want {
			t.Errorf("%q: %v, want %v", title, got, want)
		}
	}
}
