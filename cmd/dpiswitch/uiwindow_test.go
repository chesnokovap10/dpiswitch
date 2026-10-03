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
