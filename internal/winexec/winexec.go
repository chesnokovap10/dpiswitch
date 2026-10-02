// Running external commands without a flashing console window.
//
// The app is built as a GUI binary (-H=windowsgui) and has no console, so
// Windows creates a new window for every child process. When polling every
// few seconds this shows up as a flickering black window.
// CREATE_NO_WINDOW prevents it.
package winexec

import (
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

const createNoWindow = 0x08000000

func Command(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
	return cmd
}

func Output(name string, args ...string) ([]byte, error) {
	return Command(name, args...).Output()
}

func CombinedOutput(name string, args ...string) ([]byte, error) {
	return Command(name, args...).CombinedOutput()
}

// System32: a program of Windows' own, by its full path. Run by name it is
// looked for along PATH, and a directory there that others may write in --
// some installers put one ahead of System32 -- would have the service run,
// as SYSTEM, whatever was put there under that name.
func System32(name string) string {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		dir = `C:\Windows\System32`
	}
	return filepath.Join(dir, name)
}

// WindowsDir: a program in the Windows directory itself (explorer.exe), by
// its full path, as System32
func WindowsDir(name string) string {
	dir, err := windows.GetWindowsDirectory()
	if err != nil {
		dir = `C:\Windows`
	}
	return filepath.Join(dir, name)
}
