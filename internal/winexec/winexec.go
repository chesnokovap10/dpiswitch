// Running external commands without a flashing console window.
//
// The app is built as a GUI binary (-H=windowsgui) and has no console, so
// Windows creates a new window for every child process. When polling every
// few seconds this shows up as a flickering black window.
// CREATE_NO_WINDOW prevents it.
package winexec

import (
	"os/exec"
	"syscall"
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
