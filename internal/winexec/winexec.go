// Запуск внешних команд без всплывающего консольного окна.
//
// Приложение собрано как GUI (-H=windowsgui), своей консоли у него нет,
// и Windows создаёт новое окно под каждый дочерний процесс. При опросе
// раз в несколько секунд это выглядит как мигание чёрного окна.
// CREATE_NO_WINDOW убирает его.
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
