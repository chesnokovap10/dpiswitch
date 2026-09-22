// Автозапуск трея через ключ реестра пользователя.
// HKCU, а не HKLM и не планировщик: прав администратора не требует.
package autostart

import (
	"strings"

	"golang.org/x/sys/windows/registry"

	"dpiswitch/internal/paths"
)

const (
	runKey    = `Software\Microsoft\Windows\CurrentVersion\Run`
	valueName = "dpiswitch"
)

func command() string { return `"` + paths.Exe() + `" tray` }

func Enabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(valueName)
	if err != nil {
		return false
	}
	// путь мог устареть после переноса папки -- тогда автозапуск
	// формально включён, но запускает не то
	return strings.EqualFold(v, command())
}

func Set(on bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !on {
		err := k.DeleteValue(valueName)
		if err == registry.ErrNotExist {
			return nil
		}
		return err
	}
	return k.SetStringValue(valueName, command())
}
