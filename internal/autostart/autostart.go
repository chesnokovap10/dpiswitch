// Tray autostart via the per-user Run registry key.
// HKCU rather than HKLM or Task Scheduler: no administrator rights needed.
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
	// the path may be stale after the folder was moved: autostart is then
	// formally on but launches the wrong binary
	return strings.EqualFold(v, command())
}

// Present: whether autostart is on for any copy -- after the tray moves to
// the installed copy, the old path still says the user wanted it.
func Present() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(valueName)
	return err == nil
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
