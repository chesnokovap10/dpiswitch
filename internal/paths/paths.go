// Пути приложения. Служба работает с рабочим каталогом C:\Windows\System32,
// поэтому ничего нельзя резолвить относительно текущего каталога --
// только от реального положения бинаря и от ProgramData.
package paths

import (
	"os"
	"path/filepath"
)

const AppName = "dpiswitch"

// каталог с бинарями: dpiswitch.exe и mihomo.exe лежат рядом
func ExeDir() string {
	exe, err := os.Executable()
	if err != nil {
		wd, _ := os.Getwd()
		return wd
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return filepath.Dir(exe)
}

func Exe() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join(ExeDir(), AppName+".exe")
	}
	return exe
}

func Mihomo() string { return filepath.Join(ExeDir(), "mihomo.exe") }

// каталог данных на системном диске: не зависит от готовности
// тома с бинарями при загрузке и позволяет закрыть конфиг правами
func DataDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, AppName)
}

func EnsureDataDir() error {
	if err := os.MkdirAll(DataDir(), 0o755); err != nil {
		return err
	}
	return os.MkdirAll(LogDir(), 0o755)
}

func Settings() string { return Data("settings.json") }

func Data(name string) string { return filepath.Join(DataDir(), name) }

func LogDir() string { return filepath.Join(DataDir(), "logs") }

func Config() string          { return Data("config.yaml") }
func SourceConf() string      { return Data("source.conf") }
func State() string           { return Data("controller-state.json") }
func Reports() string         { return Data("reports.jsonl") }
func Verified() string        { return Data("direct-verified.txt") }
func ForceDirect() string     { return Data("force-direct.txt") }
func ForceDirectApps() string { return Data("force-direct-apps.txt") }

// второй туннель (vpsde): исходник .conf, свой список сайтов, пресеты
func SourceConf2() string     { return Data("source2.conf") }
func Awg2Hosts() string       { return Data("awg2-hosts.txt") }
func Preset(id string) string { return Data("preset-" + id + ".txt") }
func ForceTunnel() string     { return Data("force-tunnel.txt") }
func ServiceLog() string      { return filepath.Join(LogDir(), "service.log") }
func MihomoLog() string       { return filepath.Join(LogDir(), "mihomo.log") }
func ControllerLog() string   { return filepath.Join(LogDir(), "controller.log") }
