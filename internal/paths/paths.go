// Application paths. The service runs with C:\Windows\System32 as its working
// directory, so nothing may be resolved relative to the current directory --
// only relative to the actual binary location and to ProgramData.
package paths

import (
	"os"
	"path/filepath"
)

const AppName = "dpiswitch"

// binaries directory: dpiswitch.exe and mihomo.exe sit side by side
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

// data directory on the system drive: does not depend on the binaries'
// volume being ready at boot, and lets the config be locked down by ACL
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
func VerifiedIP() string      { return Data("direct-verified-ip.txt") }
func ForceDirect() string     { return Data("force-direct.txt") }
func ForceDirectApps() string { return Data("force-direct-apps.txt") }

// second tunnel (awg2): source .conf, custom host list, presets
func SourceConf2() string     { return Data("source2.conf") }
func Awg2Hosts() string       { return Data("awg2-hosts.txt") }
func Preset(id string) string { return Data("preset-" + id + ".txt") }
func ForceTunnel() string     { return Data("force-tunnel.txt") }
func TunnelIPv6() string      { return Data("tunnel-ipv6.json") }
func ServiceLog() string      { return filepath.Join(LogDir(), "service.log") }
func MihomoLog() string       { return filepath.Join(LogDir(), "mihomo.log") }
func ControllerLog() string   { return filepath.Join(LogDir(), "controller.log") }
