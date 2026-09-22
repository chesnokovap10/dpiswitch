// Версия программы. Переменная, а не константа: сборка может
// подставить своё значение через -ldflags "-X dpiswitch/internal/version.Version=...".
package version

var Version = "1.0.1"
