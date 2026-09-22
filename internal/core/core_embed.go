//go:build embedcore

package core

import (
	_ "embed"
	"strings"
)

// mihomo.exe.gz and mihomo.exe.sha256 are produced by build.ps1 from
// dist\mihomo.exe (see tools\build-mihomo.ps1); they are not committed.

//go:embed mihomo.exe.gz
var embeddedGz []byte

//go:embed mihomo.exe.sha256
var embeddedSum string

func init() {
	embedded = embeddedGz
	embeddedHash = strings.ToLower(strings.TrimSpace(embeddedSum))
}
