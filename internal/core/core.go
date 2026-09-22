// Package core ships the mihomo core inside dpiswitch.exe.
//
// The user sees a single executable. The core is embedded gzip-compressed
// together with the SHA-256 of the uncompressed binary; before every start
// the service makes sure %ProgramData%\dpiswitch\core\mihomo.exe exists and
// matches that hash, extracting it again otherwise.
//
// The service runs as SYSTEM and executes that file, so the core directory
// is locked down: SYSTEM and Administrators may write, Users may only read
// and execute. Without that, the Users-modify permission inherited from the
// data directory would let any local user replace the file and run code as
// SYSTEM. The hash check before every start covers the rest.
//
// A build without the embedcore tag embeds nothing and falls back to a
// mihomo.exe next to dpiswitch.exe (development builds).
package core

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"dpiswitch/internal/paths"
	"dpiswitch/internal/winexec"
)

// set by core_embed.go when built with -tags embedcore
var (
	embedded     []byte // gzip-compressed mihomo.exe
	embeddedHash string // hex SHA-256 of the uncompressed binary
)

// Embedded reports whether this build carries the core inside.
func Embedded() bool { return len(embedded) > 0 }

// Dir is where the embedded core is extracted.
func Dir() string { return filepath.Join(paths.DataDir(), "core") }

// Path is the core the service should run.
func Path() string {
	if Embedded() {
		return filepath.Join(Dir(), "mihomo.exe")
	}
	return paths.Mihomo()
}

// Paths lists every location a core of ours may run from, current and
// legacy -- used to find orphaned cores after an upgrade.
func Paths() []string {
	out := []string{paths.Mihomo()}
	if Embedded() {
		out = append(out, Path())
	}
	return out
}

var ensureMu sync.Mutex

// Ensure makes the core file present and intact. It reports whether the
// file had to be (re)written.
func Ensure() (bool, error) {
	if !Embedded() {
		if _, err := os.Stat(paths.Mihomo()); err != nil {
			return false, fmt.Errorf("mihomo.exe not found next to dpiswitch.exe: %w", err)
		}
		return false, nil
	}
	ensureMu.Lock()
	defer ensureMu.Unlock()

	if err := os.MkdirAll(Dir(), 0o755); err != nil {
		return false, err
	}
	if err := lockDown(Dir()); err != nil {
		return false, fmt.Errorf("core directory permissions: %w", err)
	}
	target := Path()
	if h, err := fileHash(target); err == nil && h == embeddedHash {
		return false, nil
	}

	zr, err := gzip.NewReader(bytes.NewReader(embedded))
	if err != nil {
		return false, fmt.Errorf("embedded core: %w", err)
	}
	tmp := target + ".new"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return false, err
	}
	hw := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, hw), zr)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return false, fmt.Errorf("extracting the core: %w", err)
	}
	if got := hex.EncodeToString(hw.Sum(nil)); got != embeddedHash {
		os.Remove(tmp)
		return false, fmt.Errorf("embedded core is corrupted (hash %s, want %s)", got, embeddedHash)
	}
	// the old file may still be held by a dying process for a moment
	_ = os.Remove(target)
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		return false, fmt.Errorf("installing the core: %w", err)
	}
	return true, nil
}

func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// lockDown: no inheritance; SYSTEM and Administrators full control,
// Users read and execute. Permissions are set by SID so it works on
// localized Windows.
func lockDown(dir string) error {
	out, err := winexec.CombinedOutput("icacls.exe", dir, "/inheritance:r",
		"/grant:r", "*S-1-5-18:(OI)(CI)F",
		"/grant:r", "*S-1-5-32-544:(OI)(CI)F",
		"/grant:r", "*S-1-5-32-545:(OI)(CI)RX")
	if err != nil {
		return fmt.Errorf("icacls: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
