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
	"unsafe"

	"golang.org/x/sys/windows"

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

	if err := secureDir(Dir()); err != nil {
		return false, fmt.Errorf("core directory: %w", err)
	}
	target := Path()
	// A file someone else owns is not trusted whatever its hash: its owner
	// may grant itself write access again at any moment, and change the
	// file between the check and the start -- and SYSTEM runs it.
	if trusted(target) {
		if h, err := fileHash(target); err == nil && h == embeddedHash {
			return false, nil
		}
	}

	zr, err := gzip.NewReader(bytes.NewReader(embedded))
	if err != nil {
		return false, fmt.Errorf("embedded core: %w", err)
	}
	// a file of our own making: one left in its place is not written into
	tmp := target + ".new"
	if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("extracting the core: %w", err)
	}
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
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

// coreSDDL: the core directory's permissions -- owner SYSTEM, no
// inheritance; SYSTEM and Administrators full control, Users read and
// execute, for the directory and everything made in it.
const coreSDDL = "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)"

// secureDir makes sure the core directory is ours. One made by someone
// else -- the data directory lets every user create files, and one could
// make "core" before the service did -- is not locked down in place: its
// owner may take the permissions back, or hold a handle opened while it
// could write. It is taken over, removed, and made anew, locked down from
// its first moment: made and then locked, there was a window in which it
// inherited the data directory's Users-modify.
func secureDir(dir string) error {
	fi, err := os.Lstat(dir)
	switch {
	case err == nil && fi.IsDir() && trusted(dir):
		return lockDown(dir)
	case err == nil:
		// SYSTEM may lack the rights a stranger's objects grant: it takes
		// ownership first, and ownership brings the right to set them
		_, _ = winexec.CombinedOutput("icacls.exe", dir, "/setowner", "*S-1-5-18", "/T", "/C", "/Q")
		_, _ = winexec.CombinedOutput("icacls.exe", dir, "/grant", "*S-1-5-18:(OI)(CI)F", "/T", "/C", "/Q")
		if err := os.RemoveAll(dir); err != nil {
			return fmt.Errorf("%s is not the service's and cannot be removed: %w", dir, err)
		}
	case !os.IsNotExist(err):
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(coreSDDL)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	return windows.CreateDirectory(name, sa)
}

// trusted: path is owned by SYSTEM or the Administrators -- nobody else can
// change what it lets them do.
func trusted(path string) bool {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	o, _, err := sd.Owner()
	if err != nil || o == nil {
		return false
	}
	return o.IsWellKnown(windows.WinLocalSystemSid) || o.IsWellKnown(windows.WinBuiltinAdministratorsSid)
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
