package paths

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/user"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The files holding a private key (source.conf, source2.conf, config.yaml)
// used to be written in place and locked down after: a new one was born
// with the data directory's permissions -- modify for every user -- and
// held the key so until Restrict ran; if Restrict failed, only a warning
// was logged. config.yaml was rewritten by truncating it first, which kept
// its permissions but left it empty or cut short when the write failed.
//
// Now the content goes into a temporary file beside the target, created
// already locked down -- the permissions are part of CreateFile, and the
// handle shares nothing, so no one gets a handle to it on the way -- then
// flushed and moved over the target in one step. A failure at any point
// leaves the old file whole, and nothing is written unlocked.

// WriteSecret writes a key-bearing file for the user saving it: access for
// SYSTEM (the service), Administrators and the current user -- what
// Restrict gives.
func WriteSecret(path string, data []byte) error {
	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("current user unknown: %w", err)
	}
	sd, err := windows.SecurityDescriptorFromString(
		"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + u.Uid + ")")
	if err != nil {
		return fmt.Errorf("permissions for %s: %w", path, err)
	}
	return writeWith(path, data, sd)
}

// ReplaceSecret rewrites a key-bearing file that exists, keeping its own
// permissions: the service rewriting config.yaml must not take away the
// access the user who saved it -- and the tray reading its secret -- has.
func ReplaceSecret(path string, data []byte) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("permissions of %s: %w", path, err)
	}
	// the directory's own permissions must not be inherited on top
	if err := sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		return fmt.Errorf("permissions of %s: %w", path, err)
	}
	return writeWith(path, data, sd)
}

func writeWith(path string, data []byte, sd *windows.SECURITY_DESCRIPTOR) error {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	// a fresh name each time: one planted beforehand cannot be reused
	tmp := path + "." + hex.EncodeToString(rnd[:]) + ".tmp"
	name, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, sa,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return fmt.Errorf("%s not written: %w", path, err)
	}
	f := os.NewFile(uintptr(h), tmp)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("%s not written: %w", path, err)
	}
	return nil
}
