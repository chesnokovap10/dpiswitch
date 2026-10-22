package paths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// ReplaceFile writes a file whole or not at all: the data goes to a
// temporary file of its own, which then takes the file's place. Two writers
// that shared one ".tmp" name could interleave into a broken file, or one's
// rename failed because the other had already moved the file away.
func ReplaceFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		// CreateTemp makes it 0600; the lists are read by the core, which may
		// run as another account
		err = os.Chmod(f.Name(), 0o644)
	}
	if err != nil {
		os.Remove(f.Name())
		return err
	}
	return renameRetry(f.Name(), path)
}

// RemoveRetry removes a file, trying again while Windows refuses it for a
// moment. A name of a file with other names, just opened and closed, is
// refused for a millisecond or two ("Access is denied"): a refused request
// the service had read stayed until the next second. One gone already is no
// error.
func RemoveRetry(path string) error {
	var err error
	for i := 0; i < 20; i++ {
		if err = os.Remove(path); err == nil || errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return err
}

// renameRetry: Windows refuses to replace a file someone has open, and the
// core reads a list the moment it changes. A read takes well under a
// millisecond, so trying again a few times gets through.
func renameRetry(from, to string) error {
	var err error
	for i := 0; i < 20; i++ {
		if err = os.Rename(from, to); err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	os.Remove(from)
	return err
}
