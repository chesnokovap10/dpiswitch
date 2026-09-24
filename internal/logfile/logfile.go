// Package logfile keeps the program's append-only files bounded: a file that
// has outgrown its limit is renamed to <path>.1, the previous .1 dropped.
package logfile

import "os"

// RotateIfOver moves path to path.1 once it has reached max bytes. The file
// must not be open here: Windows refuses to rename an open file.
func RotateIfOver(path string, max int64) error {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() < max {
		return nil
	}
	_ = os.Remove(path + ".1")
	return os.Rename(path, path+".1")
}
