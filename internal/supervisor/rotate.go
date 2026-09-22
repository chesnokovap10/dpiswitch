package supervisor

import (
	"os"
	"sync"
)

// rotatingFile is an append-only log file that rotates itself by size,
// keeping one previous copy (path.1).
//
// The core may run for days without a restart, so rotating only at start
// let the log grow without bound (~3 MB a day). The old start-time rotation
// also never worked: it ran after the file had been opened, and Windows
// refuses to rename an open file -- the error was silently ignored.
type rotatingFile struct {
	mu      sync.Mutex
	path    string
	max     int64
	f       *os.File
	written int64
}

func openRotating(path string, max int64) (*rotatingFile, error) {
	r := &rotatingFile{path: path, max: max}
	if err := r.open(); err != nil {
		return nil, err
	}
	if r.written >= max {
		r.rotate()
	}
	return r, nil
}

func (r *rotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	r.f = f
	r.written = 0
	if fi, err := f.Stat(); err == nil {
		r.written = fi.Size()
	}
	return nil
}

// rotate closes the file first: Windows cannot rename an open file
func (r *rotatingFile) rotate() {
	r.f.Close()
	_ = os.Remove(r.path + ".1")
	_ = os.Rename(r.path, r.path+".1")
	if err := r.open(); err != nil {
		// cannot reopen -- keep writing nowhere rather than crash the service
		r.f = nil
	}
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		if err := r.open(); err != nil {
			return len(p), nil
		}
	}
	if r.written+int64(len(p)) > r.max {
		r.rotate()
		if r.f == nil {
			return len(p), nil
		}
	}
	n, err := r.f.Write(p)
	r.written += int64(n)
	return n, err
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	return r.f.Close()
}
