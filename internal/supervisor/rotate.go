package supervisor

import (
	"log"
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
	lost    bool // the log could not be opened, and that was said
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

// Write takes the core's output. What cannot be written is dropped, and
// reported as written: this is the core's stdout, and an error here stops
// the copying from its pipe -- the core would then hang on its next log
// line. The loss is said once in the service log, and again only after the
// log came back.
func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		if err := r.open(); err != nil {
			r.drop(err)
			return len(p), nil
		}
	}
	if r.written+int64(len(p)) > r.max {
		r.rotate()
		if r.f == nil {
			r.drop(nil)
			return len(p), nil
		}
	}
	r.lost = false
	n, err := r.f.Write(p)
	r.written += int64(n)
	return n, err
}

func (r *rotatingFile) drop(err error) {
	if r.lost {
		return
	}
	r.lost = true
	if err == nil {
		err = os.ErrClosed
	}
	log.Printf("core log %s unavailable (%v): its output is dropped until it opens again", r.path, err)
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	return r.f.Close()
}
