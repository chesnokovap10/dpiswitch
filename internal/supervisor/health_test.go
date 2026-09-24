package supervisor

import (
	"errors"
	"testing"
	"time"

	"dpiswitch/internal/ctl"
)

// Each of the core's checks counts once; a check it stopped renewing, and an
// API that does not answer, count every time.
func TestReadCheck(t *testing.T) {
	at := time.Now().Add(-10 * time.Second)
	failed := ctl.TunnelCheck{At: at, Note: "no answer"}
	for _, tc := range []struct {
		name     string
		c        ctl.TunnelCheck
		err      error
		seen     time.Time
		news, ok bool
	}{
		{"a new failed check", failed, nil, at.Add(-30 * time.Second), true, false},
		{"the same check again", failed, nil, at, false, false},
		{"a new good check", ctl.TunnelCheck{OK: true, At: at}, nil, at.Add(-30 * time.Second), true, true},
		{"no check yet", ctl.TunnelCheck{OK: true}, nil, time.Time{}, true, true},
		{"stale, read again", ctl.TunnelCheck{At: at, Stale: true}, nil, at, true, false},
		{"API down", ctl.TunnelCheck{}, errors.New("connection refused"), at, true, false},
	} {
		news, ok, _ := readCheck(tc.c, tc.err, tc.seen)
		if news != tc.news || ok != tc.ok {
			t.Errorf("%s: news %v ok %v, want %v %v", tc.name, news, ok, tc.news, tc.ok)
		}
	}
}
