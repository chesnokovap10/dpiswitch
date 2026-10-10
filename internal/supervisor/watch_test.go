package supervisor

import (
	"testing"

	"dpiswitch/internal/ctl"
)

// The watchdog watches the first tunnel; with none, the second, only while
// it is switched on: switched off, its server down, it restarted the core
// every minute for a tunnel nothing goes through
func TestWatchedOf(t *testing.T) {
	on, off := ctl.Settings{SecondTunnel: true}, ctl.Settings{SecondTunnel: true}
	on.SetMode(ctl.ModeOn)
	on.SetAwg2(true)
	off.SetMode(ctl.ModeOn)
	off.SetAwg2(false)
	for _, c := range []struct {
		tunnels []string
		set     ctl.Settings
		want    string
	}{
		{nil, on, ""},
		{[]string{"awg1"}, off, "awg1"},
		{[]string{"awg1", "awg2"}, off, "awg1"},
		{[]string{"awg2"}, on, "awg2"},
		{[]string{"awg2"}, off, ""},
	} {
		if got := watchedOf(c.tunnels, c.set); got != c.want {
			t.Errorf("%v, awg2 on %v: %q, want %q", c.tunnels, c.set.Awg2Active(), got, c.want)
		}
	}
}
