package ctl

import (
	"encoding/json"
	"os"
)

// TunnelIPv6 remembers what the one-shot check found for each tunnel:
// whether IPv6 actually gets through it. The config generator reads this,
// so a tunnel whose IPv6 is dead is written with ip-version: ipv4 and stops
// stalling on IPv6-only hosts until their timeout.
//
// The check runs when a tunnel comes up, not on a schedule: IPv6 dying in the
// middle of a session is rare enough not to carry a permanent watchdog for.
type TunnelIPv6 map[string]bool

func LoadTunnelIPv6(path string) TunnelIPv6 {
	b, err := os.ReadFile(path)
	if err != nil {
		return TunnelIPv6{}
	}
	var t TunnelIPv6
	if json.Unmarshal(b, &t) != nil || t == nil {
		return TunnelIPv6{}
	}
	return t
}

// Save replaces the file whole: written in place, a write cut short left
// it broken, and LoadTunnelIPv6 then read it as "nothing known".
func (t TunnelIPv6) Save(path string) error {
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Dead reports a tunnel the check has found IPv6 broken on. An unknown
// tunnel is not dead: until it is checked it keeps IPv6, so a first run
// behaves as before.
func (t TunnelIPv6) Dead(name string) bool {
	ok, seen := t[name]
	return seen && !ok
}

func (t TunnelIPv6) Same(other TunnelIPv6) bool {
	if len(t) != len(other) {
		return false
	}
	for k, v := range t {
		if o, ok := other[k]; !ok || o != v {
			return false
		}
	}
	return true
}
