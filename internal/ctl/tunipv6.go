package ctl

import (
	"dpiswitch/internal/paths"

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
	return paths.ReplaceFile(path, append(b, '\n'))
}

// TunKey: the entry of the check through the TUN adapter itself -- whether
// Windows lets the programs' IPv6 reach it at all. A third-party network
// filter (ViPNet's, with callouts on every IPv6 packet) took each one before
// the adapter did: the tunnels carried IPv6, and every program's IPv6
// connection hung. Found so, the core runs without IPv6 until its next start.
const TunKey = "tun"

// SystemBlocked: whether IPv6 was found not to reach the TUN adapter
func (t TunnelIPv6) SystemBlocked() bool { return t.Dead(TunKey) }

// Tun4Key: the same for IPv4 -- a core answering its API and no IPv4 query
// through the adapter answered: Windows keeps the programs' traffic from it
// altogether. Nothing can go around that; it is said, not acted on.
const Tun4Key = "tun4"

// TrafficBlocked: whether IPv4 was found not to reach the TUN adapter
func (t TunnelIPv6) TrafficBlocked() bool { return t.Dead(Tun4Key) }

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
