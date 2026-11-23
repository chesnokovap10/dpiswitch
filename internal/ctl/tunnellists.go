package ctl

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"dpiswitch/internal/paths"
)

// Where a connection goes past the lists that name it depends on the mode
// and on the second tunnel switched on or off, and a group's members are
// fixed in the config: changing them there would restart the core. So each
// route has a select group, whose member the controller picks within a
// second of a change, as the lists follow the settings:
//
//   - the always-tunnel list: the first tunnel alone, or -- the second
//     switched on -- the first and then the second; never direct, in every
//     mode.
//   - the second tunnel's presets and list: the second, then the first,
//     then direct -- or, in tunnel only, refused instead of direct. With
//     Awg2NoFallback, the second alone; connections fail when it is down.
//   - what no list names: the first tunnel, then -- switched on -- the
//     second, then direct; in tunnel only the same tunnels, never direct.
//
// The config lists the member the settings ask for first: a core started
// meanwhile begins with it.
const (
	TunnelListsGroup = "tunnel-lists" // select: the always-tunnel list
	Tunnel2Group     = "tunnel2"      // select: the presets and the awg2 list
	TunnelRestGroup  = "tunnel-rest"  // select: MATCH

	TunnelOneGroup     = "tunnel-one"      // the first; nothing else
	TunnelAnyGroup     = "tunnel-any"      // the first, then the second; nothing else
	TunnelSoftGroup    = "tunnel"          // the first, then direct
	TunnelSoftAnyGroup = "tunnel-soft-any" // the first, then the second, then direct
	Tunnel2SoftGroup   = "tunnel2-soft"    // the second, then the first, then direct
	Tunnel2StrictGroup = "tunnel2-strict"  // the second, then the first; nothing else
	Tunnel2OnlyGroup   = "tunnel2-only"    // the second alone; nothing else
)

// Awg2Attached: whether the core's config has a second tunnel. Set by
// awgconf, which decides it; this default only looks for the .conf and the
// settings' switch.
var Awg2Attached = func() bool {
	return Awg2Loaded() && LoadSettings(paths.Settings()).SecondTunnel
}

// Awg2Loaded: whether a .conf is loaded for the second tunnel, usable or
// not, the tunnel switched on in the settings or not; a var for tests
var Awg2Loaded = func() bool {
	_, err := os.Stat(paths.SourceConf2())
	return err == nil
}

// Awg2Carries: whether the second tunnel takes its presets and list -- it
// is there, and switched on. Loaded or switched off, they route nothing.
func (s Settings) Awg2Carries() bool { return s.Awg2Active() && Awg2Attached() }

// RouteChoice: the member each select group takes under the settings.
func RouteChoice(s Settings) map[string]string {
	on, strict := s.Awg2Active(), s.Mode() == ModeTunnel
	pick := func(yes bool, a, b string) string {
		if yes {
			return a
		}
		return b
	}
	two := pick(strict, Tunnel2StrictGroup, Tunnel2SoftGroup)
	if s.Awg2NoFallback {
		two = Tunnel2OnlyGroup
	}
	return map[string]string{
		TunnelListsGroup: pick(on, TunnelAnyGroup, TunnelOneGroup),
		Tunnel2Group:     two,
		TunnelRestGroup: pick(strict, pick(on, TunnelAnyGroup, TunnelOneGroup),
			pick(on, TunnelSoftAnyGroup, TunnelSoftGroup)),
	}
}

// Awg2RouteSynced reports whether the core has taken the current fallback
// choice for the second tunnel. The UI waits for this before closing open
// preset/list connections, so their immediate reconnect cannot take the old
// route again.
func Awg2RouteSynced(apiAddr, secret string) bool {
	b, err := newAPI(apiAddr, secret).do("GET", "/proxies/"+url.PathEscape(Tunnel2Group), nil)
	if err != nil {
		return false
	}
	var g struct {
		Now string `json:"now"`
	}
	return json.Unmarshal(b, &g) == nil && g.Now == RouteChoice(LoadSettings(paths.Settings()))[Tunnel2Group]
}

// routesSet: the member last chosen in the core, by group; listMu held. A
// core started since chose the one its config lists first, which is the
// one the settings asked for when the config was written.
//
// Not always: a core started on the old config, when it could not be
// rebuilt, lists first what the settings asked for back then. So what is
// remembered is forgotten every routesRecheck, and the core asked again.
var (
	routesSet     = map[string]string{}
	routesChecked time.Time
	routesRecheck = 30 * time.Second
)

// syncRoutes has the core's select groups take the members the settings
// ask for; listMu held.
func syncRoutes(a *api) {
	if time.Since(routesChecked) >= routesRecheck {
		clear(routesSet)
		routesChecked = time.Now()
	}
	for group, want := range RouteChoice(LoadSettings(paths.Settings())) {
		if routesSet[group] == want {
			continue
		}
		b, err := a.do("GET", "/proxies/"+url.PathEscape(group), nil)
		if err != nil {
			// no core yet -- its config lists the choice first -- or this
			// group failed: the others are still asked
			continue
		}
		var g struct {
			All []string `json:"all"`
			Now string   `json:"now"`
		}
		if err := json.Unmarshal(b, &g); err != nil {
			continue
		}
		// a choice the core's group does not have yet is not taken as made:
		// it was, and once the core had it nothing ever switched to it
		if !slices.Contains(g.All, want) {
			continue
		}
		if g.Now != want {
			body := fmt.Sprintf(`{"name":%q}`, want)
			if _, err := a.do("PUT", "/proxies/"+url.PathEscape(group), strings.NewReader(body)); err != nil {
				log.Printf("%s not switched to %s: %v", group, want, err)
				continue
			}
			log.Printf("%s: %s", group, want)
		}
		routesSet[group] = want
	}
}
