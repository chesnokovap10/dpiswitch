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

// Every route is a select group over fixed fallback groups. The controller
// changes the selected member within a second when either tunnel switch, the
// global mode or the default order changes; the core need not restart.
const (
	DefaultTunnel12 = "awg1-awg2"
	DefaultTunnel21 = "awg2-awg1"

	RouteAwg1Group           = "route-awg1"
	RouteAwg2Group           = "route-awg2"
	Route12Group             = "route-awg1-awg2"
	Route21Group             = "route-awg2-awg1"
	Route12DirectGroup       = "route-awg1-awg2-direct"
	Route21DirectGroup       = "route-awg2-awg1-direct"
	DefaultRouteGroup        = "tunnel-default"
	PresetsRouteGroup        = "route-presets-default"
	EnabledPresetsRouteGroup = "route-enabled-presets"

	// Old names remain for compatibility with older generated configs and
	// tests; new configs use the Route* and DefaultRoute groups above.
	TunnelListsGroup  = "tunnel-lists"
	Tunnel2ListsGroup = "tunnel2-lists"
	Tunnel2Group      = "tunnel2"
	TunnelRestGroup   = "tunnel-rest"

	TunnelOneGroup       = "tunnel-one"        // the first; nothing else
	TunnelAnyGroup       = "tunnel-any"        // the first, then the second; nothing else
	TunnelSoftGroup      = "tunnel"            // the first, then direct
	TunnelSoftAnyGroup   = "tunnel-soft-any"   // the first, then the second, then direct
	Tunnel2SoftGroup     = "tunnel2-soft"      // the second, then the first, then direct
	Tunnel2OnlySoftGroup = "tunnel2-only-soft" // the second, then direct
	Tunnel2StrictGroup   = "tunnel2-strict"    // the second, then the first; nothing else
	Tunnel2OnlyGroup     = "tunnel2-only"      // the second alone; nothing else
)

// Awg2Attached: whether the core's config has a second tunnel. Set by
// awgconf, which decides it; this default only looks for the .conf and the
// settings' switch.
var Awg2Attached = func() bool {
	return Awg2Loaded()
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
	one, two := s.Awg1Active(), s.Awg2Active()
	strict := func(reverse bool) string {
		switch {
		case one && two && reverse:
			return Tunnel2StrictGroup
		case one && two:
			return TunnelAnyGroup
		case one:
			return TunnelOneGroup
		case two:
			return Tunnel2OnlyGroup
		default:
			return "REJECT"
		}
	}
	soft := func(reverse bool) string {
		switch {
		case one && two && reverse:
			return Tunnel2SoftGroup
		case one && two:
			return TunnelSoftAnyGroup
		case one:
			return TunnelSoftGroup
		case two:
			return Tunnel2OnlySoftGroup
		default:
			return "DIRECT"
		}
	}
	reverse := s.DefaultTunnel == DefaultTunnel21
	def := soft(reverse)
	if s.Mode() == ModeTunnel {
		def = strict(reverse)
	}
	return map[string]string{
		RouteAwg1Group:           map[bool]string{true: TunnelOneGroup, false: "REJECT"}[one],
		RouteAwg2Group:           map[bool]string{true: Tunnel2OnlyGroup, false: "REJECT"}[two],
		Route12Group:             strict(false),
		Route21Group:             strict(true),
		Route12DirectGroup:       soft(false),
		Route21DirectGroup:       soft(true),
		DefaultRouteGroup:        def,
		PresetsRouteGroup:        strict(reverse),
		EnabledPresetsRouteGroup: EnabledPresetsRoute(),
	}
}

// EnabledPresetsRoute is the proxy/group selected for the virtual
// enabled_presets row. With no override its empty provider still points at
// the strict default route of presets.
func EnabledPresetsRoute() string {
	for _, route := range []struct{ file, group string }{
		{paths.BlockList, "REJECT"},
		{paths.Tunnel1List, RouteAwg1Group},
		{paths.Tunnel2List, RouteAwg2Group},
		{paths.TunnelList, Route12Group},
		{paths.Tunnel21List, Route21Group},
		{paths.Tunnel12DirectList, Route12DirectGroup},
		{paths.Awg2List, Route21DirectGroup},
		{paths.DirectList, "DIRECT"},
	} {
		if EnabledPresetsIn(route.file) {
			return route.group
		}
	}
	return PresetsRouteGroup
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

// SyncRoutesNow applies tunnel switches and route order immediately for a UI
// action, before existing connections are closed and reconnect.
func SyncRoutesNow(apiAddr, secret string) {
	listMu.Lock()
	defer listMu.Unlock()
	syncRoutes(newAPI(apiAddr, secret))
}
