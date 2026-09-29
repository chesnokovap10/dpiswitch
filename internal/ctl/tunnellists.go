package ctl

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"slices"
	"strings"

	"dpiswitch/internal/paths"
)

// The always-tunnel list goes to a select group of its own: awg alone, or
// -- the second tunnel switched on -- a fallback of awg and then awg2. Named
// for a tunnel, it never goes direct; and a second tunnel switched off
// carries nothing, this list included. The switch follows the settings file
// within a second, as the lists do: a group's members are fixed in the
// config, and changing them there would restart the core.
const (
	TunnelListsGroup = "tunnel-lists"
	TunnelAnyGroup   = "tunnel-any"
)

// tunnelListsSet: the member last chosen in the core; listMu held. A core
// started since chose the one its config lists first, which is the one the
// settings asked for when the config was written.
var tunnelListsSet string

// syncTunnelLists has the core's group take the member the settings ask
// for. A core with no second tunnel has one member: nothing to choose.
// listMu held.
func syncTunnelLists(a *api) {
	want := "awg"
	if LoadSettings(paths.Settings()).Awg2Active() {
		want = TunnelAnyGroup
	}
	if tunnelListsSet == want {
		return
	}
	b, err := a.do("GET", "/proxies/"+TunnelListsGroup, nil)
	if err != nil {
		return // no core yet: its config lists the choice first
	}
	var g struct {
		All []string `json:"all"`
		Now string   `json:"now"`
	}
	if err := json.Unmarshal(b, &g); err != nil {
		return
	}
	if slices.Contains(g.All, want) && g.Now != want {
		body := fmt.Sprintf(`{"name":%q}`, want)
		if _, err := a.do("PUT", "/proxies/"+url.PathEscape(TunnelListsGroup), strings.NewReader(body)); err != nil {
			log.Printf("always-tunnel list not switched to %s: %v", want, err)
			return
		}
		log.Printf("always-tunnel list: %s", want)
	}
	tunnelListsSet = want
}
