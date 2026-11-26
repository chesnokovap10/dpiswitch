package ctl

import (
	"os"
	"testing"

	"dpiswitch/internal/paths"
)

func TestRouteChoiceIndependentTunnels(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name              string
		one, two          bool
		order, mode       string
		def, strict, soft string
	}{
		{"both forward", true, true, DefaultTunnel12, ModeOn, TunnelSoftAnyGroup, TunnelAnyGroup, TunnelSoftAnyGroup},
		{"both reverse", true, true, DefaultTunnel21, ModeOn, Tunnel2SoftGroup, TunnelAnyGroup, TunnelSoftAnyGroup},
		{"only awg1", true, false, DefaultTunnel21, ModeOn, TunnelSoftGroup, TunnelOneGroup, TunnelSoftGroup},
		{"only awg2", false, true, DefaultTunnel12, ModeOn, Tunnel2OnlySoftGroup, Tunnel2OnlyGroup, Tunnel2OnlySoftGroup},
		{"neither", false, false, DefaultTunnel12, ModeOn, "DIRECT", "REJECT", "DIRECT"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := DefaultSettings()
			s.Awg1On, s.Awg2On, s.DefaultTunnel = tc.one, tc.two, tc.order
			s.SetMode(tc.mode)
			if got := RouteChoice(s); got[DefaultRouteGroup] != tc.def || got[Route12Group] != tc.strict || got[Route12DirectGroup] != tc.soft {
				t.Fatalf("choices = %#v", got)
			}
			s.SetMode(ModeTunnel)
			want := tc.strict
			if tc.order == DefaultTunnel21 {
				want = RouteChoice(s)[Route21Group]
			}
			if got := RouteChoice(s)[DefaultRouteGroup]; got != want {
				t.Fatalf("tunnel-only default = %q, want %q", got, want)
			}
		})
	}
}

func TestEnabledPresetsRoute(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	for file, want := range map[string]string{
		paths.BlockList: "REJECT", paths.DirectList: "DIRECT",
		paths.Tunnel1List: RouteAwg1Group, paths.Tunnel2List: RouteAwg2Group,
		paths.TunnelList: Route12Group, paths.Tunnel21List: Route21Group,
		paths.Tunnel12DirectList: Route12DirectGroup, paths.Awg2List: Route21DirectGroup,
	} {
		for _, clear := range paths.UserLists {
			_ = os.Remove(paths.User(clear))
		}
		if err := os.WriteFile(paths.User(file), []byte(EnabledPresets+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := EnabledPresetsRoute(); got != want {
			t.Errorf("%s: route %q, want %q", file, got, want)
		}
	}
}
