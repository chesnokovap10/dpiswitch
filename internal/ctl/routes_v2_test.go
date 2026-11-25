package ctl

import "testing"

func TestRouteChoiceIndependentTunnels(t *testing.T) {
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
