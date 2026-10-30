package supervisor

import (
	"net/netip"
	"slices"
	"testing"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
)

func TestGuardDirectUDPDNS(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	s := ctl.DefaultSettings()
	s.DirectDNS = []string{"8.8.8.8", "udp://1.1.1.1:5353", "udp://[2001:4860:4860::8888]:5354", "tcp://192.0.2.1", "tls://192.0.2.2", "https://192.0.2.3/dns-query"}
	if err := ctl.SaveSettings(paths.Settings(), s); err != nil {
		t.Fatal(err)
	}
	endpoints := guardSystemEndpoints()
	got := endpoints()
	want := []netip.AddrPort{netip.MustParseAddrPort("8.8.8.8:53"), netip.MustParseAddrPort("1.1.1.1:5353"), netip.MustParseAddrPort("[2001:4860:4860::8888]:5354")}
	if len(got) != len(want) {
		t.Fatalf("endpoints %v", got)
	}
	for _, p := range want {
		if !slices.Contains(got, p) {
			t.Errorf("missing %s in %v", p, got)
		}
	}
	s.DirectDNS = []string{"tls://8.8.8.8"}
	if err := ctl.SaveSettings(paths.Settings(), s); err != nil {
		t.Fatal(err)
	}
	if got := endpoints(); len(got) != 0 {
		t.Fatalf("removed UDP DNS still excepted: %v", got)
	}
}
