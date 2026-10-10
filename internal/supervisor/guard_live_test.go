package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"dpiswitch/internal/udpguard"
)

// The service's own way of finding out that the guard holds, against the real
// engine and the real adapters: with no guard in, no packet is seen dropped;
// with it in, the test packet out of each adapter is. Run elevated, like the
// udpguard package's TestLive -- tools\udpguard-live.ps1 does both:
//
//	set DPISWITCH_LIVE_WFP=1
//	supervisor.test.exe -test.run TestLiveGuardHolds -test.v        (elevated)
func TestLiveGuardHolds(t *testing.T) {
	if os.Getenv("DPISWITCH_LIVE_WFP") != "1" {
		t.Skip("puts real filters into the engine: set DPISWITCH_LIVE_WFP=1, and run elevated")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("the engine takes filters from an administrator: run elevated")
	}
	// the core the service really runs, so that its own packets go on while the
	// guard of this check is in
	core := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	if p := filepath.Join(os.Getenv("ProgramFiles"), "DPI Switch", "core", "mihomo.exe"); fileExists(p) {
		core = p
	}
	t.Logf("the core let through: %s", core)

	if udpguard.Present() {
		t.Skip("the service's guard is in the engine: this one would take its keys. Switch the guard off in the settings to run it")
	}
	g := udpguard.New()
	defer g.Lift()
	if readGuardHolds(context.Background(), g) {
		t.Fatal("shown to hold with no guard in place")
	}
	if _, err := g.Ensure(core); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if !readGuardHolds(context.Background(), g) {
		t.Fatalf("not shown to hold with the guard in, after %v", time.Since(start))
	}
	t.Logf("shown to hold, in %v", time.Since(start))
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
