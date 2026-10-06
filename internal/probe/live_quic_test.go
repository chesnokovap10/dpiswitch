package probe

import (
	"os"
	"strings"
	"testing"
	"time"
)

// The QUIC decoy on the live core: QUIC blocked direct, through the cut's
// listener (its outbound with quic-fake on) clean. Runs against the
// service's own listeners -- direct 7892, cut 7894, tunnel 7891 -- with the
// core API's secret in DPISWITCH_SOCKS_PASS and targets as ip=name in
// DPISWITCH_LIVE_QUIC, separated by spaces.
func TestLiveSplitQUIC(t *testing.T) {
	targets, pass := os.Getenv("DPISWITCH_LIVE_QUIC"), os.Getenv("DPISWITCH_SOCKS_PASS")
	if targets == "" || pass == "" {
		t.Skip("runs against the service's core: DPISWITCH_LIVE_QUIC=\"ip=name ...\" DPISWITCH_SOCKS_PASS=<secret>")
	}
	d := func(addr string) Dialer { return Dialer{Addr: addr, Timeout: 8 * time.Second, Pass: pass} }
	direct, split, tunnel := d("127.0.0.1:7892"), d("127.0.0.1:7894"), d("127.0.0.1:7891")
	for _, tg := range strings.Fields(targets) {
		ip, name, _ := strings.Cut(tg, "=")
		plain := Report{Domain: name, Port: 443, Proto: "quic", TestedIP: ip}
		dr, tr := RunQUIC(direct, ip, 443, name), RunQUIC(tunnel, ip, 443, name)
		v, why := Judge(dr, tr)
		t.Logf("%s plain: %s %s", name, v, why)
		r := CheckSplitQUIC(split, tunnel, plain, 2, "")
		t.Logf("%s decoy: %s %s (direct %d ms, tunnel %d ms)", name, r.Verdict, r.Reason, r.DirectMs, r.TunnelMs)
		if r.Verdict != CleanSplit && r.Verdict != Slower {
			t.Errorf("%s: through the decoy %s %s", name, r.Verdict, r.Reason)
		}
	}
}
