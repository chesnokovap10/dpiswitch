package supervisor

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"dpiswitch/internal/awgconf"
	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
)

// One-shot IPv6 check, run once per tunnel bring-up.
//
// The liveness check in keepHealthy goes to cp.cloudflare.com, whose name
// resolves to an A record under ip-version: ipv4-prefer -- so it passes
// entirely over IPv4, and a tunnel whose IPv6 is dead looks perfectly
// healthy while every IPv6-only host behind it hangs until its timeout.
// Nothing in the log says why. This is the check that says it.
//
// A tunnel found without IPv6 is written with ip-version: ipv4 -- that one
// tunnel, not both -- and the core re-reads the config in place. A full core
// restart would drop every connection for the sake of one line.
const (
	// A literal address: no DNS in the way, so this measures IPv6 transport
	// and nothing else.
	v6Literal = "http://[2606:4700:4700::1111]/generate_204"
	// Control target, AAAA only. If the literal is silent and this one
	// answers, IPv6 works and the first address is simply unreachable.
	v6Named = "https://ipv6.google.com/generate_204"
)

// checkIPv6 waits for the tunnels to come up, tests IPv6 through each and
// rewrites the config for the ones that cannot carry it. Runs after every core
// start, against a config that was just rebuilt with IPv6 on for everyone --
// an outbound already pinned to ip-version: ipv4 rejects IPv6 targets, so a
// check running against yesterday's answer would only ever confirm it.
func (s *Supervisor) checkIPv6(ctx context.Context) {
	if !ctl.LoadSettings(paths.Settings()).IPv6 {
		return // IPv6 is off altogether: both tunnels are already ipv4
	}
	hc := newHealthChecker("127.0.0.1:9090", ctl.SecretFromConfig(paths.Config()))

	names := []string{"awg"}
	if _, err := os.Stat(paths.SourceConf2()); err == nil {
		names = append(names, "awg2")
	}

	// reset at core start, so this is empty unless a previous check in this
	// same core session already answered
	old := ctl.LoadTunnelIPv6(paths.TunnelIPv6())
	found := ctl.TunnelIPv6{}
	for _, name := range names {
		if !s.waitTunnel(ctx, hc, name) {
			// the tunnel never came up: no answer about its IPv6 either, so
			// keep what we knew rather than inventing a verdict
			if v, seen := old[name]; seen {
				found[name] = v
			}
			continue
		}
		ok, detail := hc.check(name, v6Literal, 8000)
		if !ok {
			ok, detail = hc.check(name, v6Named, 8000)
		}
		found[name] = ok
		switch {
		case ok && old.Dead(name):
			log.Printf("%s: IPv6 works again (%s)", name, detail)
		case !ok && !old.Dead(name):
			log.Printf("%s: IPv6 does not get through the tunnel (%s) -- "+
				"resolving IPv4 only for it, IPv6-only sites will not open through this tunnel", name, detail)
		}
	}
	if found.Same(old) {
		return
	}
	if err := found.Save(paths.TunnelIPv6()); err != nil {
		log.Printf("IPv6 state not saved: %v", err)
		return
	}
	changed, err := awgconf.Regenerate()
	if err != nil {
		log.Printf("config not rebuilt after the IPv6 check: %v", err)
		return
	}
	if !changed {
		return
	}
	if err := reloadCoreConfig(hc); err != nil {
		log.Printf("core did not re-read the config after the IPv6 check: %v", err)
		return
	}
	log.Println("config re-read after the IPv6 check")
}

// waitTunnel: an IPv6 answer means nothing until the tunnel itself is up --
// during the handshake everything is silent and every verdict would be false.
func (s *Supervisor) waitTunnel(ctx context.Context, hc *healthChecker, name string) bool {
	for i := 0; i < 12; i++ {
		if ok, _ := hc.check(name, ctl.HealthURL, 5000); ok {
			return true
		}
		if !sleepCtx(ctx, 5*time.Second) {
			return false
		}
	}
	return false
}

// reloadCoreConfig asks the core to re-read config.yaml in place, the way the
// UI does when a setting changes. The process keeps running and connections
// survive; only the outbound options are rebuilt.
func reloadCoreConfig(hc *healthChecker) error {
	body := strings.NewReader(`{"path":` + strconv.Quote(paths.Config()) + `}`)
	req, err := http.NewRequest("PUT", "http://"+hc.apiAddr+"/configs?force=true", body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if hc.secret != "" {
		req.Header.Set("Authorization", "Bearer "+hc.secret)
	}
	resp, err := hc.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("PUT /configs: %s", resp.Status)
	}
	return nil
}
