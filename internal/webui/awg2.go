package webui

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"

	"golang.org/x/sys/windows/svc"

	"dpiswitch/internal/awgconf"
	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
	"dpiswitch/internal/winsvc"
)

// Second tunnel (awg2): presets and the custom list only.
// Other traffic is unaffected -- it still goes through awg + the detector.

type awg2Preset struct {
	presets.Preset
	Rules   int  `json:"rules"`
	Enabled bool `json:"enabled"`
}

func (s *Server) handleAwg2(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		set := ctl.LoadSettings(paths.Settings())
		on := map[string]bool{}
		for _, id := range set.Awg2Presets {
			on[id] = true
		}
		var ps []awg2Preset
		for _, p := range presets.All {
			ps = append(ps, awg2Preset{Preset: p, Rules: len(p.Rules()), Enabled: on[p.ID]})
		}
		out := map[string]any{
			"loaded":  false,
			"presets": ps,
			"hosts":   readList(paths.Awg2Hosts()),
		}
		if c, err := awgconf.ParseFile(paths.SourceConf2()); err == nil {
			out["loaded"] = true
			out["endpoint"] = c.Peer["Endpoint"]
			if st, err := winsvc.State(); err == nil && st == svc.Running {
				alive, note := ctl.TunnelHealth("127.0.0.1:9090",
					ctl.SecretFromConfig(paths.Config()), "awg2")
				out["alive"], out["note"] = alive, note
			}
		}
		writeJSON(w, out)
	case http.MethodPost:
		var body struct {
			Presets []string `json:"presets"`
			Hosts   []string `json:"hosts"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeResult(w, err)
			return
		}
		set := ctl.LoadSettings(paths.Settings())
		set.Awg2Presets = body.Presets
		if set.Awg2Presets == nil {
			set.Awg2Presets = []string{}
		}
		if err := ctl.SaveSettings(paths.Settings(), set); err != nil {
			writeResult(w, err)
			return
		}
		// write the files right away: the core watches them itself,
		// no need to wait for the controller cycle
		if err := presets.Write(set.Awg2Presets); err != nil {
			writeResult(w, err)
			return
		}
		writeResult(w, writeList(paths.Awg2Hosts(), "via the second tunnel", body.Hosts))
	default:
		http.Error(w, "GET or POST required", 405)
	}
}

// loading and removing the second tunnel's .conf changes config.yaml,
// so the service restarts itself -- connectivity drops for a few seconds
func (s *Server) handleConfig2(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var body struct {
			Text string `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeResult(w, err)
			return
		}
		c, err := awgconf.Parse(body.Text)
		if err != nil {
			writeResult(w, err)
			return
		}
		if _, _, err := net.SplitHostPort(c.Peer["Endpoint"]); err != nil {
			writeResult(w, fmt.Errorf("cannot parse Endpoint: %w", err))
			return
		}
		if c1, err := awgconf.ParseFile(paths.SourceConf()); err == nil &&
			c1.Interface["PrivateKey"] == c.Interface["PrivateKey"] {
			// one key in two sessions -- the servers keep stealing it from each other
			writeResult(w, fmt.Errorf("this is the same config as the first tunnel"))
			return
		}
		// the second tunnel's private key: written locked down, or not at all
		if err := paths.WriteSecret(paths.SourceConf2(), []byte(body.Text)); err != nil {
			writeResult(w, err)
			return
		}
	case http.MethodDelete:
		if err := os.Remove(paths.SourceConf2()); err != nil && !os.IsNotExist(err) {
			writeResult(w, err)
			return
		}
	default:
		http.Error(w, "POST or DELETE required", 405)
		return
	}
	writeResult(w, restartService())
}

// a restart is needed only if the service is running: a stopped one
// will be started by the user, and the config is built on start
func restartService() error {
	if !winsvc.Installed() {
		return nil
	}
	if st, err := winsvc.State(); err != nil || st != svc.Running {
		return nil
	}
	if err := winsvc.Stop(); err != nil {
		return fmt.Errorf("stopping the service: %w", err)
	}
	return winsvc.Start()
}
