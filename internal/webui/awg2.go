package webui

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"golang.org/x/sys/windows/svc"

	"dpiswitch/internal/awgconf"
	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
	"dpiswitch/internal/supervisor"
	"dpiswitch/internal/winsvc"
)

// Второй туннель (awg2, выход vpsde): только пресеты и свой список.
// Остальной трафик его не касается -- там по-прежнему awg + детектор.

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
				alive, note := supervisor.TunnelAlive("127.0.0.1:9090",
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
		// файлы пишем сразу: ядро следит за ними само,
		// ждать цикла контроллера незачем
		if err := presets.Write(set.Awg2Presets); err != nil {
			writeResult(w, err)
			return
		}
		writeResult(w, writeList(paths.Awg2Hosts(), "через второй туннель", body.Hosts))
	default:
		http.Error(w, "нужен GET или POST", 405)
	}
}

// подгрузка и удаление .conf второго туннеля: меняет config.yaml,
// поэтому служба перезапускается сама -- связь пропадает на секунды
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
			writeResult(w, fmt.Errorf("не разобран Endpoint: %w", err))
			return
		}
		if c1, err := awgconf.ParseFile(paths.SourceConf()); err == nil &&
			c1.Interface["PrivateKey"] == c.Interface["PrivateKey"] {
			// один ключ на двух сессиях -- серверы перебивают друг друга
			writeResult(w, fmt.Errorf("это тот же конфиг, что у первого туннеля"))
			return
		}
		if err := os.WriteFile(paths.SourceConf2(), []byte(body.Text), 0o600); err != nil {
			writeResult(w, err)
			return
		}
		if err := paths.Restrict(paths.SourceConf2()); err != nil {
			log.Printf("предупреждение: права на %s не ограничены: %v", paths.SourceConf2(), err)
		}
	case http.MethodDelete:
		if err := os.Remove(paths.SourceConf2()); err != nil && !os.IsNotExist(err) {
			writeResult(w, err)
			return
		}
	default:
		http.Error(w, "нужен POST или DELETE", 405)
		return
	}
	writeResult(w, restartService())
}

// перезапуск нужен, только если служба работает: остановленную
// пользователь запустит сам, и конфиг соберётся при старте
func restartService() error {
	if !winsvc.Installed() {
		return nil
	}
	if st, err := winsvc.State(); err != nil || st != svc.Running {
		return nil
	}
	if err := winsvc.Stop(); err != nil {
		return fmt.Errorf("остановка службы: %w", err)
	}
	return winsvc.Start()
}
