package ctl

import (
	"os"
	"sort"

	"context"
	"dpiswitch/internal/probe"
	"log"
	"time"

	"dpiswitch/internal/paths"
)

// Defaults: настройки по умолчанию, рассчитанные от каталога данных.
func Defaults() Config {
	return Config{
		DirectAddr:    "127.0.0.1:7892",
		TunnelAddr:    "127.0.0.1:7891", // вход, привязанный к awg напрямую
		APIAddr:       "127.0.0.1:9090",
		CfgPath:       paths.Config(),
		ProxyName:     "awg",
		Provider:      "direct-verified",
		ListPath:      paths.Verified(),
		StatePath:     paths.State(),
		JSONLPath:     paths.Reports(),
		Interval:      60 * time.Second,
		WatchInterval: time.Second,
		TTL:           7 * 24 * time.Hour,
		FailTTL:       time.Hour,
		MaxBackoff:    24 * time.Hour,
		SettingsPath:  paths.Settings(),
		Families:      true,
		DirectDNS:     DefaultSettings().apply(Config{}).DirectDNS,
		Timeout:       8 * time.Second,
		Attempts:      3,
		Workers:       4,
		PerCycle:      20,
		Apply:         false,
		SkipSuffix:    []string{"in-addr.arpa", "local", "lan"},
	}
}

// Run крутит цикл до отмены контекста. Используется и службой,
// и отдельным CLI -- логика одна, дублировать её нельзя.
func Run(ctx context.Context, cfg Config) {
	secret := secretFromConfig(cfg.CfgPath)
	if secret == "" {
		log.Printf("предупреждение: секрет не найден в %s, обращаюсь к API без авторизации", cfg.CfgPath)
	}
	a := newAPI(cfg.APIAddr, secret)
	st := loadState(cfg.StatePath)
	netID := resolveNetwork(cfg, st)
	st.setCurrent(netID)
	_ = st.save()

	// файл настроек пользователя главнее значений службы; его нет --
	// остаётся то, что передали при запуске
	set, haveSet := readSettings(cfg)
	if haveSet {
		cfg = set.apply(cfg)
	}

	mode := "НАБЛЮДЕНИЕ (ничего не меняется)"
	if cfg.Apply {
		mode = "ПРИМЕНЕНИЕ"
	}
	log.Printf("сеть %s | режим: %s | TTL чистых %s, блокировок %s", netID, mode, cfg.TTL, cfg.FailTTL)
	if n := len(st.verified(netID)); n > 0 {
		log.Printf("в памяти уже %d доменов с прямым путём для этой сети", n)
	}

	// синхронизируем файл с памятью СРАЗУ, не дожидаясь изменения вердикта.
	// иначе список и состояние расходятся после переноса, ручной правки
	// или аварийного сброса -- и накопленные вердикты просто не применяются
	if cfg.Apply {
		applyList(cfg, a, st, netID)
	} else if haveSet {
		// выключено пользователем: список от прошлого запуска не должен
		// продолжать уводить сайты напрямую
		clearList(cfg, a)
	}

	w := newWatcher(ctx, cfg, a)

	t := time.NewTicker(cfg.Interval)
	defer t.Stop()
	cycle(cfg, a, st, netID, w)
	for {
		select {
		case <-t.C:
			if ns, ok := readSettings(cfg); ok && (!haveSet || !ns.Equal(set)) {
				if haveSet && !ns.SameCore(set) && cfg.OnCoreChange != nil {
					log.Printf("изменены настройки ядра (DNS: прямой %v, в туннеле %v; IPv6 %v) -- перезапускаю ядро",
						ns.DirectDNS, ns.TunnelDNS, ns.IPv6)
					cfg.OnCoreChange()
				}
				cfg = onSettingsChanged(cfg, ns, a, st, netID)
				set, haveSet = ns, true
			}
			// сеть могла смениться -- вердикты другой сети неприменимы
			if id := resolveNetwork(cfg, st); id != netID {
				log.Printf("сеть сменилась: %s -> %s, переключаю память", netID, id)
				netID = id
				st.setCurrent(id)
				_ = st.save()
				if cfg.Apply {
					applyList(cfg, a, st, netID)
				}
			}
			cycle(cfg, a, st, netID, w)
		case <-ctx.Done():
			log.Println("контроллер остановлен")
			_ = st.save()
			return
		}
	}
}

// Snapshot: сводка для интерфейса.
type Snapshot struct {
	NetworkID string         `json:"network_id"`
	Counts    map[string]int `json:"counts"`
	Direct    []string       `json:"direct"`
	Details   []DirectEntry  `json:"details"`
	Families  []family       `json:"families"`
	// всё, что НЕ идёт напрямую: заблокированные, медленные, непроверенные
	Others []DirectEntry `json:"others"`
}

// DirectEntry: строка таблицы "идут напрямую" в интерфейсе
type DirectEntry struct {
	Domain    string    `json:"domain"`
	DecidedAt time.Time `json:"decided_at"`
	ExpiresAt time.Time `json:"expires_at"`
	TestedIP  string    `json:"tested_ip"`
	Reason    string    `json:"reason"`
	Verdict   string    `json:"verdict,omitempty"`
}

func Load(statePath string) Snapshot {
	st := loadState(statePath)
	id := st.Current
	if id == "" {
		id = networkID()
	}
	s := Snapshot{NetworkID: id, Counts: map[string]int{}}
	st.mu.Lock()
	for _, e := range st.Networks[id] {
		s.Counts[string(e.Verdict)]++
	}
	st.mu.Unlock()
	s.Direct = st.verified(id)
	if LoadSettings(paths.Settings()).Families {
		s.Families = st.families(id)
	}
	for _, d := range s.Direct {
		if e, ok := st.get(id, d); ok {
			s.Details = append(s.Details, DirectEntry{d, e.DecidedAt, e.ExpiresAt, e.TestedIP, e.Reason, string(e.Verdict)})
		}
	}
	st.mu.Lock()
	for dom, e := range st.Networks[id] {
		if e.Verdict != probe.Clean {
			s.Others = append(s.Others, DirectEntry{dom, e.DecidedAt, e.ExpiresAt, e.TestedIP, e.Reason, string(e.Verdict)})
		}
	}
	st.mu.Unlock()
	sort.Slice(s.Others, func(i, j int) bool { return s.Others[i].Domain < s.Others[j].Domain })
	return s
}

func readSettings(cfg Config) (Settings, bool) {
	if cfg.SettingsPath == "" {
		return Settings{}, false
	}
	if _, err := os.Stat(cfg.SettingsPath); err != nil {
		return Settings{}, false
	}
	return LoadSettings(cfg.SettingsPath), true
}

// onSettingsChanged применяет новые настройки к уже вынесенным вердиктам,
// а не только к будущим: сократил срок -- ждать старого незачем
func onSettingsChanged(cfg Config, s Settings, a *api, st *state, netID string) Config {
	was := cfg.Apply
	cfg = s.apply(cfg)
	log.Printf("настройки: автопереключение %v, прямой путь %s, блокировки %s, потолок %s, допуск +%d%%, попыток %d",
		cfg.Apply, cfg.TTL, cfg.FailTTL, cfg.MaxBackoff, s.SlowPct, cfg.Attempts)

	st.mu.Lock()
	for _, m := range st.Networks {
		for _, e := range m {
			if e.Verdict == probe.Clean {
				e.ExpiresAt = e.DecidedAt.Add(cfg.TTL)
			}
		}
	}
	st.mu.Unlock()
	if err := st.save(); err != nil {
		log.Printf("состояние не сохранено: %v", err)
	}

	switch {
	case was && !cfg.Apply:
		// выключили -- всё возвращается в туннель немедленно, а не когда
		// истекут вердикты; память при этом сохраняется
		clearList(cfg, a)
	default:
		applyList(cfg, a, st, netID)
	}
	return cfg
}
