package ctl

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"dpiswitch/internal/presets"
	"dpiswitch/internal/probe"
)

// Settings: то, что пользователь правит из интерфейса. Хранится
// отдельным файлом, а не в config.yaml: конфиг ядра закрыт правами
// (там приватный ключ), а эти значения трей должен писать сам.
//
// Контроллер перечитывает файл каждый цикл -- перезапуск службы
// ради смены срока не нужен.
type Settings struct {
	// автопереключение: false -- только наблюдать, всё идёт в туннель
	AutoSwitch bool `json:"auto_switch"`
	// сколько держать домен напрямую до перепроверки
	CleanTTLMin int `json:"clean_ttl_min"`
	// через сколько перепроверять заблокированный
	FailTTLMin int `json:"fail_ttl_min"`
	// потолок паузы для доменов, которые уже теряли прямой путь
	MaxBackoffMin int `json:"max_backoff_min"`
	// насколько прямой путь может быть медленнее туннеля, в процентах
	SlowPct int `json:"slow_pct"`
	// попыток на каждую пробу; лучшее измерение идёт в зачёт
	Attempts int `json:"attempts"`
	// переносить вердикт на весь домен, когда у него несколько чистых
	// поддоменов и ни одного заблокированного
	Families bool `json:"families"`
	// IPv6 через туннель: TUN получает IPv6, туннель предпочитает его
	IPv6 bool `json:"ipv6"`
	// пресеты второго туннеля (awg2): youtube, telegram, ai
	Awg2Presets []string `json:"awg2_presets"`
	// резолверы прямого пути: к ним ядро и пробник ходят напрямую,
	// поэтому CDN выдаёт узлы, ближайшие к провайдеру пользователя
	DirectDNS []string `json:"direct_dns"`
	// резолверы внутри туннеля; пусто -- DNS из .conf
	TunnelDNS []string `json:"tunnel_dns"`
}

// Яндекс: проверен на сети пользователя напрямую, ответы на
// заблокированные домены не подменяет, узлы CDN подбирает под
// российских провайдеров. DoH и DoT на разных адресах: закроют
// один протокол или адрес -- останется другой.
var defaultDirectDNS = []string{"https://77.88.8.8/dns-query", "tls://77.88.8.1"}

// SameCore: не изменилось ли то, что входит в конфиг ядра (резолверы,
// IPv6). Такие настройки требуют перезапуска ядра, остальные
// подхватываются на лету
func (s Settings) SameCore(o Settings) bool {
	return reflect.DeepEqual(s.DirectDNS, o.DirectDNS) &&
		reflect.DeepEqual(s.TunnelDNS, o.TunnelDNS) && s.IPv6 == o.IPv6
}

func (s Settings) Equal(o Settings) bool { return reflect.DeepEqual(s, o) }

func DefaultSettings() Settings {
	return Settings{
		AutoSwitch:    true,
		Families:      true,
		IPv6:          true,
		Awg2Presets:   []string{"youtube", "telegram", "ai"},
		CleanTTLMin:   7 * 24 * 60,
		FailTTLMin:    60,
		MaxBackoffMin: 24 * 60,
		SlowPct:       20,
		Attempts:      3,
		DirectDNS:     append([]string(nil), defaultDirectDNS...),
		TunnelDNS:     []string{},
	}
}

// LoadSettings: отсутствующий или битый файл -- не ошибка,
// берутся значения по умолчанию. Недостающие поля тоже.
func LoadSettings(path string) Settings {
	s := DefaultSettings()
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	s.clamp()
	return s
}

func SaveSettings(path string, s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s Settings) Validate() error {
	switch {
	case s.CleanTTLMin < 10 || s.CleanTTLMin > 30*24*60:
		return fmt.Errorf("срок прямого пути: от 10 минут до 30 дней")
	case s.FailTTLMin < 5 || s.FailTTLMin > 7*24*60:
		return fmt.Errorf("перепроверка заблокированных: от 5 минут до 7 дней")
	// потолок паузы ограничивает перепроверку ЗАБЛОКИРОВАННЫХ после отката,
	// со сроком прямого пути он не связан: 7 дней напрямую и 1 день
	// потолка -- законное сочетание. раньше сравнивалось именно с ним,
	// и такое сохранение молча отклонялось
	case s.MaxBackoffMin < s.FailTTLMin || s.MaxBackoffMin > 30*24*60:
		return fmt.Errorf("потолок паузы: не меньше перепроверки заблокированных и не больше 30 дней")
	case s.SlowPct < 0 || s.SlowPct > 500:
		return fmt.Errorf("допуск по задержке: от 0 до 500%%")
	case s.Attempts < 1 || s.Attempts > 10:
		return fmt.Errorf("попыток: от 1 до 10")
	case len(s.DirectDNS) == 0:
		return fmt.Errorf("нужен хотя бы один DNS для прямых сайтов")
	}
	for _, id := range s.Awg2Presets {
		if !presets.Valid(id) {
			return fmt.Errorf("неизвестный пресет %q", id)
		}
	}
	for _, list := range [][]string{s.DirectDNS, s.TunnelDNS} {
		for _, d := range list {
			if _, err := probe.ParseResolver(d); err != nil {
				return err
			}
		}
	}
	return nil
}

// clamp чинит руками испорченный файл, а не отказывается работать:
// служба не должна падать из-за опечатки в настройках
func (s *Settings) clamp() {
	d := DefaultSettings()
	if s.CleanTTLMin < 10 {
		s.CleanTTLMin = d.CleanTTLMin
	}
	if s.FailTTLMin < 5 {
		s.FailTTLMin = d.FailTTLMin
	}
	if s.MaxBackoffMin < s.FailTTLMin {
		s.MaxBackoffMin = s.FailTTLMin
	}
	if s.SlowPct < 0 {
		s.SlowPct = d.SlowPct
	}
	if s.Attempts < 1 || s.Attempts > 10 {
		s.Attempts = d.Attempts
	}
	var ps []string
	for _, id := range s.Awg2Presets {
		if presets.Valid(id) {
			ps = append(ps, id)
		}
	}
	if ps == nil {
		ps = []string{}
	}
	s.Awg2Presets = ps
	s.DirectDNS = cleanDNS(s.DirectDNS)
	s.TunnelDNS = cleanDNS(s.TunnelDNS)
	if len(s.DirectDNS) == 0 {
		s.DirectDNS = d.DirectDNS
	}
}

// cleanDNS отбрасывает пустые и нераспознанные записи: ядро с кривым
// резолвером не стартует, а оставлять пользователя без сети из-за
// опечатки нельзя
func cleanDNS(in []string) []string {
	out := []string{}
	for _, d := range in {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if _, err := probe.ParseResolver(d); err == nil {
			out = append(out, d)
		}
	}
	return out
}

func (s Settings) apply(cfg Config) Config {
	cfg.Apply = s.AutoSwitch
	cfg.TTL = time.Duration(s.CleanTTLMin) * time.Minute
	cfg.FailTTL = time.Duration(s.FailTTLMin) * time.Minute
	cfg.MaxBackoff = time.Duration(s.MaxBackoffMin) * time.Minute
	cfg.Attempts = s.Attempts
	cfg.Families = s.Families
	cfg.DirectDNS = nil
	for _, d := range s.DirectDNS {
		if r, err := probe.ParseResolver(d); err == nil {
			cfg.DirectDNS = append(cfg.DirectDNS, r)
		}
	}
	probe.SetSlowFactor(1 + float64(s.SlowPct)/100)
	return cfg
}
