// контроллер: берёт кандидатов из живого трафика mihomo, гоняет пробы,
// ведёт память вердиктов с TTL и привязкой к сети.
// по умолчанию НИЧЕГО не применяет -- только пишет, что сделал бы.
package ctl

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"dpiswitch/internal/probe"
)

type Config struct {
	DirectAddr    string
	TunnelAddr    string
	APIAddr       string
	CfgPath       string
	ProxyName     string
	Provider      string
	ListPath      string
	StatePath     string
	JSONLPath     string
	Interval      time.Duration
	WatchInterval time.Duration
	TTL           time.Duration
	FailTTL       time.Duration
	MaxBackoff    time.Duration
	SettingsPath  string
	Families      bool             // переносить вердикт на весь домен, см. family.go
	DirectDNS     []probe.Resolver // пусто -- встроенный DoH пробника
	// просьба перезапустить ядро: смена резолверов или IPv6 меняет его конфиг
	OnCoreChange func()
	Timeout      time.Duration
	Attempts     int
	Workers      int
	PerCycle     int
	Apply        bool
	SkipSuffix   []string
}

func cycle(cfg Config, a *api, st *state, netID string, w *watcher) {
	conns, err := a.connections()
	if err != nil {
		log.Printf("не читаются соединения: %v", err)
		return
	}

	ports := w.drain()

	// порядок важен: сперва подозрительные, потом просроченные,
	// и только затем новые кандидаты -- откат срочнее расширения
	queue := dedupe(concat(
		suspectDirect(cfg, st, netID, conns),
		st.expired(netID),
		pickCandidates(cfg, st, netID, ports),
	))
	if len(queue) == 0 {
		return
	}
	total := len(queue)
	if len(queue) > cfg.PerCycle {
		queue = queue[:cfg.PerCycle]
		log.Printf("в очереди %d доменов, беру %d за цикл", total, cfg.PerCycle)
	}

	direct := probe.Dialer{Addr: cfg.DirectAddr, Timeout: cfg.Timeout, DNS: cfg.DirectDNS}
	tunnel := probe.Dialer{Addr: cfg.TunnelAddr, Timeout: cfg.Timeout}

	var (
		wg      sync.WaitGroup
		sem     = make(chan struct{}, cfg.Workers)
		mu      sync.Mutex
		changed bool
	)
	for _, dom := range queue {
		wg.Add(1)
		go func(dom string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// правило в mihomo доменное, поэтому решение распространяется
			// на все порты сразу. значит и проверить надо все, что видели,
			// и худший вердикт побеждает.
			eps := ports[dom]
			if len(eps) == 0 {
				eps = []endpoint{{port: 443}}
			}
			var rep probe.Report
			for _, ep := range eps {
				r := probe.CheckProto(direct, tunnel, dom, ep.port, cfg.Attempts, ep.udp)
				appendJSONL(cfg.JSONLPath, r)
				if r.Aborted {
					// память не трогаем: домен останется в очереди
					// и проверится заново, когда ядро поднимется
					return
				}
				// INCONCLUSIVE означает "измерить не удалось" -- например, хост
				// вообще не отвечает по QUIC ни туда, ни сюда. такой результат
				// не должен перебивать определённый вердикт, иначе домен
				// застрянет в туннеле из-за протокола, которого у него нет.
				switch {
				case rep.Domain == "":
					rep = r
				case rep.Verdict == probe.Inconcl && r.Verdict != probe.Inconcl:
					rep = r
				case r.Verdict == probe.Inconcl:
				case rep.Verdict == probe.Clean && r.Verdict != probe.Clean:
					rep = r
				}
			}

			prev, had := st.get(netID, dom)
			e := &entry{
				Verdict:   rep.Verdict,
				Reason:    rep.Reason,
				DecidedAt: time.Now(),
				TestedIP:  rep.TestedIP,
			}
			if rep.Verdict == probe.Clean {
				e.ExpiresAt = time.Now().Add(cfg.TTL)
			} else {
				e.ExpiresAt = time.Now().Add(cfg.FailTTL)
			}
			if had {
				e.Reverts = prev.Reverts
				// домен терял прямой путь -- чем чаще это повторяется,
				// тем дольше он потом не проверяется заново
				if prev.Verdict == probe.Clean && rep.Verdict != probe.Clean {
					e.Reverts++
					backoff := time.Duration(e.Reverts) * cfg.TTL
					if backoff > cfg.MaxBackoff {
						backoff = cfg.MaxBackoff
					}
					e.ExpiresAt = time.Now().Add(backoff)
					log.Printf("ОТКАТ %s: %s (%s), откатов всего %d", dom, rep.Verdict, rep.Reason, e.Reverts)
				}
			}

			st.put(netID, dom, e)

			mu.Lock()
			if !had || prev.Verdict != rep.Verdict {
				changed = true
				if rep.Verdict == probe.Clean {
					// печатаем ЛУЧШИЕ измерения -- те самые, на которых
					// основано решение. последний проход мог быть случайно
					// медленным, и показывать его значит вводить в заблуждение
					log.Printf("ЧИСТО %s (узел %s, прямой %s против туннеля %s)",
						dom, rep.TestedIP, msVal(rep.DirectMs, rep.Direct), msVal(rep.TunnelMs, rep.Tunnel))
				} else if !had {
					log.Printf("  %s %s: %s", rep.Verdict, dom, rep.Reason)
				}
			}
			mu.Unlock()
		}(dom)
	}
	wg.Wait()

	if err := st.save(); err != nil {
		log.Printf("состояние не сохранено: %v", err)
	}
	if changed {
		applyList(cfg, a, st, netID)
	}
}

// кандидаты: то, что накопил наблюдатель и о чём мы ещё не решали.
// фильтры по протоколу и маршруту уже применены при сборе.
func pickCandidates(cfg Config, st *state, netID string, seen map[string][]endpoint) []string {
	var out []string
	for dom := range seen {
		if skipped(cfg, dom) {
			continue
		}
		if _, had := st.get(netID, dom); had {
			continue
		}
		out = append(out, dom)
	}
	return dedupe(out)
}

// домены с прямым путём, у которых соединение открыто, но ничего не пришло:
// похоже на разрыв -- перепроверяем не дожидаясь TTL
func suspectDirect(cfg Config, st *state, netID string, conns []connection) []string {
	var out []string
	fams := map[string]bool{}
	if cfg.Families {
		for _, f := range st.families(netID) {
			fams[f.Domain] = true
		}
	}
	for _, c := range conns {
		dom := c.domain()
		if dom == "" || !c.viaDirect() || c.Download > 0 {
			continue
		}
		e, had := st.get(netID, dom)
		switch {
		case had && e.Verdict == probe.Clean:
		case !had && fams[familyOf(dom)]:
			// пущен напрямую семейством, сам ни разу не проверялся
		default:
			continue
		}
		if ts, err := time.Parse(time.RFC3339, c.Start); err == nil && time.Since(ts) > 10*time.Second {
			out = append(out, dom)
		}
	}
	return dedupe(out)
}

// запись вердиктов в rule-provider и перечитывание его ядром
func applyList(cfg Config, a *api, st *state, netID string) {
	doms, fams := directRules(cfg, st, netID)
	if !cfg.Apply {
		log.Printf("наблюдение: в DIRECT ушли бы %d доменов (%s)", len(doms), preview(doms))
		return
	}
	var b strings.Builder
	b.WriteString("# генерируется контроллером, руками не править\n")
	fmt.Fprintf(&b, "# сеть %s, обновлено %s\n", netID, time.Now().Format(time.RFC3339))
	for _, d := range doms {
		b.WriteString(d + "\n")
	}
	tmp := cfg.ListPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0644); err != nil {
		log.Printf("список не записан: %v", err)
		return
	}
	if err := os.Rename(tmp, cfg.ListPath); err != nil {
		log.Printf("список не заменён: %v", err)
		return
	}
	if err := a.reloadProvider(cfg.Provider); err != nil {
		log.Printf("провайдер не перечитан: %v", err)
		return
	}
	if len(fams) > 0 {
		names := make([]string, len(fams))
		for i, f := range fams {
			names[i] = fmt.Sprintf("%s (%d)", f.Domain, f.Clean)
		}
		log.Printf("применено: %d правил напрямую, из них семейств %d: %s",
			len(doms), len(fams), strings.Join(names, ", "))
		return
	}
	log.Printf("применено: %d доменов идут напрямую", len(doms))
}

func clearList(cfg Config, a *api) {
	b := "# автопереключение выключено -- всё идёт через туннель\n"
	tmp := cfg.ListPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(b), 0644); err != nil {
		log.Printf("список не очищен: %v", err)
		return
	}
	if err := os.Rename(tmp, cfg.ListPath); err != nil {
		log.Printf("список не заменён: %v", err)
		return
	}
	if err := a.reloadProvider(cfg.Provider); err != nil {
		log.Printf("провайдер не перечитан: %v", err)
		return
	}
	log.Println("автопереключение выключено: прямой путь снят со всех доменов")
}

func skipped(cfg Config, dom string) bool {
	for _, s := range cfg.SkipSuffix {
		if dom == s || strings.HasSuffix(dom, "."+s) {
			return true
		}
	}
	return false
}

func concat(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

// порядок первого появления сохраняется: очередь приоритетная
func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func appendJSONL(path string, rep probe.Report) {
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	b, _ := json.Marshal(rep)
	fmt.Fprintln(f, string(b))
}

func preview(d []string) string {
	s := append([]string{}, d...)
	sort.Strings(s)
	if len(s) > 5 {
		return strings.Join(s[:5], ", ") + ", ..."
	}
	return strings.Join(s, ", ")
}

func ms(r probe.PathResult) string {
	if !r.TLSOk {
		return "-"
	}
	return fmt.Sprintf("%dms", (r.TCPTime + r.TLSTime).Milliseconds())
}

// msVal: лучшее измерение, если оно есть; иначе последнее
func msVal(best int64, last probe.PathResult) string {
	if best > 0 {
		return fmt.Sprintf("%dms", best)
	}
	return ms(last)
}
