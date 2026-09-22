package ctl

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
)

// GET /connections отдаёт снимок ОТКРЫТЫХ соединений. обычный веб-запрос
// живёт секунды, поэтому опрос раз в цикл пропускает почти всё: за сеанс
// через ядро прошло 353 домена, а в опросы попал 31.
// поэтому смотрим часто и копим имена, а пробуем по-прежнему раз в цикл.
type watcher struct {
	mu   sync.Mutex
	seen map[string]map[endpoint]bool
}

func newWatcher(ctx context.Context, cfg Config, a *api) *watcher {
	w := &watcher{seen: map[string]map[endpoint]bool{}}
	go w.loop(ctx, cfg, a)
	return w
}

func (w *watcher) loop(ctx context.Context, cfg Config, a *api) {
	t := time.NewTicker(cfg.WatchInterval)
	defer t.Stop()
	var failed int
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		conns, err := a.connections()
		if err != nil {
			// ядро могло перезапуститься -- не шумим на каждой итерации
			if failed++; failed%30 == 1 {
				log.Printf("наблюдатель: соединения не читаются: %v", err)
			}
			continue
		}
		failed = 0
		w.mu.Lock()
		for _, c := range conns {
			dom := c.domain()
			// кроме туннельных берём и пущенные напрямую нашим списком:
			// так в проверку попадают хосты, которых пустило семейство
			// без собственного вердикта. уже решённые отсеет состояние
			if dom == "" || !c.probeable() ||
				!(c.viaTunnel(cfg.ProxyName) || c.byProvider(cfg.Provider)) {
				continue
			}
			// маршрут закреплён за вторым туннелем (пресет или свой список):
			// вердикт ничего не изменит, проверка -- пустая трата. без awg2
			// такие соединения идут через awg и иначе попали бы сюда
			if c.Rule == "RuleSet" && (strings.HasPrefix(c.RulePayload, "preset-") ||
				c.RulePayload == "awg2-hosts") {
				continue
			}
			if w.seen[dom] == nil {
				w.seen[dom] = map[endpoint]bool{}
			}
			w.seen[dom][endpoint{udp: c.isUDP(), port: c.port()}] = true
		}
		w.mu.Unlock()
	}
}

// забрать накопленное и очистить: решённые домены больше не вернутся,
// потому что их отфильтрует состояние
// endpoint: одна проверяемая точка домена. протокол важен --
// QUIC может резаться отдельно от TCP на том же порту 443.
type endpoint struct {
	udp  bool
	port int
}

func (e endpoint) String() string {
	if e.udp {
		return fmt.Sprintf("quic/%d", e.port)
	}
	return fmt.Sprintf("tcp/%d", e.port)
}

func (w *watcher) drain() map[string][]endpoint {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[string][]endpoint, len(w.seen))
	for d, eps := range w.seen {
		for e := range eps {
			out[d] = append(out[d], e)
		}
		sort.Slice(out[d], func(i, j int) bool {
			if out[d][i].port != out[d][j].port {
				return out[d][i].port < out[d][j].port
			}
			return !out[d][i].udp
		})
	}
	w.seen = map[string]map[endpoint]bool{}
	return out
}
