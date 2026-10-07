package ctl

import (
	"context"
	"slices"
	"sync/atomic"
	"time"
)

// The fast lane: a name is probed the moment it turns up, not at the next
// cycle.
//
// A cycle waits for its slowest probe -- a name blocked by its name takes a
// timeout of 8 s on TCP and another on QUIC before the cut is tried -- and
// the next one starts at the following tick. A name first seen meanwhile
// waited it all out: on 07.10 a new media host of YouTube Music had its
// verdict 35 to 57 s after the first connection, though its own probes took
// some 10 to 18. Now each new name is probed alone, as soon as the watcher
// has it, by a few probes of its own beside the cycle; with them all busy
// the name waits for the cycle as before.
//
// It probes what the cycle would: names with no verdict, not skipped and
// not pinned by a list, while the cycle's gate lets probes run.

// fastWorkers: names probed at once by the fast lane, beside the cycle's
const fastWorkers = 4

func fastLane(ctx context.Context, cfgNow func() Config, a *api, st *state, allowed *atomic.Bool, w *watcher) {
	sem := make(chan struct{}, fastWorkers)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		doms, ports := w.takeFresh()
		if len(doms) == 0 || !allowed.Load() {
			continue
		}
		cfg := cfgNow()
		id := st.current()
		if id == "" || id == noNetwork || cfg.stopping() {
			continue
		}
		cfg.alone = noFirstTunnel()
		lists := loadPinned(cfg.PinnedLists)
		doms = slices.DeleteFunc(doms, func(d string) bool {
			_, had := st.get(id, d)
			return had || skipped(cfg, d) || lists.has(d)
		})
		for _, d := range doms {
			select {
			case sem <- struct{}{}:
			default:
				// all busy: the cycle takes it, it is still in the watcher
				continue
			}
			go func(d string) {
				defer func() { <-sem }()
				probeBatch(cfg, a, st, id, w, []string{d}, map[string][]endpoint{d: ports[d]})
			}(d)
		}
	}
}
