package ctl

import (
	"fmt"
	"testing"
)

// A tick with no cycle takes what the watcher gathered: the names and
// addresses in use handed over, the candidates kept within the backlog, the
// rest dropped. Nothing drained it while the probes were paused.
func TestWatcherIdle(t *testing.T) {
	w := &watcher{seen: map[string]map[endpoint]bool{}, bare: map[string]bool{},
		live: map[string]bool{}, pinned: map[string]bool{},
		addrPorts: map[string]map[endpoint]bool{}, addrCycles: map[string]int{}}
	var conns []connection
	for i := 0; i < maxBacklog+50; i++ {
		c := tunnelled(fmt.Sprintf("h%d.example.org", i), 443)
		conns = append(conns, c)
		var b connection
		b.Chains = []string{"awg1"}
		b.Metadata.Network, b.Metadata.DestinationPort = "tcp", "20000"
		b.Metadata.DestinationIP = fmt.Sprintf("203.0.%d.%d", i/250, i%250+1)
		conns = append(conns, b)
	}
	w.observe(Config{ProxyName: "awg1"}, conns)
	live, bare := w.idle()
	if len(live) != maxBacklog+50 || len(bare) != maxBacklog+50 {
		t.Fatalf("handed over %d names and %d addresses, want %d of each", len(live), len(bare), maxBacklog+50)
	}
	if len(w.live)+len(w.bare)+len(w.pinned)+len(w.addrPorts) != 0 {
		t.Errorf("kept after an idle tick: %d names in use, %d addresses, %d pinned, %d address candidates",
			len(w.live), len(w.bare), len(w.pinned), len(w.addrPorts))
	}
	if len(w.order) != maxBacklog || len(w.seen) != maxBacklog {
		t.Errorf("candidates kept: %d in order, %d seen, want %d", len(w.order), len(w.seen), maxBacklog)
	}
	// the oldest went, the newest wait for the probes
	if _, ok := w.seen["h0.example.org"]; ok {
		t.Error("the oldest candidate was kept past the backlog")
	}
	if _, ok := w.seen[fmt.Sprintf("h%d.example.org", maxBacklog+49)]; !ok {
		t.Error("the newest candidate was dropped")
	}
}
