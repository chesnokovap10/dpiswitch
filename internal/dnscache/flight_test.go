package dnscache

import (
	"testing"
	"time"

	"dpiswitch/internal/probe"
)

// A fetch begun in one network and ending in another: the question asked
// in the new one is a fetch of its own, not the old one's answer, and the
// old answer is kept in neither -- it was asked in the old network, and
// would be given as the new one's. The same with the servers changed.
func TestFetchAcrossChange(t *testing.T) {
	for _, change := range []string{"network", "servers"} {
		t.Run(change, func(t *testing.T) {
			slow := &fakeServer{answer: gives("192.0.2.1", 60), block: make(chan struct{})}
			other := &fakeServer{answer: gives("192.0.2.2", 60)}
			fakeServers(t, map[string]*fakeServer{"udp://192.0.2.53": slow, "udp://192.0.2.54": other})
			s := newCache(t, "udp://192.0.2.53")
			first := make(chan string, 1)
			go func() { first <- firstIP(ask(t, s, "example.com", 1)) }()
			for end := time.Now().Add(2 * time.Second); slow.asked.Load() == 0; time.Sleep(time.Millisecond) {
				if time.Now().After(end) {
					t.Fatal("the first fetch never began")
				}
			}
			if change == "network" {
				// the same servers answer the new network: the slow one
				// gives the new answer, unblocked for it
				slow.answer = gives("192.0.2.2", 60)
				s.SetNetwork("AS2")
			} else {
				s.Configure([]string{"udp://192.0.2.54"}, probe.Dialer{})
			}
			second := make(chan string, 1)
			go func() { second <- firstIP(ask(t, s, "example.com", 2)) }()
			if change == "network" {
				// the second fetch asks too: two asked, not one waited on
				for end := time.Now().Add(2 * time.Second); slow.asked.Load() < 2; time.Sleep(time.Millisecond) {
					if time.Now().After(end) {
						t.Fatal("the new network's question joined the old fetch")
					}
				}
			}
			close(slow.block)
			if ip := <-second; ip != "192.0.2.2" {
				t.Errorf("the new %s got %s", change, ip)
			}
			<-first
			s.mu.Lock()
			old := s.nets["AS1"]["example.com"]
			s.mu.Unlock()
			if old != nil && firstIP(old.Msg) == "192.0.2.1" && change == "servers" {
				t.Error("the old servers' answer kept after they changed")
			}
			if change == "network" && old != nil {
				t.Error("an answer kept for the old network after it changed")
			}
			// the new one's answer is what is given from now on
			if ip := firstIP(ask(t, s, "example.com", 3)); ip != "192.0.2.2" {
				t.Errorf("kept for the new %s: %s", change, ip)
			}
		})
	}
}
