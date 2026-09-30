package supervisor

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Each tunnel is asked until it answers, and no more after; one that never
// does is given up at warmFor; the core's end stops it at once.
func TestWarmTunnels(t *testing.T) {
	oldCheck, oldFor, oldEvery := warmCheck, warmFor, warmEvery
	t.Cleanup(func() { warmCheck, warmFor, warmEvery = oldCheck, oldFor, oldEvery })
	warmEvery = time.Millisecond

	var mu sync.Mutex
	asked := map[string]int{}
	upAfter := map[string]int{"awg": 3, "awg2": 1, "dead": 1 << 30}
	warmCheck = func(_ *healthChecker, name string) (bool, string) {
		mu.Lock()
		defer mu.Unlock()
		asked[name]++
		return asked[name] >= upAfter[name], ""
	}

	warmFor = 200 * time.Millisecond
	warmTunnels(context.Background(), nil, []string{"awg", "awg2", "dead"})
	if asked["awg"] != 3 || asked["awg2"] != 1 {
		t.Errorf("asked %v: awg 3 times and awg2 once, each until it answered", asked)
	}
	if asked["dead"] < 3 {
		t.Errorf("a tunnel that never answers asked %d times: kept at it until warmFor", asked["dead"])
	}

	// the core gone: done at once, however long warmFor is
	warmFor = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { warmTunnels(ctx, nil, []string{"dead"}); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("warmTunnels outlived its core")
	}
}
