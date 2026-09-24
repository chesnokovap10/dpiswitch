package supervisor

import (
	"context"
	"testing"
	"time"
)

// A request still pending when a poll looks at the context is waited for
// further, not dropped for a new one; when the context ends it is cancelled,
// and let go only once the cancellation has completed.
func TestAddrWaitOutlivesPolls(t *testing.T) {
	old := ctxPollMs
	ctxPollMs = 20
	defer func() { ctxPollMs = old }()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	fired, err := waitAddrChange(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if fired {
		t.Skip("an address changed during the test")
	}
	if d := time.Since(start); d < 250*time.Millisecond {
		t.Fatalf("returned after %v, at a poll, with the request pending", d)
	}
	abandonedMu.Lock()
	n := len(abandoned)
	abandonedMu.Unlock()
	if n != 0 {
		t.Fatalf("%d requests abandoned: the cancellation did not complete", n)
	}
}

// The watch ends with its context.
func TestAddrWatchEnds(t *testing.T) {
	old := ctxPollMs
	ctxPollMs = 20
	defer func() { ctxPollMs = old }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { watchNetworkChanges(ctx, func() {}); close(done) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the watch did not end with its context")
	}
}
