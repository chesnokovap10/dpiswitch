package supervisor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestHelperCore is not a test: it stands in for the core, a process that
// runs until killed.
func TestHelperCore(t *testing.T) {
	if os.Getenv("DPISWITCH_HELPER_CORE") != "1" {
		return
	}
	time.Sleep(time.Minute)
	os.Exit(0)
}

func startHelperCore(t *testing.T) (*exec.Cmd, chan struct{}) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperCore$")
	cmd.Env = append(os.Environ(), "DPISWITCH_HELPER_CORE=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	t.Cleanup(func() { cmd.Process.Kill() })
	return cmd, done
}

// Restarts asked for at once -- the health check, a settings change, a
// second change -- stop the core once; one asked for after it is gone
// stops nothing.
func TestRestartsCoalesce(t *testing.T) {
	var offs atomic.Int32
	old := tunOff
	tunOff = func() error {
		offs.Add(1)
		time.Sleep(100 * time.Millisecond) // the window in which the others arrive
		return errors.New("test: no core API")
	}
	defer func() { tunOff = old }()

	s := New()
	cmd, done := startHelperCore(t)
	s.cmd, s.done = cmd, done

	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); s.restartCore() }()
	}
	wg.Wait()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the core was not stopped")
	}
	s.restartCore()
	if n := offs.Load(); n != 1 {
		t.Fatalf("TUN disabled %d times, want once", n)
	}
}

// The API is ready when it answers and takes the secret, not when the
// process merely runs.
func TestAPIReady(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path != "/version" || r.Header.Get("Authorization") != "Bearer s" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"version":"test"}`))
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	if apiReady(addr, "s") || apiReady(addr, "s") {
		t.Fatal("ready while the core answers 503")
	}
	if !apiReady(addr, "s") {
		t.Fatal("not ready once it answers")
	}
	if apiReady(addr, "wrong") {
		t.Fatal("ready with a secret the core refuses")
	}

	// waitAPI: a running process whose API never answers is not ready
	s := New()
	s.running.Store(true)
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "starting", http.StatusServiceUnavailable)
	}))
	defer dead.Close()
	if s.waitAPI(context.Background(), strings.TrimPrefix(dead.URL, "http://"), 1500*time.Millisecond) {
		t.Fatal("waitAPI took a running process for a ready API")
	}
}
