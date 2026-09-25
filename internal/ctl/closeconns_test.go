package ctl

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// A list change closes the connections it moves, and never a probe's: those
// are routed by their listener, and closing one broke a check in progress.
func TestCloseConnsLeavesProbes(t *testing.T) {
	var mu sync.Mutex
	var closed []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Write([]byte(`{"connections":[
				{"id":"app","chains":["DIRECT"],"metadata":{"host":"a.example","sourceIP":"198.18.0.1"}},
				{"id":"probe","chains":["DIRECT"],"metadata":{"host":"a.example","sourceIP":"127.0.0.1","inboundName":"probe-direct"}}]}`))
		case http.MethodDelete:
			mu.Lock()
			closed = append(closed, strings.TrimPrefix(r.URL.Path, "/connections/"))
			mu.Unlock()
		}
	}))
	defer srv.Close()
	n, err := CloseConns(strings.TrimPrefix(srv.URL, "http://"), "", func(c Conn) bool { return c.Host == "a.example" })
	if err != nil || n != 1 || len(closed) != 1 || closed[0] != "app" {
		t.Fatalf("closed %v (%d, %v), want the application's only", closed, n, err)
	}
}

// A core that is not listening has nothing to reload: no error.
func TestReloadProvidersCoreDown(t *testing.T) {
	if err := ReloadProviders("127.0.0.1:1", "", "force-direct"); err != nil {
		t.Fatal(err)
	}
}
