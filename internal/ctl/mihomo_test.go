package ctl

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A torrent client's thousands of connections are more than 4 MB of JSON:
// the answer was cut there, and the JSON cut short failed every cycle. It
// is read whole now; past the cap it is an error that says so.
func TestConnectionsLarge(t *testing.T) {
	conns := make([]map[string]any, 12000)
	for i := range conns {
		conns[i] = map[string]any{"id": fmt.Sprintf("%036d", i), "chains": []string{"DIRECT"},
			"rule": "Match", "start": "2026-09-28T20:00:00Z",
			"metadata": map[string]any{"host": fmt.Sprintf("peer%d.example.org", i),
				"destinationIP": "192.0.2.1", "destinationPort": "51413", "network": "tcp",
				"process": "qbittorrent.exe", "processPath": `C:\Program Files\qBittorrent\qbittorrent.exe`,
				"sourceIP": "198.18.0.1", "sourcePort": "50000", "type": "Tun", "inboundName": "DEFAULT-TUN"}}
	}
	body, err := json.Marshal(map[string]any{"connections": conns})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) <= 4<<20 {
		t.Fatalf("setup: %d bytes, not past the old cap", len(body))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()
	// the answer read only up to the cap leaves the server writing the
	// rest, and under wine that write never gives up: Close waited forever
	defer srv.CloseClientConnections()
	a := newAPI(strings.TrimPrefix(srv.URL, "http://"), "")
	got, err := a.connections()
	if err != nil || len(got) != len(conns) {
		t.Fatalf("%d connections, %v", len(got), err)
	}

	old := maxBody
	maxBody = 1 << 20
	defer func() { maxBody = old }()
	if _, err := a.connections(); err == nil || !strings.Contains(err.Error(), "larger than 1 MB") {
		t.Fatalf("an answer past the cap: %v", err)
	}
}

// A client that asks for as long as the service runs reads the secret again
// when the core refuses the one it holds -- a config written anew has
// another -- and asks once more, the body sent again. One made for a moment
// does not: its caller has just read the secret.
func TestAPIRenewsSecret(t *testing.T) {
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		if r.Header.Get("Authorization") != "Bearer new" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"connections":[]}`))
	}))
	defer srv.Close()
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfg, []byte("mode: rule\nsecret: 'new'\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	short := newAPI(strings.TrimPrefix(srv.URL, "http://"), "old")
	if _, err := short.connections(); err == nil {
		t.Fatal("a client made for a moment read the secret again")
	}

	a := newAPI(strings.TrimPrefix(srv.URL, "http://"), "old")
	a.cfgPath = cfg
	bodies = nil
	if _, err := a.do("PUT", "/proxies/g", strings.NewReader(`{"name":"x"}`)); err != nil {
		t.Fatalf("not asked again with the new secret: %v", err)
	}
	if len(bodies) != 2 || bodies[1] != `{"name":"x"}` {
		t.Fatalf("the bodies the core got: %q", bodies)
	}
	// the config holding the very secret refused: nothing new to try
	stale := "stale"
	a.secret.Store(&stale)
	os.WriteFile(cfg, []byte("secret: 'stale'\n"), 0o644)
	bodies = nil
	if _, err := a.connections(); err == nil || len(bodies) != 1 {
		t.Fatalf("the same secret: %v, %d requests", err, len(bodies))
	}
	// one more try with the one read, refused too: no loop
	os.WriteFile(cfg, []byte("secret: 'other'\n"), 0o644)
	bodies = nil
	if _, err := a.connections(); err == nil || len(bodies) != 2 {
		t.Fatalf("another refused secret: %v, %d requests", err, len(bodies))
	}
}
