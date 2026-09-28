package ctl

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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
