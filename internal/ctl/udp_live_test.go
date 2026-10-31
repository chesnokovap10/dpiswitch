package ctl

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLiveUDPPeers(t *testing.T) {
	parent := "12345678-1234-4321-9876-123456789abc"
	peer := parent + "-12345678-1234-4321-9876-123456789abd"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("udp") != "peers" {
			t.Error("Live did not request detailed counters")
		}
		fmt.Fprintf(w, `{"connections":[{"id":%q,"peerID":%q,"udpAssociation":%q,"download":100,"upload":20,"metadata":{"network":"udp","destinationIP":"192.0.2.1","destinationPort":"1234"}}]}`, parent, peer, parent)
	}))
	defer srv.Close()
	c := NewLiveClient(strings.TrimPrefix(srv.URL, "http://"), "")
	defer c.Release()
	x, err := c.Connections()
	if err != nil || len(x.Conns) != 1 {
		t.Fatalf("%+v %v", x, err)
	}
	r := x.Conns[0]
	if r.ID != peer || r.UDPAssociation != parent || r.Download != 100 || r.DstIP != "192.0.2.1" {
		t.Fatalf("bad peer: %+v", r)
	}
}
