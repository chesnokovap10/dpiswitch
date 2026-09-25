// uidev serves the web UI on a fixed port without the tray, for working on
// the pages: go run ./tools/uidev [-addr 127.0.0.1:8766]. Set ProgramData to
// a copy of the data directory to click around without touching the real
// settings -- the service and the core it talks to are still the real ones.
package main

import (
	"flag"
	"log"
	"net/http"

	"dpiswitch/internal/webui"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8766", "listen address")
	flag.Parse()
	s := &webui.Server{}
	log.Printf("UI on http://%s/", *addr)
	log.Fatal(http.ListenAndServe(*addr, s.Handler()))
}
