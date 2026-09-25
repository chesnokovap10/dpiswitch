// uidev serves the web UI on a fixed port without the tray, for working on
// the pages: go run ./tools/uidev [-addr 127.0.0.1:8766]. Set ProgramData to
// a copy of the data directory to click around without touching the real
// settings -- the service and the core it talks to are still the real ones.
// The UI wants the same key as the tray's: open the address it prints.
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
	key, err := webui.LoadKey()
	if err != nil {
		log.Printf("key not kept: %v", err)
	}
	s := &webui.Server{Key: key}
	log.Printf("UI on %s", webui.WithKey("http://"+*addr+"/", key))
	log.Fatal(http.ListenAndServe(*addr, s.Handler()))
}
