package dnscache

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
	"time"

	"dpiswitch/internal/paths"
	"dpiswitch/internal/probe"
)

// The cache against this machine's own direct servers, through the running
// core's direct listener, as the service runs it: how long each server takes,
// a name the cache has not, and one it has -- asked over UDP as the core
// asks, and in-process as the detector does. Run with DPISWITCH_LIVE_DNS=1
// on a machine whose service runs.
func TestLiveCache(t *testing.T) {
	if os.Getenv("DPISWITCH_LIVE_DNS") == "" {
		t.Skip("asks the real servers through the running core: DPISWITCH_LIVE_DNS=1")
	}
	// the settings and the listener's password as the service has them --
	// read here: ctl imports this package
	var set struct {
		DirectDNS []string `json:"direct_dns"`
	}
	if b, err := os.ReadFile(paths.Settings()); err != nil || json.Unmarshal(b, &set) != nil || len(set.DirectDNS) == 0 {
		t.Fatalf("no direct servers in %s: %v", paths.Settings(), err)
	}
	cfg, err := os.ReadFile(paths.Config())
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^secret:\s*'?"?([^'"\r\n]+)`).FindSubmatch(cfg)
	if m == nil {
		t.Fatal("no secret in the config")
	}
	d := probe.Dialer{Addr: "127.0.0.1:7892", Timeout: 4 * time.Second, Pass: string(m[1])}
	names := []string{"ya.ru", "vk.com", "mail.ru", "ozon.ru", "avito.ru", "habr.com", "github.com", "wikipedia.org",
		"stackoverflow.com", "microsoft.com", "apple.com", "dzen.ru", "rutube.ru", "kinopoisk.ru", "gosuslugi.ru",
		"sberbank.ru", "wildberries.ru", "lenta.ru", "rbc.ru", "pikabu.ru"}
	ms := func(d time.Duration) string { return fmt.Sprintf("%.3f", float64(d.Nanoseconds())/1e6) }
	median := func(ds []time.Duration) time.Duration {
		slices.Sort(ds)
		return ds[len(ds)/2]
	}

	t.Logf("direct servers: %v", set.DirectDNS)
	for _, r := range Usable(set.DirectDNS) {
		var cold, warm []time.Duration
		for i, n := range names {
			q := query(n, uint16(i))
			start := time.Now()
			if _, err := r.Exchange(d, q); err != nil {
				t.Logf("  %s %s: %v", r.Raw, n, err)
				continue
			}
			cold = append(cold, time.Since(start))
			start = time.Now()
			if _, err := r.Exchange(d, q); err == nil {
				warm = append(warm, time.Since(start))
			}
		}
		if len(cold) > 0 && len(warm) > 0 {
			t.Logf("server %-36s first ask %7s ms, asked again %7s ms (median of %d)", r.Raw, ms(median(cold)), ms(median(warm)), len(warm))
		}
	}

	old := listenAddr
	listenAddr = "127.0.0.1:0"
	defer func() { listenAddr = old }()
	s := New(filepath.Join(t.TempDir(), "cache.json"), "")
	s.Configure(set.DirectDNS, d)
	s.SetNetwork("live")
	if err := s.Serve(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	addr := Serving()

	// as the core asks: a socket of its own for each query
	overUDP := func(q []byte) (time.Duration, error) {
		start := time.Now()
		c, err := net.Dial("udp", addr)
		if err != nil {
			return 0, err
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(q); err != nil {
			return 0, err
		}
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		if err != nil {
			return 0, err
		}
		if n < 12 || buf[3]&0x0f != 0 {
			return 0, fmt.Errorf("rcode %d", buf[3]&0x0f)
		}
		return time.Since(start), nil
	}
	var miss []time.Duration
	for i, n := range names {
		took, err := overUDP(query(n, uint16(100+i)))
		if err != nil {
			t.Logf("  miss %s: %v", n, err)
			continue
		}
		miss = append(miss, took)
	}
	// a name kept takes less than Windows' clock tells apart (half a
	// millisecond and more): a thousand are timed together
	const rounds = 50
	start := time.Now()
	for range rounds {
		for i, n := range names {
			if _, err := overUDP(query(n, uint16(200+i))); err != nil {
				t.Fatalf("kept %s: %v", n, err)
			}
		}
	}
	hitUDP := time.Since(start) / time.Duration(rounds*len(names))
	start = time.Now()
	for r := range rounds {
		for i, n := range names {
			if _, err := s.Exchange(query(n, uint16(r*len(names)+i))); err != nil {
				t.Fatal(err)
			}
		}
	}
	hitIn := time.Since(start) / time.Duration(rounds*len(names))
	st := s.stats()
	t.Logf("cache: a name not kept %s ms (median of %d); a name kept over UDP %s ms, in-process %s ms (mean of %d)",
		ms(median(miss)), len(miss), ms(hitUDP), ms(hitIn), rounds*len(names))
	for _, sv := range st.Servers {
		t.Logf("  the cache's measure of %-36s %6.2f ms, %d failed in a row", sv.Addr, sv.Ms, sv.Fails)
	}
	t.Logf("  counts %+v", st.Counts)
}
