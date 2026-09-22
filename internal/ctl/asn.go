package ctl

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"
)

// Verdict memory is keyed by the ISP (autonomous system number), not by
// the point of connection.
//
// Blocking is done by the ISP, so verdicts hold equally for any router and
// band within its network. The key used to be the gateway and its MAC, and
// switching between 2.4 and 5 GHz of one router counted as a new network:
// memory started from scratch and every site went into the tunnel for a while.
//
// The gateway remains the "attachment address": it shows that the network
// changed, and the discovered ISP is cached by it.

// asnCacheTTL: how often to re-check the ISP behind the same gateway
// (the router may have been switched to another uplink)
const asnCacheTTL = 24 * time.Hour

type attachment struct {
	Net     string    `json:"net"` // AS12389
	Checked time.Time `json:"checked"`
}

// lookupASN finds the ISP from the public address of the DIRECT path.
// Through the tunnel the answer would be the VPS provider.
func lookupASN(directAddr string) (string, error) {
	cl := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{
			Scheme: "socks5", Host: directAddr})},
	}
	var ip struct {
		Data struct {
			IP string `json:"ip"`
		} `json:"data"`
	}
	if err := getJSON(cl, "https://stat.ripe.net/data/whats-my-ip/data.json", &ip); err != nil {
		return "", fmt.Errorf("public address: %w", err)
	}
	if ip.Data.IP == "" {
		return "", errors.New("public address not received")
	}
	var info struct {
		Data struct {
			ASNs []string `json:"asns"`
		} `json:"data"`
	}
	if err := getJSON(cl, "https://stat.ripe.net/data/network-info/data.json?resource="+
		url.QueryEscape(ip.Data.IP), &info); err != nil {
		return "", fmt.Errorf("ISP: %w", err)
	}
	if len(info.Data.ASNs) == 0 {
		return "", fmt.Errorf("ISP unknown for %s", ip.Data.IP)
	}
	return "AS" + info.Data.ASNs[0], nil
}

func getJSON(cl *http.Client, u string, v any) error {
	resp, err := cl.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// resolveNetwork: the memory key for the current connection.
//
// If the ISP cannot be determined (network still coming up, RIPE
// unreachable) we work under the gateway key as before and retry next cycle.
// Borrowing the previous ISP's verdicts "just in case" is not allowed: on a
// foreign network a false "clean" breaks sites.
func resolveNetwork(cfg Config, st *state) string {
	att := networkID()
	if att == "unknown" {
		return att
	}
	cached, ok := st.attached(att)
	if ok && time.Since(cached.Checked) < asnCacheTTL {
		return cached.Net
	}

	var asn string
	var err error
	for i := 0; i < 3; i++ {
		if asn, err = lookupASN(cfg.DirectAddr); err == nil {
			break
		}
		time.Sleep(5 * time.Second)
	}
	if err != nil {
		if ok {
			// the ISP behind this gateway is already known, it just failed
			// to re-check -- keep using it
			return cached.Net
		}
		log.Printf("ISP not determined (%v), using gateway memory %s", err, att)
		return att
	}
	st.attach(att, asn)
	if n := st.mergeInto(asn); n > 0 {
		log.Printf("ISP %s: merged %d verdicts from previous gateway memory", asn, n)
	}
	return asn
}
