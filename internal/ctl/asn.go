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

// asnCacheTTL: how often to look up the ISP behind the same gateway anew.
const asnCacheTTL = time.Hour

// ipRecheck: how often the public address behind the same gateway is
// checked. The router may have been switched to another uplink with the
// gateway and its MAC the same: the ISP was only looked up again after
// asnCacheTTL, and for up to an hour the old ISP's verdicts sent names
// direct on the new one, where they may be blocked. The address changes with
// the uplink, and asking for it is one small request: a changed one has the
// ISP looked up at once.
const ipRecheck = 5 * time.Minute

type attachment struct {
	Net     string    `json:"net"` // AS12389
	Checked time.Time `json:"checked"`
	// the public address of the direct path the ISP was found by, and when
	// it was last seen the same
	IP        string    `json:"ip,omitempty"`
	IPChecked time.Time `json:"ip_checked,omitempty"`
}

// directClient: requests over the DIRECT path. Through the tunnel the answer
// would be the VPS provider's.
func directClient(directAddr string) *http.Client {
	return &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{
			Scheme: "socks5", Host: directAddr})},
	}
}

// publicIP: the public address of the direct path.
func publicIP(cl *http.Client) (string, error) {
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
	return ip.Data.IP, nil
}

// lookupASN finds the ISP from the public address of the DIRECT path, and
// says the address too.
func lookupASN(directAddr string) (asn, ip string, err error) {
	cl := directClient(directAddr)
	if ip, err = publicIP(cl); err != nil {
		return "", "", err
	}
	var info struct {
		Data struct {
			ASNs []string `json:"asns"`
		} `json:"data"`
	}
	if err := getJSON(cl, "https://stat.ripe.net/data/network-info/data.json?resource="+
		url.QueryEscape(ip), &info); err != nil {
		return "", "", fmt.Errorf("ISP: %w", err)
	}
	if len(info.Data.ASNs) == 0 {
		return "", "", fmt.Errorf("ISP unknown for %s", ip)
	}
	return "AS" + info.Data.ASNs[0], ip, nil
}

// the lookups, for the tests to script
var (
	lookupASNFn = lookupASN
	publicIPFn  = func(directAddr string) (string, error) { return publicIP(directClient(directAddr)) }
)

// lookupRetry: the wait between lookups that failed; the tests shorten it
var lookupRetry = 5 * time.Second

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
		if cached.IP != "" && time.Since(cached.IPChecked) < ipRecheck {
			return cached.Net
		}
		ip, err := publicIPFn(cfg.DirectAddr)
		switch {
		case err != nil:
			// not known to have changed: the next tick asks again
			return cached.Net
		case ip == cached.IP:
			st.sawIP(att)
			return cached.Net
		}
		if cached.IP != "" {
			log.Printf("public address changed behind the same gateway: %s -> %s, looking up the ISP",
				cached.IP, ip)
		}
	}

	var asn, ip string
	var err error
	for i := 0; i < 3; i++ {
		if asn, ip, err = lookupASNFn(cfg.DirectAddr); err == nil {
			break
		}
		time.Sleep(lookupRetry)
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
	if ok && cached.Net != asn {
		log.Printf("ISP changed behind the same gateway: %s -> %s", cached.Net, asn)
	}
	st.attach(att, asn, ip)
	if n := st.mergeInto(asn); n > 0 {
		log.Printf("ISP %s: merged %d verdicts from previous gateway memory", asn, n)
	}
	return asn
}
