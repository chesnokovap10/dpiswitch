package ctl

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"dpiswitch/internal/paths"
	"dpiswitch/internal/probe"
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
			Scheme: "socks5", Host: directAddr, User: url.UserPassword(probe.SocksUser, socksPass())})},
	}
}

// socksPass: the prober's listeners' password -- the API's secret, see
// awgconf
var socksPass = func() string { return secretFromConfig(paths.Config()) }

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

// lookupBackoff: how long after the ISP could not be looked up behind a
// gateway the lookup is left alone. A lookup is three tries five seconds
// apart, two requests of up to eight seconds each: with RIPE out of reach
// the main loop spent most of every minute in it -- settings applied late,
// cycles held up -- and the next tick started it all over again.
var lookupBackoff = 10 * time.Minute

// ipBackoff: how long after the public address could not be checked behind
// a gateway the check is left alone. Failing, it was asked again at every
// tick -- up to eight seconds each, every ten seconds, the cycles held up
// while RIPE was out of reach.
var ipBackoff = time.Minute

// ipHeld: whether the address check behind att failed within ipBackoff
func (s *state) ipHeld(att string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	at, ok := s.ipFailed[att]
	return ok && time.Since(at) < ipBackoff
}

// ipDone notes how the address check behind att went
func (s *state) ipDone(att string, failed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !failed {
		delete(s.ipFailed, att)
		return
	}
	if s.ipFailed == nil {
		s.ipFailed = map[string]time.Time{}
	}
	s.ipFailed[att] = time.Now()
}

// lookupHeld: whether the lookup behind att failed within lookupBackoff
func (s *state) lookupHeld(att string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	at, ok := s.lookupFailed[att]
	return ok && time.Since(at) < lookupBackoff
}

// lookupDone notes how the lookup behind att went
func (s *state) lookupDone(att string, failed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !failed {
		delete(s.lookupFailed, att)
		return
	}
	if s.lookupFailed == nil {
		s.lookupFailed = map[string]time.Time{}
	}
	s.lookupFailed[att] = time.Now()
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
	if att == noNetwork {
		return att
	}
	cached, ok := st.attached(att)
	// the public address was seen to change: the cached ISP is not known
	// to be the one behind it any more
	moved := false
	if ok && time.Since(cached.Checked) < asnCacheTTL {
		if cached.IP != "" && time.Since(cached.IPChecked) < ipRecheck || st.ipHeld(att) {
			return cached.Net
		}
		ip, err := publicIPFn(cfg.DirectAddr)
		st.ipDone(att, err != nil)
		switch {
		case err != nil:
			// not known to have changed: asked again after ipBackoff
			return cached.Net
		case ip == cached.IP:
			st.sawIP(att)
			return cached.Net
		}
		if cached.IP != "" {
			moved = true
			log.Printf("public address changed behind the same gateway: %s -> %s, looking up the ISP",
				cached.IP, ip)
		}
	}

	if st.lookupHeld(att) {
		// failed a moment ago: what the failure below answers, without
		// the minute it takes
		if ok && !moved {
			return cached.Net
		}
		return att
	}
	var asn, ip string
	var err error
	for i := 0; i < 3; i++ {
		if asn, ip, err = lookupASNFn(cfg.DirectAddr); err == nil {
			break
		}
		time.Sleep(lookupRetry)
	}
	st.lookupDone(att, err != nil)
	if err != nil {
		if ok && !moved {
			// the ISP behind this gateway is already known, it just failed
			// to re-check -- keep using it
			return cached.Net
		}
		// With the address changed the old ISP is not kept "just in case":
		// its CLEAN verdicts would send names direct on what may be another
		// ISP. The gateway's own memory until the lookup succeeds -- the next
		// tick tries again, the address still differing from the cached one.
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

// ipStillRecheck: how old the last look at the public address may be before
// a cycle's results are filed without looking again.
const ipStillRecheck = time.Minute

// ipStill: whether the public address behind att is still the one the ISP
// was found by. The network guard sees the gateway only: behind the same
// router the uplink may change mid-cycle, and the cycle's results would go
// into the old ISP's memory. A cycle with results asks before filing them,
// at most once a minute. A changed address is marked for the main loop to
// look up the ISP at its next tick.
func ipStill(cfg Config, st *state, att string) bool {
	cached, ok := st.attached(att)
	if !ok || cached.IP == "" || time.Since(cached.IPChecked) < ipStillRecheck {
		return true
	}
	ip, err := publicIPFn(cfg.DirectAddr)
	switch {
	case err != nil:
		return true // not known to have changed
	case ip == cached.IP:
		st.sawIP(att)
		return true
	}
	st.staleIP(att)
	return false
}
