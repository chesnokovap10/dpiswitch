// famrec: a dry run of service families -- which page a CDN serves, so the
// page and its media hosts could go one way (see ctl/inherit.go: a media
// URL is signed for the address the page came from). Routing is left alone.
//
//	famrec [record] [-dir d]     the core's connections, opened and closed,
//	                            one JSON line each, a file a day
//	famrec analyze [-dir d]     the families the records show
//
// The analysis, three steps:
//  1. a CDN is a domain (eTLD+1) of many short-lived hosts -- googlevideo.com
//     a new rrN---sn-... for every track;
//  2. its clients are the domains its own certificate names (fetched through
//     the tunnel's listener);
//  3. its page is the domain open in the same process when a new host of it
//     appears, far more often than that domain is open at all (lift).
//
// Step 2 is shown apart: a CDN of another operator names no client in its
// certificate, and only step 3 is left.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/proxy"
	"golang.org/x/net/publicsuffix"
)

const dataDir = `C:\ProgramData\dpiswitch`

func main() {
	// no arguments: record -- so explorer.exe can start it outside a
	// session that would take it down on its way out
	if len(os.Args) < 2 {
		os.Args = append(os.Args, "record")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	dir := fs.String("dir", `D:\2\mihomo\cap\famrec`, "where the records are")
	cfg := fs.String("config", filepath.Join(dataDir, "config.yaml"), "the core's config: controller, secret, listener password")
	every := fs.Duration("every", 250*time.Millisecond, "record: how often the connections are read")
	minHosts := fs.Int("hosts", 10, "analyze: a CDN has at least this many hosts")
	window := fs.Duration("window", 10*time.Second, "analyze: a page opened this long before a new host counts as open")
	certs := fs.Bool("certs", true, "analyze: fetch the CDNs' certificates through the tunnel")
	fs.Parse(os.Args[2:])
	c, err := readCore(*cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	switch os.Args[1] {
	case "record":
		err = record(c, *dir, *every)
	case "analyze":
		err = analyze(c, *dir, *minHosts, *window, *certs)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type core struct{ controller, secret, password string }

// readCore: the controller, its secret and the listeners' password, from
// the config the service wrote
func readCore(path string) (core, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return core{}, err
	}
	val := func(key string) string {
		m := regexp.MustCompile(`(?m)^\s*` + key + `:\s*['"]?([^'"\r\n]+)`).FindSubmatch(raw)
		if m == nil {
			return ""
		}
		return strings.TrimSpace(string(m[1]))
	}
	c := core{controller: val("external-controller"), secret: val("secret"), password: val("password")}
	if c.controller == "" {
		return c, fmt.Errorf("%s: no external-controller", path)
	}
	return c, nil
}

// event: one line of the record
type event struct {
	Ev    string    `json:"ev"` // open, close, alive
	T     time.Time `json:"t"`
	ID    string    `json:"id,omitempty"`
	Host  string    `json:"host,omitempty"`
	IP    string    `json:"ip,omitempty"`
	Port  string    `json:"port,omitempty"`
	Net   string    `json:"net,omitempty"`
	Proc  string    `json:"proc,omitempty"`
	Chain string    `json:"chain,omitempty"`
	Rule  string    `json:"rule,omitempty"`
	Down  int64     `json:"down,omitempty"`
}

type conn struct {
	ID       string   `json:"id"`
	Chains   []string `json:"chains"`
	Download int64    `json:"download"`
	Rule     string   `json:"rule"`
	Payload  string   `json:"rulePayload"`
	Metadata struct {
		Host     string `json:"host"`
		Sniff    string `json:"sniffHost"`
		DstIP    string `json:"destinationIP"`
		DstPort  string `json:"destinationPort"`
		Network  string `json:"network"`
		Process  string `json:"process"`
		Inbound  string `json:"inboundName"`
		RemoteDs string `json:"remoteDestination"`
	} `json:"metadata"`
}

func record(c core, dir string, every time.Duration) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	cl := &http.Client{Timeout: 5 * time.Second}
	open := map[string]conn{}
	var f *os.File
	var w *bufio.Writer
	day := ""
	put := func(e event) {
		if d := e.T.Format("20060102"); d != day {
			if f != nil {
				w.Flush()
				f.Close()
			}
			var err error
			f, err = os.OpenFile(filepath.Join(dir, "famrec-"+d+".jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			w, day = bufio.NewWriter(f), d
		}
		b, _ := json.Marshal(e)
		w.Write(append(b, '\n'))
	}
	lastAlive := time.Time{}
	fmt.Printf("recording to %s every %s\n", dir, every)
	for {
		now := time.Now()
		var r struct {
			Connections []conn `json:"connections"`
		}
		req, _ := http.NewRequest("GET", "http://"+c.controller+"/connections", nil)
		req.Header.Set("Authorization", "Bearer "+c.secret)
		resp, err := cl.Do(req)
		if err == nil {
			err = json.NewDecoder(resp.Body).Decode(&r)
			resp.Body.Close()
		}
		if err != nil {
			// the core restarting: what was open is gone, the gap shows by
			// the missing alive lines
			time.Sleep(time.Second)
			continue
		}
		seen := map[string]bool{}
		for _, x := range r.Connections {
			// the prober's own connections, through its listeners
			if strings.HasPrefix(x.Metadata.Inbound, "probe-") {
				continue
			}
			seen[x.ID] = true
			if _, ok := open[x.ID]; ok {
				open[x.ID] = x
				continue
			}
			open[x.ID] = x
			host := x.Metadata.Host
			if host == "" {
				host = x.Metadata.Sniff
			}
			chain := ""
			if len(x.Chains) > 0 {
				chain = x.Chains[0]
			}
			put(event{Ev: "open", T: now, ID: x.ID, Host: strings.ToLower(host), IP: x.Metadata.DstIP, Port: x.Metadata.DstPort,
				Net: x.Metadata.Network, Proc: x.Metadata.Process, Chain: chain, Rule: strings.TrimSpace(x.Rule + " " + x.Payload)})
		}
		for id, x := range open {
			if !seen[id] {
				put(event{Ev: "close", T: now, ID: id, Down: x.Download})
				delete(open, id)
			}
		}
		if now.Sub(lastAlive) >= time.Minute {
			put(event{Ev: "alive", T: now})
			lastAlive = now
		}
		w.Flush()
		time.Sleep(every)
	}
}

// span: one connection, open to close
type span struct {
	host, fam, proc string
	from, to        time.Time
}

func famOf(host string) string {
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	f, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return f
}

func analyze(c core, dir string, minHosts int, window time.Duration, certs bool) error {
	files, _ := filepath.Glob(filepath.Join(dir, "famrec-*.jsonl"))
	if len(files) == 0 {
		return fmt.Errorf("no records in %s", dir)
	}
	sort.Strings(files)
	var spans []span
	var alive []time.Time
	for _, p := range files {
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		opened := map[string]*span{}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		var last time.Time
		for sc.Scan() {
			var e event
			if json.Unmarshal(sc.Bytes(), &e) != nil {
				continue
			}
			last = e.T
			switch e.Ev {
			case "open":
				if fam := famOf(e.Host); fam != "" {
					opened[e.ID] = &span{host: e.Host, fam: fam, proc: e.Proc, from: e.T}
				}
			case "close":
				if s := opened[e.ID]; s != nil {
					s.to = e.T
					spans = append(spans, *s)
					delete(opened, e.ID)
				}
			case "alive":
				alive = append(alive, e.T)
			}
		}
		f.Close()
		for _, s := range opened {
			s.to = last
			spans = append(spans, *s)
		}
	}
	if len(spans) == 0 {
		return fmt.Errorf("the records in %s hold no connection with a name", dir)
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].from.Before(spans[j].from) })
	// the recorded time: minutes with an alive line
	recorded := 0.0
	for i := 1; i < len(alive); i++ {
		if d := alive[i].Sub(alive[i-1]); d < 3*time.Minute {
			recorded += d.Hours()
		}
	}
	fmt.Printf("%d connections with a name, %.1f h recorded, %s .. %s\n\n", len(spans), recorded,
		spans[0].from.Format("02.01 15:04"), spans[len(spans)-1].from.Format("02.01 15:04"))

	// step 1: hosts per domain, and how short-lived they are -- a host whose
	// connections all fall within 30 min of its first is short-lived
	type hostSeen struct{ first, last time.Time }
	byFam := map[string]map[string]*hostSeen{}
	for _, s := range spans {
		m := byFam[s.fam]
		if m == nil {
			m = map[string]*hostSeen{}
			byFam[s.fam] = m
		}
		h := m[s.host]
		if h == nil {
			m[s.host] = &hostSeen{s.from, s.to}
			continue
		}
		if s.to.After(h.last) {
			h.last = s.to
		}
	}
	type cdn struct {
		fam          string
		hosts, short int
	}
	var cdns []cdn
	var all []cdn
	for fam, m := range byFam {
		short := 0
		for _, h := range m {
			if h.last.Sub(h.first) <= 30*time.Minute {
				short++
			}
		}
		x := cdn{fam, len(m), short}
		all = append(all, x)
		if len(m) >= minHosts && short*10 >= len(m)*7 {
			cdns = append(cdns, x)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].hosts > all[j].hosts })
	fmt.Println("step 1 -- domains by hosts (short-lived = all within 30 min):")
	for i, x := range all {
		if i >= 25 {
			break
		}
		mark := ""
		if x.hosts >= minHosts && x.short*10 >= x.hosts*7 {
			mark = "  <- CDN"
		}
		fmt.Printf("  %-28s %4d hosts, %3d%% short-lived%s\n", x.fam, x.hosts, 100*x.short/x.hosts, mark)
	}
	fmt.Println()

	// baseline: how often each domain is open in each process, sampled
	// every 10 s of the recorded time
	type key struct{ fam, proc string }
	var samples []time.Time
	for i := 1; i < len(alive); i++ {
		if alive[i].Sub(alive[i-1]) >= 3*time.Minute {
			continue
		}
		for t := alive[i-1]; t.Before(alive[i]); t = t.Add(10 * time.Second) {
			samples = append(samples, t)
		}
	}
	// each domain's connections in each process, for the baseline
	byKey := map[key][]span{}
	for _, s := range spans {
		k := key{s.fam, s.proc}
		byKey[k] = append(byKey[k], s)
	}
	openAt := func(t time.Time, k key) bool {
		for _, s := range byKey[k] {
			if s.from.After(t) {
				break
			}
			if s.to.After(t) || t.Sub(s.from) <= window {
				return true
			}
		}
		return false
	}
	activeAt := func(t time.Time, proc string) map[string]bool {
		out := map[string]bool{}
		for _, s := range spans {
			if s.from.After(t) {
				break
			}
			if (proc == "" || s.proc == proc) && (s.to.After(t) || t.Sub(s.from) <= window) {
				out[s.fam] = true
			}
		}
		return out
	}

	for _, x := range cdns {
		// step 3: the new hosts' first connections
		first := map[string]span{}
		for _, s := range spans {
			if s.fam != x.fam {
				continue
			}
			if _, ok := first[s.host]; !ok {
				first[s.host] = s
			}
		}
		hits := map[key]int{}
		for _, s := range first {
			// open just before it, in the same process; the CDN itself and
			// what opened at the very same instant (its own sibling hosts)
			for fam := range activeAt(s.from.Add(-time.Millisecond), s.proc) {
				if fam != x.fam {
					hits[key{fam, s.proc}]++
				}
			}
		}
		type cand struct {
			k              key
			n              int
			pEvent, pBase  float64
			lift           float64
			inCert, certOK bool
		}
		var cands []cand
		for k, n := range hits {
			if n < 3 {
				continue
			}
			base := 0
			for _, t := range samples {
				if openAt(t, k) {
					base++
				}
			}
			pb := (float64(base) + 1) / (float64(len(samples)) + 1)
			pe := float64(n) / float64(len(first))
			cands = append(cands, cand{k: k, n: n, pEvent: pe, pBase: pb, lift: pe / pb})
		}
		// step 2: the CDN's own certificate
		var certFams map[string]bool
		if certs {
			certFams = certFamilies(c, first)
		}
		for i := range cands {
			cands[i].certOK = certFams != nil
			cands[i].inCert = certFams[cands[i].k.fam]
		}
		sort.Slice(cands, func(i, j int) bool { return cands[i].lift > cands[j].lift })
		fmt.Printf("CDN %s: %d hosts", x.fam, len(first))
		if certFams != nil {
			fmt.Printf(", its certificate names %d domains", len(certFams))
		} else if certs {
			fmt.Print(", certificate not fetched")
		}
		fmt.Println()
		for i, cd := range cands {
			if i >= 15 {
				break
			}
			cert := ""
			switch {
			case cd.inCert:
				cert = "  in cert"
			case cd.certOK:
				cert = "  -"
			}
			fmt.Printf("  %-26s %-14s open at %3.0f%% of new hosts vs %3.0f%% of the time, lift %5.1f%s\n",
				cd.k.fam, cd.k.proc, 100*cd.pEvent, 100*cd.pBase, math.Round(cd.lift*10)/10, cert)
		}
		fmt.Println()
	}
	return nil
}

// certFamilies: the domains the CDN's certificate names, by the first of
// its hosts that answers through the tunnel's listener
func certFamilies(c core, hosts map[string]span) map[string]bool {
	var list []string
	for h := range hosts {
		list = append(list, h)
	}
	sort.Strings(list)
	auth := &proxy.Auth{User: "dpiswitch", Password: c.password}
	d, err := proxy.SOCKS5("tcp", "127.0.0.1:7891", auth, &net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		return nil
	}
	cd := d.(proxy.ContextDialer)
	for i, h := range list {
		if i >= 5 {
			break
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		raw, err := cd.DialContext(ctx, "tcp", net.JoinHostPort(h, "443"))
		if err != nil {
			cancel()
			continue
		}
		tc := tls.Client(raw, &tls.Config{ServerName: h, InsecureSkipVerify: true})
		err = tc.HandshakeContext(ctx)
		cancel()
		if err != nil {
			raw.Close()
			continue
		}
		out := map[string]bool{}
		for _, n := range tc.ConnectionState().PeerCertificates[0].DNSNames {
			if f := famOf(strings.TrimPrefix(n, "*.")); f != "" {
				out[f] = true
			}
		}
		tc.Close()
		return out
	}
	return nil
}
