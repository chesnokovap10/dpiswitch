//go:build routing

package awgconf

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
)

// TestCoreSecondSwitch: the second tunnel switched off and on again in the
// settings, on the real core with both tunnels alive and traffic flowing
// (the peers as in TestCoreTables), the way the service does it: the lists'
// files synced, the config built anew, the core stopped and started on it.
//
//   - on: an address of the awg2 list streams through awg2, a preset's name
//     goes there, the rest through awg1.
//   - off: the stream ends the moment the old core does; the new core knows
//     no awg2, the same address streams through awg1, the preset's name and
//     the list's go as the rest -- and not one packet reaches the second
//     server: the tunnel is down, not idle behind the rules.
//   - on again: as at first, the stream back through awg2.
//
// Each tunnel's server stands behind a tap that counts what the core sends
// it: the route a stream took is the tap its packets went through.
//
//	go test -tags routing -run TestCoreSecondSwitch ./internal/awgconf
func TestCoreSecondSwitch(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the core three times")
	}
	core := coreBinary(t)
	peer := buildPeer(t)
	setupRouting(t, ctl.ModeOn, "both on")

	taps := map[string]*udpTap{}
	for _, tn := range []string{"awg1", "awg2"} {
		path, addr := paths.SourceConf(), "10.8.1.3/32"
		if tn == "awg2" {
			path, addr = paths.SourceConf2(), "10.9.1.3/32"
		}
		cPriv, cPub := wgKeys(t)
		sPriv, sPub := wgKeys(t)
		taps[tn] = newUDPTap(t, startPeer(t, peer, sPriv, cPub))
		conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:%d\n",
			b64(cPriv), addr, b64(sPub), taps[tn].port)
		if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// an address in the awg2 list: a stream to it needs no name resolved
	stream := [4]byte{203, 0, 113, 9}
	if err := os.WriteFile(paths.User(paths.Awg2List), []byte(hostAwg2+"\n203.0.113.9\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// start: the config as the service builds it before every start of the
	// core, and the core on it
	type run struct {
		ctrl  *coreAPI
		log   *coreLog
		socks int
		stop  func()
		cfg   string
	}
	start := func() run {
		t.Helper()
		EnsureLists()
		ctl.SyncUserFiles()
		c, err := ParseFile(paths.SourceConf())
		if err != nil {
			t.Fatal(err)
		}
		out, err := c.Render()
		if err != nil {
			t.Fatal(err)
		}
		out = strings.ReplaceAll(out, "    timeout: 15000\n", "    timeout: 3000\n")
		socks, api := freePort(t), freePort(t)
		ls := fmt.Sprintf("listeners:\n  - name: in-rules\n    type: socks\n    listen: 127.0.0.1\n    port: %d\n", socks)
		ctrl, log, stop := runCore(t, core, coreSafe(t, out, ls, api, freePort(t)), api)
		return run{ctrl, log, socks, stop, out}
	}
	up := func(r run, tunnels ...string) {
		t.Helper()
		for _, tn := range tunnels {
			deadline := time.Now().Add(20 * time.Second)
			for {
				if alive, checked := r.ctrl.alive(tn, ctl.HealthURL); checked && alive {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("%s did not come up", tn)
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
	route := func(r run, host string) string {
		t.Helper()
		socksDialHost(r.socks, host, 80)
		_, target := routedBy(t, r.log, host)
		got, _ := r.ctrl.resolve(target)
		return got
	}
	has2 := func(r run) bool {
		var p map[string]any
		return r.ctrl.get("/proxies/awg2", &p) == nil
	}
	// the switch as the UI saves it and the service takes it: the settings
	// say the core must be restarted, the lists' files follow at once
	sw := func(on bool) {
		t.Helper()
		was := ctl.LoadSettings(paths.Settings())
		now, err := ctl.UpdateSettings(paths.Settings(), func(s *ctl.Settings) error { s.SecondTunnel = on; return nil })
		if err != nil {
			t.Fatal(err)
		}
		if now.SameCore(was) {
			t.Fatalf("second tunnel %v -> %v with its .conf loaded: no core restart asked", was.SecondTunnel, on)
		}
		ctl.SyncUserFiles()
	}
	// through: the stream flows, and by which tunnel's server
	through := func(s *zeroStream, want string) {
		t.Helper()
		other := map[string]string{"awg1": "awg2", "awg2": "awg1"}[want]
		taps[want].reset()
		taps[other].reset()
		got := s.bytes.Load()
		deadline := time.Now().Add(5 * time.Second)
		for s.bytes.Load() < got+1<<20 {
			if time.Now().After(deadline) || s.ended() {
				t.Fatalf("the stream does not flow: %d bytes, ended %v", s.bytes.Load()-got, s.ended())
			}
			time.Sleep(20 * time.Millisecond)
		}
		// the acknowledgements of a megabyte, against the other's keepalives
		if w, o := taps[want].pkts.Load(), taps[other].pkts.Load(); w < 50 || o > w/10 {
			t.Errorf("the stream should go through %s: %d packets to its server, %d to %s's", want, w, o, other)
		}
	}
	// restart: the old core stopped, a stream held through it must end at
	// once; then the new core on the config built anew
	restart := func(old run, s *zeroStream) run {
		t.Helper()
		at := time.Now()
		old.stop()
		select {
		case <-s.done:
			t.Logf("the stream held through the old core ended %d ms after its stop", time.Since(at).Milliseconds())
		case <-time.After(2 * time.Second):
			t.Error("a stream held through the old core is still open 2 s after it stopped")
		}
		return start()
	}

	// --- on
	a := start()
	up(a, "awg1", "awg2")
	if !has2(a) {
		t.Fatal("switched on: the core has no awg2")
	}
	if got := route(a, hostPreset); got != "awg2" {
		t.Errorf("switched on: a preset's name goes %s", got)
	}
	if got := route(a, hostUnnamed); got != "awg1" {
		t.Errorf("switched on: what no list names goes %s", got)
	}
	s1 := openZeros(t, a.socks, stream)
	through(s1, "awg2")

	// --- off
	sw(false)
	taps["awg2"].reset()
	began := time.Now()
	b := restart(a, s1)
	if strings.Contains(b.cfg, "awg2\n") || strings.Contains(b.cfg, "probe-tunnel2") {
		t.Error("switched off: the config still has awg2")
	}
	up(b, "awg1")
	if has2(b) {
		t.Error("switched off: the core still has awg2")
	}
	if got := Tunnels(); len(got) != 1 || got[0] != "awg1" {
		t.Errorf("switched off: tunnels %v", got)
	}
	s2 := openZeros(t, b.socks, stream)
	taps["awg2"].reset() // what the old core sent on its way down
	through2 := func() {
		got := s2.bytes.Load()
		deadline := time.Now().Add(5 * time.Second)
		for s2.bytes.Load() < got+1<<20 {
			if time.Now().After(deadline) || s2.ended() {
				t.Fatalf("switched off: the stream does not flow through awg1")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	through2()
	t.Logf("switched off: the stream flows through awg1 %d ms after the switch", time.Since(began).Milliseconds())
	for _, h := range []string{hostPreset, hostAwg2, hostUnnamed} {
		if got := route(b, h); got != "awg1" {
			t.Errorf("switched off: %s goes %s, want awg1", h, got)
		}
	}
	// down, not idle: the groups' checks, a keepalive, a handshake would
	// all have reached the second server within these seconds
	time.Sleep(6 * time.Second)
	if n := taps["awg2"].pkts.Load(); n != 0 {
		t.Errorf("switched off: %d packets sent to the second tunnel's server", n)
	}
	if taps["awg1"].pkts.Load() == 0 {
		t.Error("switched off: nothing sent to the first tunnel's server either: the taps do not count")
	}

	// --- on again
	sw(true)
	began = time.Now()
	c := restart(b, s2)
	up(c, "awg1", "awg2")
	if !has2(c) {
		t.Fatal("switched on again: the core has no awg2")
	}
	s3 := openZeros(t, c.socks, stream)
	through(s3, "awg2")
	t.Logf("switched on again: the stream flows through awg2 %d ms after the switch", time.Since(began).Milliseconds())
	if got := route(c, hostPreset); got != "awg2" {
		t.Errorf("switched on again: a preset's name goes %s", got)
	}
	if got := route(c, hostUnnamed); got != "awg1" {
		t.Errorf("switched on again: what no list names goes %s", got)
	}
	s3.close()
}

// runCore: startCore with the way to stop the core before the test ends,
// as the service stops one it restarts
func runCore(t *testing.T, core, cfg string, api int) (*coreAPI, *coreLog, func()) {
	t.Helper()
	secret := regexp.MustCompile(`(?m)^secret: '([^']*)'`).FindStringSubmatch(cfg)
	if secret == nil {
		t.Fatal("no secret in the config")
	}
	if err := os.WriteFile(paths.Config(), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	log := &coreLog{}
	cmd := exec.Command(core, "-d", paths.DataDir(), "-f", paths.Config())
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cmd.Process.Kill()
			cmd.Wait()
		})
	}
	t.Cleanup(func() {
		stop()
		if t.Failed() {
			t.Logf("the core's log:\n%s", log.String())
		}
	})
	ctrl := &coreAPI{base: fmt.Sprintf("http://127.0.0.1:%d", api), secret: secret[1]}
	if !ctrl.wait(15 * time.Second) {
		t.Fatal("the core did not come up")
	}
	return ctrl, log, stop
}

// udpTap: a tunnel's server as the core reaches it -- a UDP relay in front
// of the peer that counts what the core sends
type udpTap struct {
	port int
	pkts atomic.Int64
}

func (u *udpTap) reset() { u.pkts.Store(0) }

func newUDPTap(t *testing.T, target int) *udpTap {
	t.Helper()
	in, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	out, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: target})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); out.Close() })
	u := &udpTap{port: in.LocalAddr().(*net.UDPAddr).Port}
	// the core's socket, as last heard from: a core started anew has another
	var client atomic.Pointer[net.UDPAddr]
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := in.ReadFromUDP(buf)
			if err != nil {
				return
			}
			client.Store(from)
			u.pkts.Add(1)
			out.Write(buf[:n])
		}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := out.Read(buf)
			if err != nil {
				if strings.Contains(err.Error(), "closed") {
					return
				}
				// the peer not there yet, or gone: Windows says so on the
				// next read
				time.Sleep(10 * time.Millisecond)
				continue
			}
			if to := client.Load(); to != nil {
				in.WriteToUDP(buf[:n], to)
			}
		}
	}()
	return u
}

// zeroStream: a download that never ends -- the peers send zeros from port
// 19 of any address until the client goes -- read for as long as it flows
type zeroStream struct {
	c     net.Conn
	bytes atomic.Int64
	done  chan struct{}
}

func (s *zeroStream) ended() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (s *zeroStream) close() { s.c.Close() }

func openZeros(t *testing.T, socksPort int, ip [4]byte) *zeroStream {
	t.Helper()
	c, err := socksConnect(socksPort, ip, 19)
	if err != nil {
		t.Fatalf("no stream through the core: %v", err)
	}
	c.SetDeadline(time.Time{})
	s := &zeroStream{c: c, done: make(chan struct{})}
	t.Cleanup(s.close)
	go func() {
		defer close(s.done)
		buf := make([]byte, 64<<10)
		for {
			n, err := c.Read(buf)
			s.bytes.Add(int64(n))
			if err != nil {
				// closed, or reset by the core going away: the end all the same
				return
			}
		}
	}()
	return s
}
