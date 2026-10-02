// Supervisor: keeps the mihomo core running and drives the controller.
// Used by the service; never runs on its own.
package supervisor

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"

	"dpiswitch/internal/awgconf"
	"dpiswitch/internal/core"
	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/winexec"
)

type Supervisor struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	done    chan struct{} // closed when the core has exited
	running atomic.Bool
	// planned: the core was stopped by restartCore, to come back at once --
	// not a crash, see corePause
	planned atomic.Bool
	recheck chan struct{} // request to check the tunnel right away
	job     windows.Handle
	// v6mu: the start of a core, which resets what the IPv6 check found, and
	// a check writing what it found, one at a time -- see commitV6
	v6mu sync.Mutex
	// stopMu: one stop of the core at a time. A restart is asked for by the
	// health check and by the controller (DNS or IPv6 settings changed), and
	// the service's own stop may come on top: each used to shut the same
	// process down at once -- TUN disabled twice, kill racing kill, and at
	// worst a fresh core killed by a request meant for the one before it.
	stopMu sync.Mutex
}

// apiAddr: the core's external controller, as awgconf writes it
const apiAddr = "127.0.0.1:9090"

func New() *Supervisor { return &Supervisor{recheck: make(chan struct{}, 1)} }

// Run keeps the core alive until the context is cancelled and runs
// the controller alongside. Returning means a final stop.
func (s *Supervisor) Run(ctx context.Context, apply bool) {
	// the data directory was made the service's before the log was opened
	// (see paths.SecureDataDir); the user writes in paths.UserDir only.
	//
	// With no .conf the core runs all the same, with no tunnel: Live shows
	// the traffic, the lists apply, and the rest goes direct. The UI loads a
	// .conf into UserDir and restarts the service, which renders config.yaml
	// from it -- the user may not write the config itself.
	if _, err := os.Stat(paths.SourceConf()); err != nil {
		log.Println("no first tunnel's config: the core runs without it -- load a .conf in the UI")
	}
	awgconf.EnsureLists()
	ctl.SyncUserFiles()

	// cores from a previous run (hard power-off, service crash)
	// hold TUN and routes -- kill them before bringing up our own
	killOrphans()
	// with none left running from it, the core an older version extracted
	// into the data directory goes
	core.RemoveLegacy()

	if job, err := newKillJob(); err == nil {
		s.job = job
		defer windows.CloseHandle(job) // closing the job kills the core
	} else {
		log.Printf("warning: job object unavailable (%v), "+
			"the core may outlive the service on a crash", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); s.keepCore(ctx) }()

	// an address change (Wi-Fi connected, network switched, cable unplugged)
	// must trigger an immediate check instead of waiting for the regular poll
	go watchNetworkChanges(ctx, s.askRecheck)

	wg.Add(1)
	go func() { defer wg.Done(); s.keepHealthy(ctx) }()

	// the controller needs the core's API to be listening
	wg.Add(1)
	go func() {
		defer wg.Done()
		// waited for as long as it takes: keepCore brings the core up
		// whenever the network lets it, and a controller that gave up
		// after 90 seconds left the service without a detector until the
		// next restart
		for !s.waitAPI(ctx, apiAddr, 90*time.Second) {
			if ctx.Err() != nil {
				return
			}
			log.Println("core not up yet, the controller keeps waiting for it")
		}
		cfg := ctl.Defaults()
		cfg.Apply = apply
		cfg.OnCoreChange = func() { go s.restartCore() }
		ctl.Run(ctx, cfg)
	}()

	wg.Wait()
}

// restart the core with a growing pause: at boot the network
// may not be up yet, and the first attempts legitimately fail
func (s *Supervisor) keepCore(ctx context.Context) {
	backoff := minCorePause
	for {
		if ctx.Err() != nil {
			return
		}
		// after a reboot the service starts before Wi-Fi. Starting
		// the core into the void is pointless: it only burns retries and goes
		// into a long pause by the time the network finally appears
		if !s.waitNetwork(ctx) {
			return
		}
		start := time.Now()
		err := s.runCore(ctx)
		s.running.Store(false)
		if ctx.Err() != nil {
			return
		}
		planned := s.planned.Swap(false)
		if err != nil && !planned {
			log.Printf("core exited: %v", err)
		}
		var wait time.Duration
		wait, backoff = corePause(planned, time.Since(start), backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

const (
	minCorePause = 2 * time.Second
	maxCorePause = 60 * time.Second
)

// corePause: how long keepCore waits before starting the core again, and
// the pause for the time after. A core that fell waits longer each time --
// at boot the network may not be up, and the first attempts legitimately
// fail -- and one that lasted long resets it. One restartCore stopped
// comes back at once: a setting changed, a tunnel found dead. It used to
// count as a fall -- Kill ends it with an error -- and a few settings
// changed in a row waited 2, 4, 8, 16 seconds.
func corePause(planned bool, ran, backoff time.Duration) (wait, next time.Duration) {
	if planned {
		return 0, minCorePause
	}
	if ran > 2*time.Minute {
		backoff = minCorePause
	}
	next = backoff
	if next < maxCorePause {
		next *= 2
	}
	return backoff, next
}

func (s *Supervisor) runCore(ctx context.Context) error {
	logf, err := openRotating(paths.MihomoLog(), 8<<20)
	if err != nil {
		return fmt.Errorf("core log: %w", err)
	}
	defer logf.Close()

	// the config is rebuilt before EVERY start: this way the core gets both
	// a new program version and DNS changes from settings (for those
	// the controller requests a restart). The source may be missing -- then
	// use what exists; a broken source is no reason not to start
	// Start optimistic: every tunnel gets IPv6, and the check below takes it
	// away from the one that cannot carry it. Keeping the previous answer for
	// good would be a one-way door -- an outbound pinned to ip-version: ipv4
	// refuses IPv6 targets outright, so the check could never see IPv6 come
	// back. The adapter's own answers are kept, and a tunnel's for a while
	// (see startIPv6State).
	s.v6mu.Lock()
	start := startIPv6State(ctl.LoadTunnelIPv6(paths.TunnelIPv6()), loadV6Held(paths.TunnelIPv6Held()), time.Now())
	if err := start.Save(paths.TunnelIPv6()); err != nil {
		log.Printf("IPv6 state not reset: %v", err)
	}
	if changed, err := awgconf.Regenerate(); err != nil {
		log.Printf("config not rebuilt, using the old one: %v", err)
	} else if changed {
		log.Println("config rebuilt")
	}
	s.v6mu.Unlock()
	// the user's lists as they are now, before the core reads them
	awgconf.EnsureLists()
	ctl.SyncUserFiles()

	// the core is embedded into dpiswitch.exe: make sure the extracted copy
	// is present and untampered before every start (see internal/core)
	if wrote, err := core.Ensure(); err != nil {
		return fmt.Errorf("core binary: %w", err)
	} else if wrote {
		log.Printf("core extracted to %s", core.Path())
	}

	cmd := winexec.Command(core.Path(), "-d", paths.DataDir(), "-f", paths.Config())
	cmd.Dir = paths.DataDir()
	// the core disables IPv6 on TUN if the machine has no global IPv6.
	// here IPv6 may exist only inside the tunnel -- the ISP may not
	// provide any -- so that check is wrong for us
	cmd.Env = append(os.Environ(), "SKIP_SYSTEM_IPV6_CHECK=true")
	// repeated warnings (a burst of retries while the network is down)
	// are collapsed; see logfilter.go. Closed after the process exits,
	// when exec has finished copying its output.
	out := newDedupWriter(logf, time.Minute)
	defer out.Close()
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting the core: %w", err)
	}

	// exit is signalled by CLOSING the channel, not by a value in it:
	// two parties wait (this loop and stopCore on restart), and a value would
	// reach only one -- the other would wait in vain and log a false
	// "core did not exit after Kill"
	done := make(chan struct{})
	var waitErr error

	if s.job != 0 {
		if err := assignToJob(s.job, cmd.Process.Pid); err != nil {
			log.Printf("warning: core not assigned to the job object: %v", err)
		}
	}

	s.mu.Lock()
	s.cmd = cmd
	s.done = done
	s.mu.Unlock()
	s.running.Store(true)
	log.Printf("core started, pid %d", cmd.Process.Pid)
	// the UI tells this run from the last by it: a core restarted between
	// two of its calls looks the same from its API
	run := fmt.Sprintf("%d %d\n", cmd.Process.Pid, time.Now().UnixNano())
	if err := paths.ReplaceFile(paths.CoreRun(), []byte(run)); err != nil {
		log.Printf("core run not written: %v", err)
	}

	// one-shot per core start: find out whether IPv6 gets through each
	// tunnel (see ipv6.go). It waits for the tunnels, so it runs aside --
	// under a context of this core's own, ended when this core is. It ran
	// under the service's, and a check that outlived its core (waiting for
	// a tunnel can take minutes) blocked the next core's own check and wrote
	// what it had measured on the dying one into the config of the new one.
	coreCtx, coreDone := context.WithCancel(ctx)
	defer coreDone()
	go s.checkIPv6(coreCtx)
	go warmTunnels(coreCtx, newHealthChecker(apiAddr, ctl.SecretFromConfig(paths.Config())), awgconf.Tunnels())

	go func() { waitErr = cmd.Wait(); close(done) }()

	select {
	case <-done:
		return waitErr
	case <-ctx.Done():
		// a clean shutdown is mandatory: a killed core leaves
		// the system with TUN up and broken routes
		s.stopMu.Lock()
		s.stopCore(cmd, done)
		s.stopMu.Unlock()
		return nil
	}
}

// stopCore shuts the core down CLEANLY.
//
// Signals do not work on Windows: Process.Signal(os.Interrupt) always
// returns an error, so the old code always waited in vain and killed
// the core forcibly -- leaving TUN up and
// the routes rewritten. The machine ended up without internet.
//
// The right way is to ask the core to disable TUN through its own API.
// It removes the adapter and restores the routes itself; after that
// terminating the process is safe.
func (s *Supervisor) stopCore(cmd *exec.Cmd, done <-chan struct{}) {
	if cmd.Process == nil {
		return
	}
	select {
	case <-done:
		return // already gone: a stop before this one got there
	default:
	}
	if err := tunOff(); err != nil {
		log.Printf("TUN not disabled via the API (%v) -- routes may need manual cleanup", err)
	} else {
		// the core needs time to remove the adapter and restore routes
		time.Sleep(1500 * time.Millisecond)
	}

	_ = cmd.Process.Kill()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		log.Println("core did not exit after Kill")
	}
}

// tunOff: disableTUN; tests put a counter in its place -- the real one would
// switch off the TUN of whatever core runs on this machine
var tunOff = disableTUN

// disableTUN asks the core to remove the tunnel adapter and restore routes
func disableTUN() error {
	body := strings.NewReader(`{"tun":{"enable":false}}`)
	req, err := http.NewRequest(http.MethodPatch, "http://"+apiAddr+"/configs", body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if sec := ctl.SecretFromConfig(paths.Config()); sec != "" {
		req.Header.Set("Authorization", "Bearer "+sec)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("PATCH /configs: %s", resp.Status)
	}
	return nil
}

// waitAPI waits for the core's API to answer, not just for the process to
// run. It used to give the process two seconds and call that ready; a core
// slow to come up then met a controller whose first moves need it -- and on
// a network whose ISP was not yet known, the controller fell back to an
// empty memory by gateway and wrote the direct list empty until the ISP
// was found.
func (s *Supervisor) waitAPI(ctx context.Context, addr string, limit time.Duration) bool {
	secret := ctl.SecretFromConfig(paths.Config())
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return false
		}
		if s.running.Load() && apiReady(addr, secret) {
			return true
		}
		sleepCtx(ctx, time.Second)
	}
	return false
}

// apiReady: whether the core's API answers, and takes our secret.
func apiReady(addr, secret string) bool {
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/version", nil)
	if err != nil {
		return false
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// waitNetwork waits for a physical network. Returns false
// only if we are shutting down.
func (s *Supervisor) waitNetwork(ctx context.Context) bool {
	if physicalNetwork() {
		return true
	}
	log.Println("no network, waiting for it")
	for i := 0; ; i++ {
		select {
		case <-ctx.Done():
			return false
		case <-s.recheck: // address change notification -- check right away
		case <-time.After(3 * time.Second):
		}
		if physicalNetwork() {
			log.Println("network is up")
			return true
		}
		if i == 100 {
			log.Println("still no network, keep waiting")
		}
	}
}

func (s *Supervisor) askRecheck() {
	select {
	case s.recheck <- struct{}{}:
	default: // a check is already requested, no second signal needed
	}
}

// keepHealthy catches the case all of this exists for:
// TUN is up, the core is alive, but the peer is unreachable -- then all traffic
// goes nowhere, and from the outside it looks like no internet at all.
// It won't resolve itself until someone re-establishes the connection.
func (s *Supervisor) keepHealthy(ctx context.Context) {
	// read again at every look: read once, before the first core's config
	// was written, it was none -- and every look a refusal, the core
	// restarted every minute until the service was
	var secret string

	const (
		// the core checks every 30 seconds; reading twice as often keeps
		// this from lagging a check behind
		period   = 15 * time.Second
		failsMax = 3 // three in a row: a single failure is not worth reacting to
	)
	var fails int
	var seen time.Time // the core's check the last verdict here came from
	// let the core come up before judging its health
	if !sleepCtx(ctx, 25*time.Second) {
		return
	}
	for {
		if !s.running.Load() {
			if !sleepCtx(ctx, period) {
				return
			}
			continue
		}
		// without a physical network there is nothing to check: the tunnel is
		// legitimately dead, and a core restart would fix nothing
		if !physicalNetwork() {
			fails = 0
			if !s.waitRecheck(ctx, period) {
				return
			}
			continue
		}

		// The core's proxy groups check the tunnel every 30 seconds; their
		// last result is read here instead of a check of its own -- 2,880
		// requests a day through the tunnel. Each check counts once: a
		// result read again says nothing new. One the core stopped renewing
		// is a failure every time -- the core itself may be stuck.
		// the first tunnel carries what no list names; with none, the second
		// is all there is. With no tunnel there is nothing to go dead.
		name := watched()
		if name == "" {
			fails = 0
			if !s.waitRecheck(ctx, period) {
				return
			}
			continue
		}
		if sec := ctl.SecretFromConfig(paths.Config()); sec != "" {
			secret = sec // a config being replaced reads as none for a moment
		}
		c, err := ctl.LastTunnelCheck(apiAddr, secret, name)
		news, ok, detail := readCheck(c, err, seen)
		if !news {
			if !s.waitRecheck(ctx, period) {
				return
			}
			continue
		}
		seen = c.At
		if ok {
			if fails > 0 {
				log.Printf("tunnel responding again (%s)", detail)
			}
			fails = 0
		} else {
			fails++
			log.Printf("tunnel %s not responding (%s), in a row: %d", name, detail, fails)
			if fails >= failsMax {
				// another client with the same key is stealing the session on the server.
				// restarting the core is pointless: it would just seesaw
				if other, name := foreignTunnel(); other {
					log.Printf("tunnel is dead, but a foreign tunnel adapter %q is up -- "+
						"another client with the same key seems to be running. "+
						"leaving the core alone to avoid an endless restart loop", name)
					fails = 0
					if !s.waitRecheck(ctx, period) {
						return
					}
					continue
				}
				log.Println("restarting the core: tunnel dead while the network is up")
				s.restartCore()
				fails = 0
				if !sleepCtx(ctx, 20*time.Second) {
					return
				}
				continue
			}
		}
		if !s.waitRecheck(ctx, period) {
			return
		}
	}
}

// watched: the tunnel keepHealthy restarts the core for, "" for none; a var
// for tests
var watched = func() string {
	if t := awgconf.Tunnels(); len(t) > 0 {
		return t[0]
	}
	return ""
}

// readCheck: whether a reading of the core's last tunnel check is news, and
// what it says. The same check read again is not; one the core stopped
// renewing, or an API that does not answer, is a failure every time.
func readCheck(c ctl.TunnelCheck, err error, seen time.Time) (news, ok bool, detail string) {
	switch {
	case err != nil:
		// the core itself is unreachable -- a separate problem, but cured the same way
		return true, false, "core API not responding: " + trim(err.Error())
	case c.Stale || c.At.IsZero():
		return true, c.OK, c.Note
	case c.At.Equal(seen):
		return false, c.OK, c.Note
	}
	return true, c.OK, c.Note
}

// wait for either the period or a network change signal
func (s *Supervisor) waitRecheck(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-s.recheck:
		// the network changed: let the stack settle, otherwise we would check
		// before the default route comes up
		return sleepCtx(ctx, 3*time.Second)
	case <-time.After(d):
		return true
	}
}

// restartCore stops the core; keepCore brings it back up by itself.
// A restart already under way covers this one: the core it brings up is
// started after the stop, from a config built afresh -- new settings in it.
func (s *Supervisor) restartCore() {
	if !s.stopMu.TryLock() {
		log.Println("core restart already under way")
		return
	}
	defer s.stopMu.Unlock()
	s.mu.Lock()
	cmd, done := s.cmd, s.done
	s.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	select {
	case <-done:
		return // it ended by itself: keepCore takes that as the fall it is
	default:
	}
	s.planned.Store(true)
	s.stopCore(cmd, done)
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
