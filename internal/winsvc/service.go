// Windows service: registration, removal, control and the service mode.
// The service exists for LocalSystem -- TUN needs privileges, and without it
// every tunnel start would prompt for UAC.
package winsvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"dpiswitch/internal/core"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/supervisor"
	"dpiswitch/internal/version"
)

const (
	Name        = "dpiswitch"
	DisplayName = "DPI Switch (AmneziaWG + mihomo)"
	Description = "Keeps the AmneziaWG tunnel up and switches unblocked sites to a direct path."
)

// sddl: the service's permissions. Starting and stopping it is the owner's
// -- the user it was installed for -- without an administrator prompt;
// every signed-in user (IU) may only see its state. It used to let IU start
// and stop it: any account on the machine could take the tunnel down, and
// restart the service -- SYSTEM -- the moment it had planted something for
// it to read.
func sddl(owner string) string {
	s := "D:(A;;CCLCSWLOCRRC;;;IU)" +
		"(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)"
	if owner != "" {
		s += "(A;;CCLCSWRPWPDTLOCRRC;;;" + owner + ")"
	}
	return s
}

// InstallDir: where the service runs from. The service runs as SYSTEM, so
// its binary must sit where only administrators write: it used to be
// registered wherever dpiswitch.exe was started from -- Downloads, a folder
// on a second drive where every signed-in user may modify files -- and any
// of them could swap the file and restart the service.
func InstallDir() string {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		dir = `C:\Program Files`
	}
	return filepath.Join(dir, "DPI Switch")
}

// InstalledExe: the service's binary
func InstalledExe() string { return filepath.Join(InstallDir(), "dpiswitch.exe") }

// Install copies this binary to InstallDir and registers it as the service
// of owner (a user's SID), who may then start and stop it.
func Install(owner string) error {
	if !paths.ValidSID(owner) {
		return fmt.Errorf("the service is installed for a user account; got %q", owner)
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("no access to the service manager (administrator rights required): %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(Name); err == nil {
		s.Close()
		return fmt.Errorf("service %s is already installed", Name)
	}
	if err := copyBinaries(); err != nil {
		return err
	}
	if err := paths.SetOwner(owner); err != nil {
		return fmt.Errorf("owner not recorded: %w", err)
	}
	if err := paths.SecureDataDir(owner); err != nil {
		log.Printf("warning: data directory: %v", err)
	}

	s, err := m.CreateService(Name, InstalledExe(), mgr.Config{
		DisplayName: DisplayName,
		Description: Description,
		StartType:   mgr.StartAutomatic,
		// regular automatic start, NOT delayed. Delayed would cost two
		// minutes without the tunnel after every boot, while guarding against what
		// the supervisor already handles: it waits for a physical
		// network before every core start (see waitNetwork)
		DelayedAutoStart: false,
		ServiceStartName: "LocalSystem",
		Dependencies:     []string{"Tcpip", "Nsi", "Dnscache"},
	}, "service")
	if err != nil {
		return fmt.Errorf("creating the service: %w", err)
	}
	defer s.Close()

	// without recovery actions a crashed service would leave the machine offline
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 86400); err != nil {
		log.Printf("warning: recovery actions not configured: %v", err)
	}
	if err := setServiceSD(s.Handle, owner); err != nil {
		return err
	}
	// started at once: a reinstall used to leave the tunnel down until the
	// user found the Start button. With no .conf yet it waits for one.
	if err := s.Start(); err != nil {
		return fmt.Errorf("installed, but not started: %w", err)
	}
	return nil
}

// SecureService sets the service's permissions for owner. The service does
// it at every start: an installation from before owners let IU start and
// stop it.
func SecureService(owner string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return err
	}
	defer s.Close()
	return setServiceSD(s.Handle, owner)
}

func setServiceSD(h windows.Handle, owner string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl(owner))
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(h, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("service control rights not granted: %w", err)
	}
	return nil
}

// copyBinaries puts this binary (and, for a build without the core inside,
// the mihomo.exe beside it) into InstallDir. A service that ran the old one
// has just been stopped: its file may be held a moment longer.
func copyBinaries() error {
	if err := os.MkdirAll(InstallDir(), 0o755); err != nil {
		return fmt.Errorf("%s: %w", InstallDir(), err)
	}
	files := [][2]string{{paths.Exe(), InstalledExe()}}
	if m := paths.Mihomo(); !core.Embedded() && fileExists(m) {
		files = append(files, [2]string{m, filepath.Join(InstallDir(), "mihomo.exe")})
	}
	for _, f := range files {
		if samePath(windows.EscapeArg(f[0]), f[1]) {
			continue // installing from the installed copy
		}
		var err error
		for i := 0; i < 50; i++ {
			if err = copyFile(f[0], f[1]); err == nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if err != nil {
			return fmt.Errorf("%s not copied to %s: %w", f[0], f[1], err)
		}
	}
	return nil
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

func copyFile(from, to string) error {
	b, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	tmp := to + ".new"
	if err := os.WriteFile(tmp, b, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, to); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("no access to the service manager (administrator rights required): %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(Name)
	if err != nil {
		return fmt.Errorf("service is not installed")
	}
	defer s.Close()

	// stopping before removal is mandatory: otherwise the core keeps
	// running, and with it TUN and the modified routes
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			log.Printf("warning: stop failed: %v", err)
		}
		// a stop may take up to stopLimit. Deleting a service that still runs
		// only marks it: removal reported done with the process alive, TUN and
		// routes still up -- and a reinstall right after found the binary held.
		if err := waitState(query(s), svc.Stopped, stopLimit+30*time.Second, 300*time.Millisecond); err != nil {
			return fmt.Errorf("the service did not stop, it is not removed: %w", err)
		}
	}
	return s.Delete()
}

func Installed() bool {
	_, closer, err := openLimited(svcQuery)
	if err != nil {
		return false
	}
	closer()
	return true
}

// BinPath: the path the service is registered with. Used to
// notice a moved folder -- the registered path is fixed.
func BinPath() string {
	s, closer, err := openLimited(svcQuery)
	if err != nil {
		return ""
	}
	defer closer()
	cfg, err := s.Config()
	if err != nil {
		return ""
	}
	return cfg.BinaryPathName
}

// SameBuild: whether the service runs this very build. The service runs
// its own copy in InstallDir, so the path cannot tell; the file is hashed
// again only when its size or time changed.
func SameBuild() bool {
	args, err := windows.DecomposeCommandLine(BinPath())
	if err != nil || len(args) == 0 {
		return false
	}
	a, b := fileHash(args[0]), fileHash(paths.Exe())
	return a != "" && a == b
}

var hashCache sync.Map // path -> hashed

type hashed struct {
	size int64
	mod  time.Time
	sum  string
}

func fileHash(p string) string {
	fi, err := os.Stat(p)
	if err != nil {
		return ""
	}
	if v, ok := hashCache.Load(p); ok {
		if h := v.(hashed); h.size == fi.Size() && h.mod.Equal(fi.ModTime()) {
			return h.sum
		}
	}
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	sum := hex.EncodeToString(h.Sum(nil))
	hashCache.Store(p, hashed{fi.Size(), fi.ModTime(), sum})
	return sum
}

// samePath: whether a service command line runs exe. The path used to be
// looked for in it as a substring, so a registration for dpiswitch.exe.bak
// matched dpiswitch.exe too. The line is split the way Windows splits it --
// the program is registered through EscapeArg, quoted when it has spaces --
// and the program compared as a path.
func samePath(cmdline, exe string) bool {
	if strings.TrimSpace(cmdline) == "" {
		return false
	}
	args, err := windows.DecomposeCommandLine(cmdline)
	if err != nil || len(args) == 0 {
		return false
	}
	return strings.EqualFold(filepath.Clean(args[0]), filepath.Clean(exe))
}

func State() (svc.State, error) {
	s, closer, err := openLimited(svcQuery)
	if err != nil {
		return svc.Stopped, err
	}
	defer closer()
	st, err := s.Query()
	if err != nil {
		return svc.Stopped, err
	}
	return st.State, nil
}

func Start() error {
	s, closer, err := openLimited(svcQuery | windows.SERVICE_START)
	if err != nil {
		return err
	}
	defer closer()
	if err := s.Start(); err != nil {
		return err
	}
	return waitState(query(s), svc.Running, 30*time.Second, 300*time.Millisecond)
}

func Stop() error {
	s, closer, err := openLimited(svcQuery | windows.SERVICE_STOP)
	if err != nil {
		return err
	}
	defer closer()
	if _, err := s.Control(svc.Stop); err != nil {
		return err
	}
	// the service may take up to stopLimit to stop (see waitStopped)
	return waitState(query(s), svc.Stopped, stopLimit+30*time.Second, 300*time.Millisecond)
}

func query(s *mgr.Service) func() (svc.State, error) {
	return func() (svc.State, error) {
		st, err := s.Query()
		return st.State, err
	}
}

// waitState waits for the service to reach want. It used to return nothing,
// and Start and Stop reported success whether the service got there or not:
// the UI said "done" over a service still starting, or one that had died.
func waitState(state func() (svc.State, error), want svc.State, limit, pause time.Duration) error {
	deadline := time.Now().Add(limit)
	for {
		st, err := state()
		if err != nil {
			return fmt.Errorf("service state unknown: %w", err)
		}
		if st == want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the service is still %s after %s, not %s -- see service.log",
				StateText(st), limit, StateText(want))
		}
		time.Sleep(pause)
	}
}

// StateText: a service state in words.
func StateText(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "starting"
	case svc.StopPending:
		return "stopping"
	case svc.Running:
		return "running"
	case svc.Paused:
		return "paused"
	}
	return "unknown"
}

// --- service mode ---

type handler struct{ apply bool }

func (h *handler) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	s <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // safety net: the supervisor must be cancelled on every exit path
	log.Printf("service %s starting", version.Version)
	sup := supervisor.New()
	done := make(chan struct{})
	go func() { defer close(done); sup.Run(ctx, h.apply) }()

	s <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				// report StopPending early: a clean core shutdown
				// takes seconds, otherwise the SCM considers the service hung
				cancel()
				waitStopped(s, done)
				s <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		case <-done:
			s <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
}

// stopLimit: how long a stop waits for the supervisor to return. A probe
// that is already running is not cut short -- it ends on its own timeouts,
// a few tens of seconds at worst.
const stopLimit = 90 * time.Second

// waitStopped reports StopPending with a growing checkpoint until the
// supervisor has returned: STOPPED used to go out after 20 seconds whatever
// it was doing, while a cycle's probes ran on. The checkpoint keeps the SCM
// from taking a long stop for a hung one. Past stopLimit the process ends
// anyway once it returns, taking what is left with it -- the core by its
// job object.
func waitStopped(s chan<- svc.Status, done <-chan struct{}) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	limit := time.After(stopLimit)
	for cp := uint32(1); ; cp++ {
		s <- svc.Status{State: svc.StopPending, CheckPoint: cp, WaitHint: 10000}
		select {
		case <-done:
			return
		case <-limit:
			log.Printf("the supervisor did not stop in %s", stopLimit)
			return
		case <-t.C:
		}
	}
}

// RunService is called when the process is started by the service manager.
func RunService(apply bool) error {
	return svc.Run(Name, &handler{apply: apply})
}

func IsWindowsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}
