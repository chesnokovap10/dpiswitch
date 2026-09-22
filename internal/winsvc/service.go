// Windows service: registration, removal, control and the service mode.
// The service exists for LocalSystem -- TUN needs privileges, and without it
// every tunnel start would prompt for UAC.
package winsvc

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"dpiswitch/internal/paths"
	"dpiswitch/internal/supervisor"
	"dpiswitch/internal/version"
	"dpiswitch/internal/winexec"
)

const (
	Name        = "dpiswitch"
	DisplayName = "DPI Switch (AmneziaWG + mihomo)"
	Description = "Keeps the AmneziaWG tunnel up and switches unblocked sites to a direct path."
)

// Start/stop rights for interactive users: without this
// every tunnel toggle from the tray would require UAC.
// IU -- any signed-in user, SY -- SYSTEM, BA -- Administrators.
const sddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)"

func Install() error {
	if err := paths.EnsureDataDir(); err != nil {
		return fmt.Errorf("data directory: %w", err)
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

	s, err := m.CreateService(Name, paths.Exe(), mgr.Config{
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

	if out, err := sc("sdset", Name, sddl); err != nil {
		return fmt.Errorf("service control rights not granted: %v (%s)", err, out)
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
		waitState(s, svc.Stopped, 30*time.Second)
	}
	return s.Delete()
}

func Installed() bool {
	_, closer, err := openLimited()
	if err != nil {
		return false
	}
	closer()
	return true
}

// BinPath: the path the service is registered with. Used to
// notice a moved folder -- the registered path is fixed.
func BinPath() string {
	s, closer, err := openLimited()
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

// PathMatches: whether the registration matches the current binary location
func PathMatches() bool {
	bp := BinPath()
	if bp == "" {
		return false
	}
	return strings.Contains(strings.ToLower(bp), strings.ToLower(paths.Exe()))
}

func State() (svc.State, error) {
	s, closer, err := openLimited()
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
	s, closer, err := openLimited()
	if err != nil {
		return err
	}
	defer closer()
	if err := s.Start(); err != nil {
		return err
	}
	waitState(s, svc.Running, 30*time.Second)
	return nil
}

func Stop() error {
	s, closer, err := openLimited()
	if err != nil {
		return err
	}
	defer closer()
	if _, err := s.Control(svc.Stop); err != nil {
		return err
	}
	waitState(s, svc.Stopped, 30*time.Second)
	return nil
}

func waitState(s *mgr.Service, want svc.State, limit time.Duration) {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil || st.State == want {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func sc(args ...string) (string, error) {
	out, err := winexec.CombinedOutput("sc.exe", args...)
	return string(out), err
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
				s <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(20 * time.Second):
				}
				s <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		case <-done:
			s <- svc.Status{State: svc.Stopped}
			return false, 0
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

var _ = windows.ERROR_SUCCESS
