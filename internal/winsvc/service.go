// Служба Windows: регистрация, удаление, управление и режим работы.
// Служба нужна ради LocalSystem -- TUN требует привилегий, и без неё
// каждый запуск туннеля спрашивал бы UAC.
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
	Description = "Держит туннель AmneziaWG и переключает незаблокированные сайты напрямую."
)

// Права на старт/стоп для интерактивных пользователей: без этого
// каждое включение туннеля из трея требовало бы UAC.
// IU -- любой вошедший в систему, SY -- система, BA -- администраторы.
const sddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)"

func Install() error {
	if err := paths.EnsureDataDir(); err != nil {
		return fmt.Errorf("каталог данных: %w", err)
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("нет доступа к диспетчеру служб (нужны права администратора): %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(Name); err == nil {
		s.Close()
		return fmt.Errorf("служба %s уже установлена", Name)
	}

	s, err := m.CreateService(Name, paths.Exe(), mgr.Config{
		DisplayName: DisplayName,
		Description: Description,
		StartType:   mgr.StartAutomatic,
		// обычный автозапуск, НЕ отложенный. отложенный стоил бы двух
		// минут без туннеля после каждой загрузки, а защищал бы от того,
		// что супервизор и так умеет: он сам ждёт появления физической
		// сети перед каждым стартом ядра (см. waitNetwork)
		DelayedAutoStart: false,
		ServiceStartName: "LocalSystem",
		Dependencies:     []string{"Tcpip", "Nsi", "Dnscache"},
	}, "service")
	if err != nil {
		return fmt.Errorf("создание службы: %w", err)
	}
	defer s.Close()

	// без восстановления упавшая служба оставит машину без сети
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 86400); err != nil {
		log.Printf("предупреждение: не настроено восстановление: %v", err)
	}

	if out, err := sc("sdset", Name, sddl); err != nil {
		return fmt.Errorf("не выданы права на управление службой: %v (%s)", err, out)
	}
	return nil
}

func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("нет доступа к диспетчеру служб (нужны права администратора): %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(Name)
	if err != nil {
		return fmt.Errorf("служба не установлена")
	}
	defer s.Close()

	// остановка обязательна до удаления: иначе ядро останется
	// работать, а с ним TUN и изменённые маршруты
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			log.Printf("предупреждение: остановка не удалась: %v", err)
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

// BinPath: путь, с которым служба зарегистрирована. Нужен, чтобы
// заметить перенос папки -- зарегистрированный путь зашит намертво.
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

// PathMatches: совпадает ли регистрация с текущим положением бинаря
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

// --- режим работы службы ---

type handler struct{ apply bool }

func (h *handler) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	s <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // страховка: на любом выходе супервизор обязан получить отмену
	log.Printf("служба %s запускается", version.Version)
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
				// сообщаем StopPending заранее: корректная остановка
				// ядра занимает секунды, иначе SCM сочтёт службу зависшей
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

// RunService вызывается, когда процесс запущен диспетчером служб.
func RunService(apply bool) error {
	return svc.Run(Name, &handler{apply: apply})
}

func IsWindowsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

var _ = windows.ERROR_SUCCESS
