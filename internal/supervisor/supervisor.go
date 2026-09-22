// Супервизор: держит запущенным ядро mihomo и крутит контроллер.
// Используется службой; в одиночку не запускается.
package supervisor

import (
	"context"
	"fmt"
	"io"
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
	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/winexec"
)

type Supervisor struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	done    chan struct{} // закрывается, когда ядро завершилось
	running atomic.Bool
	recheck chan struct{} // просьба проверить туннель немедленно
	job     windows.Handle
}

func New() *Supervisor { return &Supervisor{recheck: make(chan struct{}, 1)} }

// Run держит ядро живым до отмены контекста и параллельно
// крутит контроллер. Возврат означает окончательную остановку.
func (s *Supervisor) Run(ctx context.Context, apply bool) {
	if err := paths.EnsureDataDir(); err != nil {
		log.Printf("каталог данных недоступен: %v", err)
		return
	}
	// служба работает от SYSTEM: без этого её файлы достаются
	// пользователю только на чтение, и трей не сможет ни сбросить
	// вердикты, ни поправить списки
	if err := paths.GrantUsersModify(paths.DataDir()); err != nil {
		log.Printf("предупреждение: права на каталог данных не выданы: %v", err)
	}
	if _, err := os.Stat(paths.Config()); err != nil {
		log.Printf("конфиг не найден: %v -- подгрузи .conf через интерфейс", err)
		return
	}
	awgconf.EnsureLists()

	// ядра от прошлого запуска (жёсткое выключение, падение службы)
	// держат TUN и маршруты -- снимаем их до того, как поднимем своё
	killOrphans()

	if job, err := newKillJob(); err == nil {
		s.job = job
		defer windows.CloseHandle(job) // закрытие job снимает ядро
	} else {
		log.Printf("предупреждение: job object недоступен (%v), "+
			"ядро может пережить службу при аварийном завершении", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); s.keepCore(ctx) }()

	// смена адресов (подключили Wi-Fi, переключили сеть, вынули кабель)
	// должна приводить к немедленной проверке, а не ждать общего опроса
	go watchNetworkChanges(ctx, s.askRecheck)

	wg.Add(1)
	go func() { defer wg.Done(); s.keepHealthy(ctx) }()

	// контроллеру нужно, чтобы ядро уже слушало API
	wg.Add(1)
	go func() {
		defer wg.Done()
		if !s.waitAPI(ctx, 90*time.Second) {
			log.Println("ядро не поднялось вовремя, контроллер не стартует")
			return
		}
		cfg := ctl.Defaults()
		cfg.Apply = apply
		cfg.OnCoreChange = func() { go s.restartCore() }
		ctl.Run(ctx, cfg)
	}()

	wg.Wait()
}

// перезапуск ядра с нарастающей паузой: при загрузке системы сеть
// может быть ещё не поднята, и первые попытки законно провалятся
func (s *Supervisor) keepCore(ctx context.Context) {
	backoff := 2 * time.Second
	const maxBackoff = 60 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		// после перезагрузки служба стартует раньше Wi-Fi. поднимать
		// ядро в пустоту незачем: оно только сожжёт попытки и уйдёт
		// в долгую паузу к тому моменту, когда сеть наконец появится
		if !s.waitNetwork(ctx) {
			return
		}
		start := time.Now()
		err := s.runCore(ctx)
		s.running.Store(false)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Printf("ядро завершилось: %v", err)
		}
		// продержалось долго -- считаем это нормальной работой
		// и сбрасываем паузу, иначе она росла бы бесконечно
		if time.Since(start) > 2*time.Minute {
			backoff = 2 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
		}
	}
}

func (s *Supervisor) runCore(ctx context.Context) error {
	logf, err := os.OpenFile(paths.MihomoLog(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("лог ядра: %w", err)
	}
	defer logf.Close()
	rotate(paths.MihomoLog(), 8<<20)

	// конфиг пересобирается перед КАЖДЫМ запуском: так до ядра доходят
	// и новая версия программы, и смена DNS в настройках (для неё
	// контроллер просит перезапуск). исходника может не быть -- тогда
	// работаем с тем, что есть; сломанный исходник не повод не стартовать
	if _, err := os.Stat(paths.SourceConf()); err == nil {
		if changed, err := awgconf.Regenerate(); err != nil {
			log.Printf("конфиг не пересобран, работаю со старым: %v", err)
		} else if changed {
			log.Println("конфиг пересобран")
		}
	}

	cmd := winexec.Command(paths.Mihomo(), "-d", paths.DataDir(), "-f", paths.Config())
	cmd.Dir = paths.DataDir()
	// ядро отключает IPv6 у TUN, если на машине нет глобального IPv6.
	// у нас IPv6 может быть только внутри туннеля -- у провайдера его
	// нет вовсе, -- поэтому проверка тут ошибочна
	cmd.Env = append(os.Environ(), "SKIP_SYSTEM_IPV6_CHECK=true")
	cmd.Stdout = logf
	cmd.Stderr = logf
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("запуск ядра: %w", err)
	}

	// завершение сигнализируется ЗАКРЫТИЕМ канала, а не значением в нём:
	// ждут двое (этот цикл и stopCore при перезапуске), и значение досталось
	// бы только одному -- второй ждал бы впустую и писал ложное
	// "ядро не завершилось после Kill"
	done := make(chan struct{})
	var waitErr error

	if s.job != 0 {
		if err := assignToJob(s.job, cmd.Process.Pid); err != nil {
			log.Printf("предупреждение: ядро не привязано к job object: %v", err)
		}
	}

	s.mu.Lock()
	s.cmd = cmd
	s.done = done
	s.mu.Unlock()
	s.running.Store(true)
	log.Printf("ядро запущено, pid %d", cmd.Process.Pid)

	go func() { waitErr = cmd.Wait(); close(done) }()

	select {
	case <-done:
		return waitErr
	case <-ctx.Done():
		// корректная остановка обязательна: убитое ядро оставит
		// систему с поднятым TUN и битыми маршрутами
		s.stopCore(cmd, done)
		return nil
	}
}

// stopCore снимает ядро КОРРЕКТНО.
//
// На Windows сигналы не работают: Process.Signal(os.Interrupt) всегда
// возвращает ошибку, поэтому прежний код каждый раз ждал впустую и убивал
// ядро принудительно -- а вместе с ним оставались поднятый TUN и
// переписанные маршруты. Машина оказывалась без интернета.
//
// Правильный путь -- попросить ядро выключить TUN через его же API.
// Оно само снимет адаптер и вернёт маршруты; после этого завершение
// процесса уже безопасно.
func (s *Supervisor) stopCore(cmd *exec.Cmd, done <-chan struct{}) {
	if cmd.Process == nil {
		return
	}
	if err := disableTUN(); err != nil {
		log.Printf("TUN не выключен через API (%v) -- маршруты может потребоваться чистить вручную", err)
	} else {
		// ядру нужно время снять адаптер и вернуть маршруты
		time.Sleep(1500 * time.Millisecond)
	}

	_ = cmd.Process.Kill()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		log.Println("ядро не завершилось после Kill")
	}
}

// disableTUN просит ядро убрать туннельный адаптер и восстановить маршруты
func disableTUN() error {
	body := strings.NewReader(`{"tun":{"enable":false}}`)
	req, err := http.NewRequest(http.MethodPatch, "http://127.0.0.1:9090/configs", body)
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

func (s *Supervisor) waitAPI(ctx context.Context, limit time.Duration) bool {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return false
		}
		if s.running.Load() {
			// ядру нужно время поднять слушатели после старта процесса
			time.Sleep(2 * time.Second)
			return true
		}
		time.Sleep(time.Second)
	}
	return false
}

// простая ротация: держим один предыдущий файл, без библиотек
func rotate(path string, max int64) {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() < max {
		return
	}
	_ = os.Remove(path + ".1")
	_ = os.Rename(path, path+".1")
}

var _ = io.Discard

// waitNetwork ждёт появления физической сети. Возвращает false,
// только если работу свернули.
func (s *Supervisor) waitNetwork(ctx context.Context) bool {
	if physicalNetwork() {
		return true
	}
	log.Println("сети нет, жду её появления")
	for i := 0; ; i++ {
		select {
		case <-ctx.Done():
			return false
		case <-s.recheck: // уведомление о смене адресов -- проверяем сразу
		case <-time.After(3 * time.Second):
		}
		if physicalNetwork() {
			log.Println("сеть появилась")
			return true
		}
		if i == 100 {
			log.Println("сети всё ещё нет, продолжаю ждать")
		}
	}
}

func (s *Supervisor) askRecheck() {
	select {
	case s.recheck <- struct{}{}:
	default: // проверка уже запрошена, второй сигнал не нужен
	}
}

// keepHealthy ловит случай, ради которого всё это и затевалось:
// TUN поднят, ядро живо, а пир недоступен -- тогда весь трафик уходит
// в никуда, и снаружи это выглядит как полное отсутствие интернета.
// Само оно не рассосётся, пока кто-то не переподнимет соединение.
func (s *Supervisor) keepHealthy(ctx context.Context) {
	hc := newHealthChecker("127.0.0.1:9090",
		ctl.SecretFromConfig(paths.Config()), "awg")

	const (
		period   = 30 * time.Second
		failsMax = 3 // три подряд: одиночный сбой ловить незачем
	)
	var fails int
	// даём ядру подняться, прежде чем судить о его здоровье
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
		// без физической сети проверять нечего: туннель мёртв
		// законно, и перезапуск ядра ничего не исправит
		if !physicalNetwork() {
			fails = 0
			if !s.waitRecheck(ctx, period) {
				return
			}
			continue
		}

		ok, detail := hc.alive()
		if ok {
			if fails > 0 {
				log.Printf("туннель снова отвечает (%s)", detail)
			}
			fails = 0
		} else {
			fails++
			log.Printf("туннель не отвечает (%s), подряд: %d", detail, fails)
			if fails >= failsMax {
				// чужой клиент с тем же ключом перебивает сессию на сервере.
				// переподнимать ядро бессмысленно: получится качели
				if other, name := foreignTunnel(); other {
					log.Printf("туннель мёртв, но поднят чужой туннельный адаптер %q -- "+
						"похоже, параллельно работает другой клиент с тем же ключом. "+
						"ядро не трогаю, иначе будет бесконечный перезапуск", name)
					fails = 0
					if !s.waitRecheck(ctx, period) {
						return
					}
					continue
				}
				log.Println("переподнимаю ядро: туннель мёртв при живой сети")
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

// ждём либо срок, либо сигнал о смене сети
func (s *Supervisor) waitRecheck(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-s.recheck:
		// сеть изменилась: даём стеку устояться, иначе проверим
		// раньше, чем поднимется маршрут по умолчанию
		return sleepCtx(ctx, 3*time.Second)
	case <-time.After(d):
		return true
	}
}

// restartCore снимает ядро; keepCore поднимет его заново сам
func (s *Supervisor) restartCore() {
	s.mu.Lock()
	cmd, done := s.cmd, s.done
	s.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
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
