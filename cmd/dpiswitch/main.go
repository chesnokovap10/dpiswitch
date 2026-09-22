// dpiswitch: трей, служба и установка в одном бинаре.
// Режим выбирается аргументом; без аргументов -- трей.
package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"dpiswitch/internal/autostart"
	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/session"
	"dpiswitch/internal/supervisor"
	"dpiswitch/internal/tray"
	"dpiswitch/internal/version"
	"dpiswitch/internal/webui"
	"dpiswitch/internal/winexec"
	"dpiswitch/internal/winsvc"
)

func main() {
	// запуск диспетчером служб распознаётся сам: ярлык и автозапуск
	// зовут тот же бинарь, перепутать режимы нельзя
	if winsvc.IsWindowsService() {
		runService()
		return
	}

	cmd := ""
	if len(os.Args) > 1 {
		cmd = strings.ToLower(os.Args[1])
	}
	switch cmd {
	case "service":
		runService()
	case "install":
		report("Установка службы", winsvc.Install())
	case "uninstall":
		report("Удаление службы", winsvc.Uninstall())
	case "reinstall":
		_ = winsvc.Uninstall()
		report("Переустановка службы", winsvc.Install())
	case "", "tray":
		runTray()
	case "version", "-v", "--version":
		msgBox("DPI Switch", "Версия "+version.Version, 0x40)
	default:
		report("dpiswitch", fmt.Errorf("неизвестная команда %q; допустимы: tray, service, install, uninstall, reinstall, version", cmd))
	}
}

func runService() {
	_ = paths.EnsureDataDir()
	if f, err := os.OpenFile(paths.ServiceLog(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		log.SetOutput(f)
	}
	log.SetFlags(log.LstdFlags)
	if err := winsvc.RunService(true); err != nil {
		log.Printf("служба завершилась с ошибкой: %v", err)
	}
}

// Второй экземпляр не нужен: две иконки в трее и две копии
// веб-сервера только путают. Но и молча умирать неправильно --
// пользователь запустил ярлык, ожидая увидеть интерфейс.
// Порт теперь постоянен внутри сессии, поэтому достаточно открыть
// его в браузере и выйти.
func alreadyRunning() bool {
	name, err := syscall.UTF16PtrFromString(`Local\dpiswitch-tray`)
	if err != nil {
		return false
	}
	_, err = windows.CreateMutex(nil, false, name)
	return err == windows.ERROR_ALREADY_EXISTS
}

func runTray() {
	// журнал настраиваем ПЕРВЫМ делом: раньше проверка "уже запущено"
	// стояла выше, и выход по ней не оставлял в логе ни строчки --
	// ровно тот путь, который и надо было увидеть
	_ = paths.EnsureDataDir()
	if f, err := os.OpenFile(paths.ControllerLog(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		log.SetOutput(f)
	}
	log.Printf("запуск трея %s: pid %d, аргументы %v", version.Version, os.Getpid(), os.Args[1:])

	// мьютекс -- объект ядра: при смерти процесса он освобождается сам,
	// поэтому "зависнуть" не может и дополнительных проверок не требует
	if alreadyRunning() {
		log.Println("трей: другая копия уже работает -- открываю интерфейс и выхожу")
		browse(fmt.Sprintf("http://127.0.0.1:%d/", session.Port()))
		return
	}

	// оконный цикл обязан жить в одном потоке с окном
	runtime.LockOSThread()

	srv := &webui.Server{
		Elevate: elevate,
		Reload:  func() error { return nil },
	}
	if err := srv.Start(); err != nil {
		report("dpiswitch", fmt.Errorf("не поднялся интерфейс: %w", err))
		return
	}

	t, err := tray.New("DPI Switch " + version.Version)
	if err != nil {
		report("dpiswitch", fmt.Errorf("не создана иконка в трее: %w", err))
		return
	}
	openUI := func() { browse(srv.Addr()) }
	t.OnOpen = openUI

	t.Menu = func() []tray.Item {
		installed := winsvc.Installed()
		running := false
		if installed {
			if st, err := winsvc.State(); err == nil {
				running = st == svc.Running
			}
		}
		items := []tray.Item{
			{ID: 1, Text: "Настройки…", Do: openUI},
			{Sep: true},
		}
		if !installed {
			items = append(items, tray.Item{ID: 2, Text: "Установить службу…",
				Do: func() { _ = elevate("install") }})
		} else if running {
			items = append(items, tray.Item{ID: 3, Text: "Остановить туннель",
				Do: func() { _ = winsvc.Stop() }})
		} else {
			items = append(items, tray.Item{ID: 4, Text: "Включить туннель",
				Do: func() { _ = winsvc.Start() }})
		}
		items = append(items,
			tray.Item{ID: 5, Text: "Всё в туннель (сбросить вердикты)", Grayed: !running,
				Do: panicTunnel},
			tray.Item{Sep: true},
			tray.Item{ID: 6, Text: "Автозапуск", Checked: autostart.Enabled(),
				Do: func() { _ = autostart.Set(!autostart.Enabled()) }},
			tray.Item{ID: 7, Text: "Папка данных", Do: func() { browse(paths.DataDir()) }},
			tray.Item{Sep: true},
			tray.Item{ID: 9, Text: "Выход", Do: func() { t.Quit() }},
		)
		return items
	}

	go watchStatus(t)
	t.Loop()
	srv.Close()
}

// иконка отражает состояние: иначе непонятно, работает ли оно вообще
func watchStatus(t *tray.Tray) {
	for {
		state, tip := status()
		t.SetState(state, tip)
		// проверка туннеля ходит в API ядра, поэтому реже,
		// чем обновлялась бы простая надпись
		sleep(10)
	}
}

func status() (tray.State, string) {
	if !winsvc.Installed() {
		return tray.StateOff, "DPI Switch — служба не установлена"
	}
	st, err := winsvc.State()
	if err != nil {
		return tray.StateError, "DPI Switch — ошибка: " + err.Error()
	}
	if st != svc.Running {
		if !supervisor.NetworkUp() {
			return tray.StateOff, "DPI Switch — выключен, сети нет"
		}
		return tray.StateOff, "DPI Switch — туннель выключен"
	}
	// служба на ходу и туннель пропускает трафик -- разные вещи:
	// при мёртвом пире TUN стоит, а интернета нет
	alive, note := supervisor.TunnelAlive("127.0.0.1:9090",
		ctl.SecretFromConfig(paths.Config()), "awg")
	if !alive {
		if !supervisor.NetworkUp() {
			return tray.StateError, "DPI Switch — нет сети, жду подключения"
		}
		return tray.StateError, "DPI Switch — туннель не отвечает: " + note
	}
	snap := ctl.Load(paths.State())
	blocked := snap.Counts["BLOCKED_TLS"] + snap.Counts["BLOCKED_TCP"] + snap.Counts["BLOCKED_QUIC"]
	return tray.StateOn, fmt.Sprintf("DPI Switch — туннель работает (%s)\n"+
		"напрямую: %d, заблокировано: %d", note, len(snap.Direct), blocked)
}

// аварийный сброс: очищаем вердикты, весь трафик возвращается в туннель.
// нужен, когда детектор ошибся и что-то перестало открываться.
func panicTunnel() {
	_ = os.WriteFile(paths.Verified(),
		[]byte("# сброшено вручную из трея\n"), 0o644)
	_ = os.Remove(paths.State())
	msgBox("DPI Switch", "Вердикты сброшены, весь трафик идёт через туннель.\n"+
		"Детектор начнёт заново подбирать домены.", 0x40)
}

// установка и удаление службы требуют администратора: обычный
// процесс их выполнить не может, поэтому зовём себя же с runas
func elevate(verb string) error {
	exe, _ := syscall.UTF16PtrFromString(paths.Exe())
	args, _ := syscall.UTF16PtrFromString(verb)
	runas, _ := syscall.UTF16PtrFromString("runas")
	dir, _ := syscall.UTF16PtrFromString(paths.ExeDir())
	return windows.ShellExecute(0, runas, exe, args, dir, windows.SW_NORMAL)
}

var (
	user32                    = windows.NewLazySystemDLL("user32.dll")
	pAllowSetForegroundWindow = user32.NewProc("AllowSetForegroundWindow")
)

const asfwAny = ^uintptr(0) // ASFW_ANY: право на фокус любому процессу

// Windows не даёт процессу самому выйти на передний план -- иначе окна
// перехватывали бы фокус у пользователя. Легальный способ один:
// заранее передать это право тому, кого мы сейчас запускаем.
// Если браузер уже открыт, он всплывёт с нужной вкладкой.
func browse(target string) {
	pAllowSetForegroundWindow.Call(asfwAny)

	verb, _ := syscall.UTF16PtrFromString("open")
	file, _ := syscall.UTF16PtrFromString(target)
	if err := windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL); err != nil {
		// запасной путь: ShellExecute капризен к некоторым схемам
		_ = winexec.Command("rundll32", "url.dll,FileProtocolHandler", target).Start()
	}
}

func report(title string, err error) {
	if err != nil {
		msgBox(title, "Не получилось:\n\n"+err.Error(), 0x10)
		os.Exit(1)
	}
	msgBox(title, "Готово.", 0x40)
}

func msgBox(title, text string, icon uint32) {
	t, _ := syscall.UTF16PtrFromString(title)
	b, _ := syscall.UTF16PtrFromString(text)
	windows.MessageBox(0, b, t, icon)
}

func sleep(sec int) {
	windows.SleepEx(uint32(sec*1000), false)
}

var _ = unsafe.Pointer(nil)
