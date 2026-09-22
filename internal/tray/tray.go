// Иконка в трее на голом Win32. Никаких GUI-фреймворков:
// x/sys/windows уже в дереве, а Shell_NotifyIcon требует
// скрытого окна и оконной процедуры -- и это всё.
package tray

import (
	"embed"
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

//go:embed icons/*.ico
var iconFS embed.FS

type State int

const (
	StateOff State = iota
	StateOn
	StateError
)

const (
	wmTrayIcon = 0x0400 + 1 // WM_APP+1
	wmQuitReq  = 0x0400 + 2 // WM_APP+2: просьба завершиться
	wmClose    = 0x0010
	wmDestroy  = 0x0002
	wmCommand  = 0x0111

	wmRButtonUp    = 0x0205
	wmLButtonDbl   = 0x0203
	wmLButtonUp    = 0x0202
	nimAdd         = 0x0
	nimModify      = 0x1
	nimDelete      = 0x2
	nifMessage     = 0x1
	nifIcon        = 0x2
	nifTip         = 0x4
	mfString       = 0x0
	mfSeparator    = 0x800
	mfGrayed       = 0x1
	mfChecked      = 0x8
	tpmRightAlign  = 0x8
	tpmBottomAlign = 0x20
	tpmRightButton = 0x2
)

// Item: пункт меню. Действие выполняется в горутине,
// чтобы не подвешивать оконный цикл.
type Item struct {
	ID      uint32
	Text    string
	Do      func()
	Checked bool
	Grayed  bool
	Sep     bool
}

type Tray struct {
	hwnd    windows.HWND
	icons   [3]windows.Handle
	state   State
	tip     string
	Menu    func() []Item
	OnOpen  func() // левый щелчок
	items   map[uint32]func()
	classNm *uint16
}

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	pRegisterClassEx          = user32.NewProc("RegisterClassExW")
	pCreateWindowEx           = user32.NewProc("CreateWindowExW")
	pDefWindowProc            = user32.NewProc("DefWindowProcW")
	pGetMessage               = user32.NewProc("GetMessageW")
	pTranslateMessage         = user32.NewProc("TranslateMessage")
	pDispatchMessage          = user32.NewProc("DispatchMessageW")
	pPostQuitMessage          = user32.NewProc("PostQuitMessage")
	pDestroyWindow            = user32.NewProc("DestroyWindow")
	pPostMessage              = user32.NewProc("PostMessageW")
	pCreatePopupMenu          = user32.NewProc("CreatePopupMenu")
	pAppendMenu               = user32.NewProc("AppendMenuW")
	pDestroyMenu              = user32.NewProc("DestroyMenu")
	pTrackPopupMenu           = user32.NewProc("TrackPopupMenu")
	pGetCursorPos             = user32.NewProc("GetCursorPos")
	pSetForegroundWindow      = user32.NewProc("SetForegroundWindow")
	pCreateIconFromResourceEx = user32.NewProc("CreateIconFromResourceEx")
	pShellNotifyIcon          = shell32.NewProc("Shell_NotifyIconW")
	pGetModuleHandle          = kernel32.NewProc("GetModuleHandleW")
	pGetProcessWindowStation  = user32.NewProc("GetProcessWindowStation")
	pGetUserObjectInformation = user32.NewProc("GetUserObjectInformationW")
)

type wndClassEx struct {
	size, style                        uint32
	wndProc                            uintptr
	clsExtra, wndExtra                 int32
	instance, icon, cursor, background windows.Handle
	menuName, className                *uint16
	iconSm                             windows.Handle
}

type point struct{ X, Y int32 }

type msg struct {
	hwnd     windows.HWND
	message  uint32
	wParam   uintptr
	lParam   uintptr
	time     uint32
	pt       point
	lPrivate uint32
}

type notifyIconData struct {
	cbSize           uint32
	hWnd             windows.HWND
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            windows.Handle
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         windows.GUID
	hBalloonIcon     windows.Handle
}

func New(tip string) (*Tray, error) {
	t := &Tray{tip: tip, items: map[uint32]func(){}}
	for i, name := range []string{"icons/off.ico", "icons/on.ico", "icons/error.ico"} {
		h, err := loadIcon(name)
		if err != nil {
			return nil, fmt.Errorf("иконка %s: %w", name, err)
		}
		t.icons[i] = h
	}

	inst, _, _ := pGetModuleHandle.Call(0)
	t.classNm = windows.StringToUTF16Ptr("dpiswitchTrayClass")
	wc := wndClassEx{
		size:      uint32(unsafe.Sizeof(wndClassEx{})),
		wndProc:   syscall.NewCallback(t.wndProc),
		instance:  windows.Handle(inst),
		className: t.classNm,
	}
	if r, _, err := pRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return nil, fmt.Errorf("регистрация класса окна: %w", err)
	}
	// окно скрытое и нужно только как получатель сообщений трея
	hwnd, _, err := pCreateWindowEx.Call(0,
		uintptr(unsafe.Pointer(t.classNm)),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("dpiswitch"))),
		0, 0, 0, 0, 0, 0, 0, inst, 0)
	if hwnd == 0 {
		return nil, fmt.Errorf("создание окна: %w", err)
	}
	t.hwnd = windows.HWND(hwnd)

	// GUID у иконки НЕ используем. Windows связывает его с конкретным
	// файлом программы: после обновления бинаря связь рвётся, и оболочка
	// перестаёт показывать иконку вовсе. Проверено на практике -- трей
	// исчезал после каждой подмены exe. Призраки от аварийно убитых
	// процессов -- меньшее зло, чем пропавшая иконка.
	if err := t.notify(nimAdd); err != nil {
		log.Printf("трей: первая попытка добавить иконку не удалась: %v", err)
		// прежняя запись могла остаться от убитой копии
		_ = t.notify(nimDelete)
		if err2 := t.notify(nimAdd); err2 != nil {
			log.Printf("трей: повторная попытка тоже не удалась: %v", err2)
			return nil, err2
		}
		log.Println("трей: иконка добавлена со второй попытки")
	} else {
		log.Println("трей: иконка добавлена")
	}
	// рабочий стол, к которому привязан процесс: если это не
	// WinSta0\Default, иконки не будет видно, сколько ни добавляй
	log.Printf("трей: рабочая станция %q, окно %v", stationName(), t.hwnd)
	return t, nil
}

func loadIcon(name string) (windows.Handle, error) {
	b, err := iconFS.ReadFile(name)
	if err != nil {
		return 0, err
	}
	// пропускаем ICONDIR и ICONDIRENTRY: CreateIconFromResourceEx
	// ждёт сам образ, а не файл целиком
	if len(b) < 22 {
		return 0, fmt.Errorf("слишком короткий ico")
	}
	img := b[22:]
	h, _, err := pCreateIconFromResourceEx.Call(
		uintptr(unsafe.Pointer(&img[0])), uintptr(len(img)),
		1, 0x00030000, 32, 32, 0)
	if h == 0 {
		return 0, err
	}
	return windows.Handle(h), nil
}

func (t *Tray) data() *notifyIconData {
	d := &notifyIconData{
		cbSize:           uint32(unsafe.Sizeof(notifyIconData{})),
		hWnd:             t.hwnd,
		uID:              1,
		uFlags:           nifMessage | nifIcon | nifTip,
		uCallbackMessage: wmTrayIcon,
		hIcon:            t.icons[t.state],
	}
	copy(d.szTip[:], windows.StringToUTF16(t.tip))
	d.szTip[len(d.szTip)-1] = 0
	return d
}

func (t *Tray) notify(action uint32) error {
	r, _, err := pShellNotifyIcon.Call(uintptr(action), uintptr(unsafe.Pointer(t.data())))
	if r == 0 {
		return fmt.Errorf("Shell_NotifyIcon: %w", err)
	}
	return nil
}

// SetState меняет иконку и подсказку. Безопасно звать из любой горутины:
// Shell_NotifyIcon не требует принадлежности к потоку окна.
func (t *Tray) SetState(s State, tip string) {
	t.state = s
	if len(tip) > 120 {
		tip = tip[:120]
	}
	t.tip = tip
	_ = t.notify(nimModify)
}

func (t *Tray) wndProc(hwnd windows.HWND, message uint32, wParam, lParam uintptr) uintptr {
	switch message {
	case wmTrayIcon:
		switch uint32(lParam) {
		case wmRButtonUp:
			t.showMenu()
		case wmLButtonUp, wmLButtonDbl:
			// двойной щелчок обрабатываем так же: иначе первый клик
			// уже открыл бы интерфейс, а второй открыл бы его повторно
			if t.OnOpen != nil {
				go t.OnOpen()
			}
		}
		return 0
	case wmCommand:
		id := uint32(wParam & 0xffff)
		if fn, ok := t.items[id]; ok && fn != nil {
			go fn() // действие может быть долгим, окно блокировать нельзя
		}
		return 0
	case wmQuitReq:
		// разрушение окна выполняется здесь, в потоке цикла сообщений:
		// из другого потока DestroyWindow молча не сработает
		if err := t.notify(nimDelete); err != nil {
			log.Printf("трей: иконка не снята: %v", err)
		}
		pDestroyWindow.Call(uintptr(t.hwnd))
		return 0
	case wmDestroy:
		pPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := pDefWindowProc.Call(uintptr(hwnd), uintptr(message), wParam, lParam)
	return r
}

func (t *Tray) showMenu() {
	if t.Menu == nil {
		return
	}
	hmenu, _, _ := pCreatePopupMenu.Call()
	if hmenu == 0 {
		return
	}
	defer pDestroyMenu.Call(hmenu)

	t.items = map[uint32]func(){}
	for _, it := range t.Menu() {
		if it.Sep {
			pAppendMenu.Call(hmenu, mfSeparator, 0, 0)
			continue
		}
		var flags uintptr = mfString
		if it.Checked {
			flags |= mfChecked
		}
		if it.Grayed {
			flags |= mfGrayed
		}
		t.items[it.ID] = it.Do
		pAppendMenu.Call(hmenu, flags, uintptr(it.ID),
			uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(it.Text))))
	}

	var pt point
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	// без этого меню не закроется по щелчку мимо -- известная
	// особенность всплывающих меню у окон без фокуса
	pSetForegroundWindow.Call(uintptr(t.hwnd))
	pTrackPopupMenu.Call(hmenu, tpmRightAlign|tpmBottomAlign|tpmRightButton,
		uintptr(pt.X), uintptr(pt.Y), 0, uintptr(t.hwnd), 0)
}

// Loop крутит цикл сообщений. Обязан выполняться в том же потоке,
// где создано окно, поэтому вызывающий делает runtime.LockOSThread.
func (t *Tray) Loop() {
	var m msg
	for {
		r, _, _ := pGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			return
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
}

// Quit безопасен из любой горутины: пункты меню выполняются в
// отдельных потоках, а DestroyWindow обязан вызываться в том, где
// окно создано. Поэтому просто отправляем окну сообщение, а всю
// работу делает оконная процедура.
//
// Раньше здесь был прямой DestroyWindow из чужого потока: он молча
// не срабатывал, окно оставалось жить, процесс не завершался и держал
// мьютекс -- следующий запуск считал программу уже работающей,
// открывал браузер и выходил без иконки.
func (t *Tray) Quit() {
	pPostMessage.Call(uintptr(t.hwnd), wmQuitReq, 0, 0)
}

// stationName: к какой оконной станции привязан процесс.
// Интерактивный рабочий стол -- только WinSta0. Процесс, запущенный
// из службы или из неинтерактивного контекста, попадает в другую
// станцию, и его иконка в трее не появится никогда.
func stationName() string {
	h, _, _ := pGetProcessWindowStation.Call()
	if h == 0 {
		return "нет станции"
	}
	buf := make([]uint16, 256)
	var n uint32
	r, _, _ := pGetUserObjectInformation.Call(h, 2, // UOI_NAME
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2),
		uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return "неизвестно"
	}
	return windows.UTF16ToString(buf)
}
