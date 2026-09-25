// Tray icon on plain Win32. No GUI frameworks:
// x/sys/windows is already a dependency, and Shell_NotifyIcon needs
// a hidden window and a window procedure -- that's all.
package tray

import (
	"embed"
	"encoding/binary"
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

//go:embed icons/*.ico
var iconFS embed.FS

// IconFile: an icon's .ico file as is -- the web UI shows the tray's own
// "off" icon as the page's.
func IconFile(name string) ([]byte, error) { return iconFS.ReadFile("icons/" + name) }

type State int

const (
	StateOff State = iota
	StateOn
	StateError
)

const (
	wmTrayIcon = 0x0400 + 1 // WM_APP+1
	wmQuitReq  = 0x0400 + 2 // WM_APP+2: quit request
	smCxSmIcon = 49         // SM_CXSMICON: small icon width at the current DPI
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

// Item: a menu entry. The action runs in a goroutine
// so the window loop is never blocked.
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
	OnOpen  func() // left click
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
	pGetSystemMetrics         = user32.NewProc("GetSystemMetrics")
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
			return nil, fmt.Errorf("icon %s: %w", name, err)
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
		return nil, fmt.Errorf("registering the window class: %w", err)
	}
	// the window is hidden and only receives tray messages
	hwnd, _, err := pCreateWindowEx.Call(0,
		uintptr(unsafe.Pointer(t.classNm)),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("dpiswitch"))),
		0, 0, 0, 0, 0, 0, 0, inst, 0)
	if hwnd == 0 {
		return nil, fmt.Errorf("creating the window: %w", err)
	}
	t.hwnd = windows.HWND(hwnd)

	// No icon GUID is used. Windows binds it to a specific
	// program file: after the binary is updated the binding breaks and the shell
	// stops showing the icon entirely. Seen in practice -- the tray icon
	// vanished after every exe replacement. Ghost icons from crashed
	// processes are a lesser evil than a missing icon.
	if err := t.notify(nimAdd); err != nil {
		log.Printf("tray: first attempt to add the icon failed: %v", err)
		// a stale entry may be left by a killed copy
		_ = t.notify(nimDelete)
		if err2 := t.notify(nimAdd); err2 != nil {
			log.Printf("tray: the retry failed too: %v", err2)
			return nil, err2
		}
		log.Println("tray: icon added on the second attempt")
	} else {
		log.Println("tray: icon added")
	}
	// the desktop the process is attached to: if it is not
	// WinSta0\Default, the icon will never be visible
	log.Printf("tray: window station %q, window %v", stationName(), t.hwnd)
	return t, nil
}

func loadIcon(name string) (windows.Handle, error) {
	b, err := iconFS.ReadFile(name)
	if err != nil {
		return 0, err
	}
	// The .ico holds several sizes (16..32). Pick the one the tray actually
	// uses at the current display scale (SM_CXSMICON: 16 at 100%, 20 at 125%,
	// 24 at 150%...), so Windows does not blur a downscaled bitmap.
	// CreateIconFromResourceEx expects a single image, not the whole file.
	if len(b) < 6 {
		return 0, fmt.Errorf("ico too short")
	}
	want, _, _ := pGetSystemMetrics.Call(smCxSmIcon)
	if want == 0 {
		want = 16
	}
	n := int(binary.LittleEndian.Uint16(b[4:]))
	var img []byte
	best := 0
	for i := 0; i < n; i++ {
		e := b[6+16*i:]
		if len(e) < 16 {
			break
		}
		size := int(e[0])
		if size == 0 {
			size = 256
		}
		ln := binary.LittleEndian.Uint32(e[8:])
		off := binary.LittleEndian.Uint32(e[12:])
		if int(off)+int(ln) > len(b) {
			continue
		}
		// the smallest image not smaller than needed; otherwise the largest
		better := best == 0 ||
			(size >= int(want) && (best < int(want) || size < best)) ||
			(best < int(want) && size > best)
		if better {
			best, img = size, b[off:off+ln]
		}
	}
	if img == nil {
		return 0, fmt.Errorf("no usable image in %s", name)
	}
	h, _, err := pCreateIconFromResourceEx.Call(
		uintptr(unsafe.Pointer(&img[0])), uintptr(len(img)),
		1, 0x00030000, want, want, 0)
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

// SetState changes the icon and tooltip. Safe to call from any goroutine:
// Shell_NotifyIcon does not require the window's thread.
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
			// double click is handled the same way: otherwise the first click
			// would open the UI and the second would open it again
			if t.OnOpen != nil {
				go t.OnOpen()
			}
		}
		return 0
	case wmCommand:
		id := uint32(wParam & 0xffff)
		if fn, ok := t.items[id]; ok && fn != nil {
			go fn() // the action may take long; the window must not be blocked
		}
		return 0
	case wmQuitReq:
		// the window is destroyed here, on the message loop thread:
		// from another thread DestroyWindow silently does nothing
		if err := t.notify(nimDelete); err != nil {
			log.Printf("tray: icon not removed: %v", err)
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
	// without this the menu does not close on an outside click -- a known
	// quirk of popup menus for windows without focus
	pSetForegroundWindow.Call(uintptr(t.hwnd))
	pTrackPopupMenu.Call(hmenu, tpmRightAlign|tpmBottomAlign|tpmRightButton,
		uintptr(pt.X), uintptr(pt.Y), 0, uintptr(t.hwnd), 0)
}

// Loop runs the message loop. It must run on the same thread
// that created the window, so the caller does runtime.LockOSThread.
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

// Quit is safe from any goroutine: menu items run on
// separate threads, while DestroyWindow must be called on the one that
// created the window. So we just post a message to the window and
// the window procedure does the work.
//
// This used to call DestroyWindow directly from a foreign thread: it silently
// did nothing, the window stayed alive, the process never exited and held
// the mutex -- the next launch considered the program already running,
// opened the browser and exited without an icon.
func (t *Tray) Quit() {
	pPostMessage.Call(uintptr(t.hwnd), wmQuitReq, 0, 0)
}

// stationName: which window station the process is attached to.
// Only WinSta0 is interactive. A process started
// from a service or a non-interactive context lands in another
// station, and its tray icon will never appear.
func stationName() string {
	h, _, _ := pGetProcessWindowStation.Call()
	if h == 0 {
		return "no station"
	}
	buf := make([]uint16, 256)
	var n uint32
	r, _, _ := pGetUserObjectInformation.Call(h, 2, // UOI_NAME
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2),
		uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return "unknown"
	}
	return windows.UTF16ToString(buf)
}
