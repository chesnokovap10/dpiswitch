package main

// dpiswitch.exe works as its own installer. Started from anywhere (Downloads,
// say), it is the tray; "Install service" copies it to Program Files and
// registers that copy (see winsvc.Install). Then the tray moves there too: it
// starts the installed copy and exits, autostart is pointed at the installed
// copy, and a first install puts a shortcut on the desktop. The file the user
// started is no longer used and may be deleted.
//
// A newer build started while the installed tray runs is an update: it asks,
// closes the running tray (its file is to be replaced), reinstalls from itself
// and starts the installed copy.

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"dpiswitch/internal/autostart"
	"dpiswitch/internal/version"
	"dpiswitch/internal/winexec"
	"dpiswitch/internal/winsvc"
)

// quitTray ends the running tray; set by runTray
var quitTray = func() {}

func hasArg(a string) bool {
	for _, x := range os.Args[1:] {
		if strings.EqualFold(x, a) {
			return true
		}
	}
	return false
}

func sameFile(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// installFor: install or reinstall from this binary for the current user,
// then move the tray to the installed copy. The administrator prompt is
// answered in its own time: the wait is in the background.
func installFor(verb string) error {
	first := !fileExists(winsvc.InstalledExe())
	u, err := user.Current()
	if err != nil {
		return err
	}
	h, err := runasWait(verb + " --owner " + u.Uid)
	if err != nil {
		return err
	}
	go func() {
		defer windows.CloseHandle(h)
		windows.WaitForSingleObject(h, windows.INFINITE)
		var code uint32
		if windows.GetExitCodeProcess(h, &code); code != 0 {
			log.Printf("tray: %s ended with code %d, the tray stays where it is", verb, code)
			return
		}
		moveTray(first)
	}()
	return nil
}

// moveTray: the tray goes to the installed copy -- or, running from it
// already, just sets itself up there.
func moveTray(first bool) {
	exe := winsvc.InstalledExe()
	if sameFile(os.Args[0], exe) || sameFile(selfExe(), exe) {
		settle(first)
		return
	}
	args := "tray --moved"
	if first {
		args += " --first"
	}
	if err := shellOpen(exe, args); err != nil {
		log.Printf("tray: the installed copy did not start: %v", err)
		return
	}
	log.Printf("tray: moved to %s", exe)
	quitTray()
}

func selfExe() string {
	p, _ := os.Executable()
	return p
}

// settle: what a tray that has just moved to the installed copy does --
// autostart follows it (on if it was on for any copy, or on a first
// install), and a first install gets a desktop shortcut.
func settle(first bool) {
	if first || autostart.Present() {
		if err := autostart.Set(true); err != nil {
			log.Printf("tray: autostart not set: %v", err)
		}
	}
	if first {
		if err := desktopShortcut(); err != nil {
			log.Printf("tray: no desktop shortcut: %v", err)
		}
	}
}

// desktopShortcut puts "DPI Switch" on the user's desktop, pointing at the
// installed copy.
func desktopShortcut() error {
	desk, err := windows.KnownFolderPath(windows.FOLDERID_Desktop, 0)
	if err != nil {
		return err
	}
	exe := winsvc.InstalledExe()
	// paths go through the environment: nothing in them is parsed as script
	cmd := winexec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:DPI_LNK); `+
			`$s.TargetPath = $env:DPI_EXE; $s.Arguments = 'tray'; `+
			`$s.WorkingDirectory = (Split-Path $env:DPI_EXE); $s.IconLocation = $env:DPI_EXE + ',0'; `+
			`$s.Description = 'DPI Switch'; $s.Save()`)
	cmd.Env = append(os.Environ(), "DPI_LNK="+filepath.Join(desk, "DPI Switch.lnk"), "DPI_EXE="+exe)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// waitMutex: a tray that has just been started by the one it replaces
// waits for that one to exit
func waitMutex() bool {
	for i := 0; i < 40; i++ {
		if !alreadyRunning() {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

// updateOffer: this binary is started while the installed tray runs. The
// same build just opens the UI (false); another build offers to update.
func updateOffer() bool {
	exe := winsvc.InstalledExe()
	if sameFile(selfExe(), exe) || !fileExists(exe) || !winsvc.Installed() || winsvc.SameBuild() {
		return false
	}
	r, _ := windows.MessageBox(0, ptr(fmt.Sprintf(
		T("Install DPI Switch %s over the installed version?"), version.Version)),
		ptr("DPI Switch"), windows.MB_YESNO|windows.MB_ICONQUESTION)
	if r != 6 { // IDYES
		return true
	}
	// the running tray -- wherever it runs from -- holds the mutex, and the
	// installed one its file open: it goes first
	closeTrays()
	u, err := user.Current()
	if err != nil {
		msgBox("DPI Switch", err.Error(), 0x10)
		return true
	}
	h, err := runasWait("reinstall --owner " + u.Uid)
	if err != nil {
		_ = shellOpen(exe, "tray") // declined: the old one back
		return true
	}
	windows.WaitForSingleObject(h, windows.INFINITE)
	var code uint32
	windows.GetExitCodeProcess(h, &code)
	windows.CloseHandle(h)
	if code != 0 {
		_ = shellOpen(exe, "tray") // not updated: the old one back
		return true
	}
	_ = shellOpen(exe, "tray --moved")
	return true
}

// closeTrays ends every other tray of this session
func closeTrays() {
	var sess uint32
	windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sess)
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if !strings.EqualFold(windows.UTF16ToString(e.ExeFile[:]), "dpiswitch.exe") || e.ProcessID == windows.GetCurrentProcessId() {
			continue
		}
		var s uint32
		if windows.ProcessIdToSessionId(e.ProcessID, &s) != nil || s != sess {
			continue
		}
		h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, e.ProcessID)
		if err != nil {
			continue
		}
		windows.TerminateProcess(h, 0)
		windows.WaitForSingleObject(h, 5000)
		windows.CloseHandle(h)
	}
}

func ptr(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func shellOpen(file, args string) error {
	pAllowSetForegroundWindow.Call(asfwAny)
	return windows.ShellExecute(0, ptr("open"), ptr(file), ptr(args), ptr(filepath.Dir(file)), windows.SW_SHOWNORMAL)
}

// shellExecuteInfo: SHELLEXECUTEINFOW
type shellExecuteInfo struct {
	cbSize         uint32
	fMask          uint32
	hwnd           uintptr
	lpVerb         *uint16
	lpFile         *uint16
	lpParameters   *uint16
	lpDirectory    *uint16
	nShow          int32
	hInstApp       uintptr
	lpIDList       uintptr
	lpClass        *uint16
	hkeyClass      uintptr
	dwHotKey       uint32
	hIconOrMonitor uintptr
	hProcess       windows.Handle
}

var pShellExecuteEx = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

// runasWait starts this binary elevated with args and returns its process,
// to be waited for and closed by the caller.
func runasWait(args string) (windows.Handle, error) {
	exe := selfExe()
	si := shellExecuteInfo{
		fMask:        0x40, // SEE_MASK_NOCLOSEPROCESS
		lpVerb:       ptr("runas"),
		lpFile:       ptr(exe),
		lpParameters: ptr(args),
		lpDirectory:  ptr(filepath.Dir(exe)),
		nShow:        windows.SW_NORMAL,
	}
	si.cbSize = uint32(unsafe.Sizeof(si))
	if r, _, err := pShellExecuteEx.Call(uintptr(unsafe.Pointer(&si))); r == 0 {
		return 0, err
	}
	if si.hProcess == 0 {
		return 0, fmt.Errorf("the elevated process was not returned")
	}
	return si.hProcess, nil
}
