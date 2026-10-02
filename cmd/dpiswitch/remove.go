package main

// Removing the program: everything installing and running it left behind,
// except the file it was installed from -- that one is the user's.
//
// The tray asks, from the UI, for an elevated "remove" and waits for it:
//
//  1. (elevated) the other trays of the session close: they run the
//     installed file, which is to go;
//  2. (elevated) the service stops -- the core with it, and TUN and the
//     routes go -- and is deleted, its registry key (the owner) too;
//  3. (elevated) the data directory goes: configs, keys, lists, verdicts,
//     logs;
//  4. (elevated) a hidden cmd is left behind to delete Program Files\DPI
//     Switch, the core with it, and the tray's folder in the user's
//     profile: both are held open until the tray and this process exit, so
//     it retries for a minute;
//  5. (tray) declined or failed: nothing more, the tray stays. Done:
//     autostart and the desktop shortcut go -- they are the user's, and
//     the elevated copy may run as another account -- and the tray exits.

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"dpiswitch/internal/autostart"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/winexec"
	"dpiswitch/internal/winsvc"
)

// removeProgram: the tray's part. The administrator prompt is answered in
// its own time: the wait is in the background.
func removeProgram() error {
	h, err := runasWait(fmt.Sprintf(`remove --keep %d --local "%s"`,
		windows.GetCurrentProcessId(), filepath.Dir(paths.TrayLog())))
	if err != nil {
		return err
	}
	go func() {
		defer windows.CloseHandle(h)
		windows.WaitForSingleObject(h, windows.INFINITE)
		var code uint32
		if windows.GetExitCodeProcess(h, &code); code != 0 {
			log.Printf("tray: remove ended with code %d, the tray stays", code)
			return
		}
		if err := autostart.Set(false); err != nil {
			log.Printf("tray: autostart not removed: %v", err)
		}
		if desk, err := windows.KnownFolderPath(windows.FOLDERID_Desktop, 0); err == nil {
			_ = os.Remove(filepath.Join(desk, "DPI Switch.lnk"))
		}
		log.Println("tray: the program is removed, exiting")
		quitTray()
	}()
	return nil
}

// runRemove: the elevated part, "dpiswitch remove [--keep <tray pid>]
// [--local <tray folder>]". Its own message on failure; silent when done,
// the tray going away says it.
func runRemove() {
	keep := uint32(0)
	if v := argValue("--keep"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			keep = uint32(n)
		}
	}
	closeTraysBut(keep)
	if winsvc.Installed() {
		if err := winsvc.Uninstall(); err != nil {
			msgBox(T("Remove the program"), T("The program was not removed:")+"\n\n"+err.Error(), 0x10)
			os.Exit(1)
		}
	}
	data := paths.DataDir()
	// the core and the logs may be let go of a moment after the service
	// reports stopped
	var err error
	for i := 0; i < 20; i++ {
		if err = os.RemoveAll(data); err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		log.Printf("remove: %s: %v, left to the cleanup", data, err)
	}
	dirs := []string{winsvc.InstallDir(), data}
	if l := argValue("--local"); l != "" && strings.EqualFold(filepath.Base(l), paths.AppName) && filepath.IsAbs(l) {
		dirs = append(dirs, filepath.Clean(l))
	}
	if err := cleanupLater(dirs); err != nil {
		msgBox(T("Remove the program"), T("The service and the data are removed, but the program folder is not:")+
			"\n\n"+winsvc.InstallDir()+"\n\n"+err.Error(), 0x30)
	}
}

// cleanupLater: a hidden cmd deletes the folders once nothing holds them --
// the running binary cannot delete itself. It tries for about a minute.
// The paths come in through the environment and are quoted: nothing in
// them is read as a command.
func cleanupLater(dirs []string) error {
	var test, del []string
	env := os.Environ()
	for i, d := range dirs {
		v := fmt.Sprintf("DPI_RM%d", i)
		env = append(env, v+"="+d)
		del = append(del, fmt.Sprintf(`(if exist "%%%s%%" rd /s /q "%%%s%%")`, v, v))
		test = append(test, fmt.Sprintf(`if not exist "%%%s%%"`, v))
	}
	line := `cmd.exe /d /q /s /c "for /l %i in (1,1,60) do @(` + strings.Join(del, " & ") +
		" & (" + strings.Join(test, " ") + " exit) & ping -n 2 127.0.0.1 >nul)" + `"`
	cmd := winexec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"))
	cmd.SysProcAttr.CmdLine = line
	cmd.Env = env
	return cmd.Start()
}

func argValue(name string) string {
	for i, a := range os.Args {
		if strings.EqualFold(a, name) && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
	}
	return ""
}

// closeTraysBut ends the trays of this session, all but keep: the one that
// asked waits for the removal and exits itself.
func closeTraysBut(keep uint32) {
	var sess uint32
	windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sess)
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	self := windows.GetCurrentProcessId()
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if !strings.EqualFold(windows.UTF16ToString(e.ExeFile[:]), "dpiswitch.exe") ||
			e.ProcessID == self || e.ProcessID == keep {
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
