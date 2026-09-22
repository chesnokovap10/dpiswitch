package supervisor

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"dpiswitch/internal/paths"
)

// Job Object: ядро обязано умереть вместе со службой.
//
// Без этого убитая или аварийно завершённая служба оставляет mihomo
// сиротой -- с поднятым TUN и переписанными маршрутами, но без всякого
// присмотра. Машина остаётся без сети, и чинить некому: супервизора
// уже нет, а ядро само себя не остановит.
func newKillJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

func assignToJob(job windows.Handle, pid int) error {
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
		false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.AssignProcessToJobObject(job, h)
}

// killOrphans снимает ядра, оставшиеся от прежнего запуска.
//
// Сюда попадаем после жёсткого выключения или падения службы. Сравниваем
// полный путь, а не имя: чужой mihomo (например, запущенный вручную)
// трогать нельзя.
func killOrphans() {
	self := os.Getpid()
	target := strings.ToLower(paths.Mihomo())

	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snap)

	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if err := windows.Process32First(snap, &e); err != nil {
		return
	}
	for {
		name := strings.ToLower(windows.UTF16ToString(e.ExeFile[:]))
		pid := int(e.ProcessID)
		if name == strings.ToLower(filepath.Base(target)) && pid != self {
			if path := processPath(uint32(pid)); strings.EqualFold(path, target) {
				log.Printf("снимаю осиротевшее ядро, pid %d", pid)
				if h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid)); err == nil {
					windows.TerminateProcess(h, 1)
					windows.CloseHandle(h)
				}
			}
		}
		if err := windows.Process32Next(snap, &e); err != nil {
			return
		}
	}
}

func processPath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}
