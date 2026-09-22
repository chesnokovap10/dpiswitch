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

// Job Object: the core must die together with the service.
//
// Otherwise a killed or crashed service leaves mihomo orphaned -- with TUN
// up and routes rewritten, but nobody watching it. The machine is left
// without network and nothing can fix it: the supervisor is gone and the
// core will not stop itself.
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

// killOrphans kills cores left over from a previous run.
//
// We get here after a hard power-off or a service crash. The full path is
// compared, not the name: someone else's mihomo (e.g. started by hand) must
// not be touched.
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
				log.Printf("killing orphaned core, pid %d", pid)
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
