// Программы, у которых сейчас есть сетевые сокеты.
//
// Нужно для выбора исключений: имя exe пользователь обычно не помнит,
// а браузер из соображений безопасности не отдаёт полный путь файла,
// выбранного в диалоге. Проще показать то, что прямо сейчас в сети.
//
// TUN на это не влияет: он работает на уровне IP-пакетов, а сокеты
// по-прежнему принадлежат самим программам.
package netprocs

import (
	"encoding/binary"
	"path/filepath"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi         = windows.NewLazySystemDLL("iphlpapi.dll")
	pGetExtendedTcp  = iphlpapi.NewProc("GetExtendedTcpTable")
	pGetExtendedUdp  = iphlpapi.NewProc("GetExtendedUdpTable")
	errInsufficient  = uintptr(windows.ERROR_INSUFFICIENT_BUFFER)
	tcpTableOwnerAll = uintptr(5) // TCP_TABLE_OWNER_PID_ALL
	udpTableOwnerPID = uintptr(1) // UDP_TABLE_OWNER_PID
)

type Proc struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Conns int    `json:"conns"`
}

// раскладка строк таблиц по заголовкам Windows: смещение PID и размер строки
type table struct {
	proc    *windows.LazyProc
	family  uintptr
	class   uintptr
	rowSize int
	pidOff  int
}

var tables = []table{
	{pGetExtendedTcp, windows.AF_INET, tcpTableOwnerAll, 24, 20},  // MIB_TCPROW_OWNER_PID
	{pGetExtendedTcp, windows.AF_INET6, tcpTableOwnerAll, 56, 52}, // MIB_TCP6ROW_OWNER_PID
	{pGetExtendedUdp, windows.AF_INET, udpTableOwnerPID, 12, 8},   // MIB_UDPROW_OWNER_PID
	{pGetExtendedUdp, windows.AF_INET6, udpTableOwnerPID, 28, 24}, // MIB_UDP6ROW_OWNER_PID
}

func pids(t table, count map[uint32]int) {
	var size uint32
	r, _, _ := t.proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, t.family, t.class, 0)
	if r != errInsufficient || size == 0 {
		return
	}
	// таблица может вырасти между вызовами -- берём с запасом
	size += 4096
	buf := make([]byte, size)
	r, _, _ = t.proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
		0, t.family, t.class, 0)
	if r != 0 {
		return
	}
	n := int(binary.LittleEndian.Uint32(buf))
	for i := 0; i < n; i++ {
		off := 4 + i*t.rowSize + t.pidOff
		if off+4 > len(buf) {
			break
		}
		count[binary.LittleEndian.Uint32(buf[off:])]++
	}
}

// Active возвращает программы с сокетами, по одной строке на exe.
// Системные процессы, чей путь недоступен обычному пользователю,
// пропускаются: исключать их всё равно бессмысленно.
func Active(skip ...string) []Proc {
	count := map[uint32]int{}
	for _, t := range tables {
		pids(t, count)
	}
	skipSet := map[string]bool{}
	for _, s := range skip {
		skipSet[strings.ToLower(s)] = true
	}

	byPath := map[string]*Proc{}
	for pid, n := range count {
		if pid == 0 || pid == 4 {
			continue
		}
		path := imagePath(pid)
		if path == "" || skipSet[strings.ToLower(filepath.Base(path))] {
			continue
		}
		key := strings.ToLower(path)
		if p, ok := byPath[key]; ok {
			p.Conns += n
			continue
		}
		byPath[key] = &Proc{Name: filepath.Base(path), Path: path, Conns: n}
	}
	out := make([]Proc, 0, len(byPath))
	for _, p := range byPath {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

func imagePath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}
