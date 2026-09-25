// Logon session identity and a stable UI port.
//
// The port must not jump on every launch: an open tab and a bookmark have
// to keep working. But it cannot be hardcoded either -- it may be taken.
// Compromise: the port is derived from the logon session LUID, so it is
// stable within a session and changes after sign-out or reboot.
package session

import (
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TOKEN_STATISTICS: x/sys has no struct, only the class constant, so the
// layout is written out by hand from the Windows headers.
type tokenStatistics struct {
	TokenID            windows.LUID
	AuthenticationID   windows.LUID // logon session LUID -- what we need
	ExpirationTime     int64
	TokenType          uint32
	ImpersonationLevel uint32
	DynamicCharged     uint32
	DynamicAvailable   uint32
	GroupCount         uint32
	PrivilegeCount     uint32
	ModifiedID         windows.LUID
}

// LogonID returns the current logon session identifier.
func LogonID() (uint64, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_QUERY, &token); err != nil {
		return 0, fmt.Errorf("process token: %w", err)
	}
	defer token.Close()

	var st tokenStatistics
	size := uint32(unsafe.Sizeof(st))
	if err := windows.GetTokenInformation(token, windows.TokenStatistics,
		(*byte)(unsafe.Pointer(&st)), size, &size); err != nil {
		return 0, fmt.Errorf("token statistics: %w", err)
	}
	return uint64(uint32(st.AuthenticationID.HighPart))<<32 |
		uint64(st.AuthenticationID.LowPart), nil
}

const (
	portBase = 49152 // start of the dynamic range
	portSpan = 16000
)

// Port: the first candidate port for this session. A second instance
// uses it to open the UI of the one already running.
func Port() int {
	id, err := LogonID()
	if err != nil {
		return portBase
	}
	h := fnv.New32a()
	fmt.Fprintf(h, "dpiswitch:%d", id)
	return portBase + int(h.Sum32()%portSpan)
}

// Candidates: the ports Listen tries, in its order.
func Candidates() []int {
	start := Port() - portBase
	out := make([]int, 64)
	for i := range out {
		out[i] = portBase + (start+i)%portSpan
	}
	return out
}

// Ports: where a running UI of this session may be -- the candidates, and
// last the port Listen fell back to when none of them was free. A second
// instance looks for the running one's UI among them: Listen steps past a
// taken port, and the second instance used to open the first candidate
// whatever answered there.
func Ports() []int {
	out := Candidates()
	if p, ok := fallbackPort(); ok {
		out = append(out, p)
	}
	return out
}

// fallbackFile: where Listen notes a port it took outside the candidates.
// Per user (the temp directory is) and per logon session (Port is).
func fallbackFile() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("dpiswitch-ui-%d.port", Port()))
}

func fallbackPort() (int, bool) {
	b, err := os.ReadFile(fallbackFile())
	if err != nil {
		return 0, false
	}
	p, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return p, err == nil && p > 0 && p <= 65535
}

// Listen opens a listener on the port derived from the logon session.
// If the port is taken (by another app or a hung copy), it steps forward
// deterministically -- so the address stays predictable. With every
// candidate taken, or no session id to derive them from, any free port
// does, and it is noted for Ports: a second instance could not find the UI
// on it, and opened the first candidate instead.
func Listen() (net.Listener, error) {
	var lastErr error
	if _, err := LogonID(); err == nil {
		for _, port := range Candidates() {
			ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err == nil {
				os.Remove(fallbackFile()) // a note left by an earlier run
				return ln, nil
			}
			lastErr = err
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if lastErr == nil {
			lastErr = err
		}
		return nil, fmt.Errorf("could not bind a port: %w", lastErr)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := os.WriteFile(fallbackFile(), []byte(strconv.Itoa(port)+"\n"), 0o644); err != nil {
		log.Printf("UI port %d not noted, a second copy will not find it: %v", port, err)
	}
	return ln, nil
}
