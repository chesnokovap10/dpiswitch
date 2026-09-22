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
	"net"
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

// Listen opens a listener on the port derived from the logon session.
// If the port is taken (by another app or a hung copy), it steps forward
// deterministically -- so the address stays predictable.
func Listen() (net.Listener, error) {
	id, err := LogonID()
	if err != nil {
		// no reason to fail without a session id: take any free port,
		// we just lose the stable address
		return net.Listen("tcp", "127.0.0.1:0")
	}
	_ = id
	start := Port() - portBase

	var lastErr error
	for i := 0; i < 64; i++ {
		port := portBase + (start+i)%portSpan
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			return ln, nil
		}
		lastErr = err
	}
	if ln, err := net.Listen("tcp", "127.0.0.1:0"); err == nil {
		return ln, nil
	}
	return nil, fmt.Errorf("could not bind a port: %w", lastErr)
}
