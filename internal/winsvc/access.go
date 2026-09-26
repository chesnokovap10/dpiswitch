package winsvc

import (
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// mgr.Connect() requests SC_MANAGER_ALL_ACCESS, which needs administrator
// rights: from a normal session the call fails and the tray concludes the
// service is not installed. Start/stop rights were granted via sdset exactly
// to avoid elevation -- so open with just what is needed, not everything.
const (
	scmLimited = windows.SC_MANAGER_CONNECT | windows.SC_MANAGER_ENUMERATE_SERVICE
	// what every signed-in user may do: see the service. Starting and
	// stopping are the owner's, asked for by Start and Stop alone -- asked
	// for always, they would keep every other user from seeing it at all.
	svcQuery = windows.SERVICE_QUERY_STATUS | windows.SERVICE_QUERY_CONFIG
)

// openLimited opens the service with access -- rights a normal user may
// hold. The caller must close the returned handle.
func openLimited(access uint32) (*mgr.Service, func(), error) {
	scm, err := windows.OpenSCManager(nil, nil, scmLimited)
	if err != nil {
		return nil, nil, fmt.Errorf("service manager: %w", err)
	}
	name, err := windows.UTF16PtrFromString(Name)
	if err != nil {
		windows.CloseServiceHandle(scm)
		return nil, nil, err
	}
	h, err := windows.OpenService(scm, name, access)
	if err != nil {
		windows.CloseServiceHandle(scm)
		return nil, nil, err
	}
	// mgr.Service is just a name+handle pair, so its methods
	// (Query, Start, Control, Config) work with our handle
	s := &mgr.Service{Name: Name, Handle: h}
	closer := func() {
		windows.CloseServiceHandle(h)
		windows.CloseServiceHandle(scm)
	}
	return s, closer, nil
}
