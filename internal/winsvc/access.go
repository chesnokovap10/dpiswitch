package winsvc

import (
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// mgr.Connect() запрашивает SC_MANAGER_ALL_ACCESS, а это права
// администратора: из обычной сессии вызов падает, и трей решает,
// что служба не установлена. Права на старт-стоп мы выдали через
// sdset именно чтобы обходиться без элевации -- значит и открывать
// надо ровно тем, что нужно, а не всем подряд.
const (
	scmLimited = windows.SC_MANAGER_CONNECT | windows.SC_MANAGER_ENUMERATE_SERVICE
	svcLimited = windows.SERVICE_QUERY_STATUS | windows.SERVICE_QUERY_CONFIG |
		windows.SERVICE_START | windows.SERVICE_STOP
)

// openLimited открывает службу правами, доступными обычному
// пользователю. Закрывать возвращённый handle обязан вызывающий.
func openLimited() (*mgr.Service, func(), error) {
	scm, err := windows.OpenSCManager(nil, nil, scmLimited)
	if err != nil {
		return nil, nil, fmt.Errorf("диспетчер служб: %w", err)
	}
	name, err := windows.UTF16PtrFromString(Name)
	if err != nil {
		windows.CloseServiceHandle(scm)
		return nil, nil, err
	}
	h, err := windows.OpenService(scm, name, svcLimited)
	if err != nil {
		windows.CloseServiceHandle(scm)
		return nil, nil, err
	}
	// mgr.Service -- просто пара имя+handle, поэтому его методы
	// (Query, Start, Control, Config) работают с нашим handle
	s := &mgr.Service{Name: Name, Handle: h}
	closer := func() {
		windows.CloseServiceHandle(h)
		windows.CloseServiceHandle(scm)
	}
	return s, closer, nil
}
