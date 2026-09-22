// Идентичность сеанса входа и стабильный порт интерфейса.
//
// Порт не должен прыгать при каждом запуске программы: открытая вкладка
// и закладка обязаны продолжать работать. Но и намертво зашивать его
// нельзя -- он может оказаться занят. Компромисс: порт выводится из LUID
// сеанса входа, поэтому постоянен внутри сессии и меняется после
// выхода из системы или перезагрузки.
package session

import (
	"fmt"
	"hash/fnv"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TOKEN_STATISTICS: в x/sys структуры нет, только константа класса,
// поэтому раскладка описана вручную по заголовкам Windows.
type tokenStatistics struct {
	TokenID            windows.LUID
	AuthenticationID   windows.LUID // LUID сеанса входа -- то, что нам нужно
	ExpirationTime     int64
	TokenType          uint32
	ImpersonationLevel uint32
	DynamicCharged     uint32
	DynamicAvailable   uint32
	GroupCount         uint32
	PrivilegeCount     uint32
	ModifiedID         windows.LUID
}

// LogonID возвращает идентификатор текущего сеанса входа.
func LogonID() (uint64, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_QUERY, &token); err != nil {
		return 0, fmt.Errorf("токен процесса: %w", err)
	}
	defer token.Close()

	var st tokenStatistics
	size := uint32(unsafe.Sizeof(st))
	if err := windows.GetTokenInformation(token, windows.TokenStatistics,
		(*byte)(unsafe.Pointer(&st)), size, &size); err != nil {
		return 0, fmt.Errorf("статистика токена: %w", err)
	}
	return uint64(uint32(st.AuthenticationID.HighPart))<<32 |
		uint64(st.AuthenticationID.LowPart), nil
}

const (
	portBase = 49152 // начало динамического диапазона
	portSpan = 16000
)

// Port: первый порт-кандидат для этого сеанса. Нужен второму
// экземпляру, чтобы открыть интерфейс уже работающего.
func Port() int {
	id, err := LogonID()
	if err != nil {
		return portBase
	}
	h := fnv.New32a()
	fmt.Fprintf(h, "dpiswitch:%d", id)
	return portBase + int(h.Sum32()%portSpan)
}

// Listen поднимает слушатель на порту, выведенном из сеанса входа.
// Если порт занят (другим приложением или зависшей копией), идём
// дальше детерминированным шагом -- так адрес остаётся предсказуемым.
func Listen() (net.Listener, error) {
	id, err := LogonID()
	if err != nil {
		// без идентификатора сеанса падать незачем: берём любой
		// свободный порт, просто теряем постоянство адреса
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
	return nil, fmt.Errorf("не удалось занять порт: %w", lastErr)
}
