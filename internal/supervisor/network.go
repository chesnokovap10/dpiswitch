package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// --- присутствие физической сети ---

// fake-ip и адрес самого TUN: интерфейс ядра не считается сетью,
// иначе проверка всегда была бы положительной
var tunRange = mustCIDR("198.18.0.0/15")

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// physicalNetwork: есть ли хоть один рабочий сетевой интерфейс помимо
// нашего TUN. После перезагрузки Wi-Fi поднимается позже службы, и
// запускать ядро в пустоту бессмысленно -- оно только сожжёт попытки.
func physicalNetwork() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := n.IP.To4()
			if ip == nil || tunRange.Contains(ip) {
				continue
			}
			// 169.254.x.x -- адрес без DHCP: связи с сетью ещё нет
			if ip[0] == 169 && ip[1] == 254 {
				continue
			}
			return true
		}
	}
	return false
}

// --- уведомление о смене сети ---

var (
	iphlpapi          = windows.NewLazySystemDLL("iphlpapi.dll")
	pNotifyAddrChange = iphlpapi.NewProc("NotifyAddrChange")
)

// watchNetworkChanges шлёт сигнал, когда меняются адреса интерфейсов:
// подключили Wi-Fi, переключили сеть, вытащили кабель. Ждать общего
// опроса в такие моменты незачем -- проверять надо сразу.
func watchNetworkChanges(ctx context.Context, notify func()) {
	for {
		if ctx.Err() != nil {
			return
		}
		var handle windows.Handle
		var ov windows.Overlapped
		ev, err := windows.CreateEvent(nil, 1, 0, nil)
		if err != nil {
			time.Sleep(10 * time.Second)
			continue
		}
		ov.HEvent = ev

		r, _, _ := pNotifyAddrChange.Call(
			uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(&ov)))
		// ERROR_IO_PENDING -- нормальный путь: уведомление придёт позже
		if r != uintptr(syscall.ERROR_IO_PENDING) && r != 0 {
			windows.CloseHandle(ev)
			time.Sleep(10 * time.Second)
			continue
		}

		// ждём событие, но не дольше минуты -- иначе отмена контекста
		// не разбудит нас до следующей смены адреса
		res, _ := windows.WaitForSingleObject(ev, 60000)
		windows.CloseHandle(ev)
		if ctx.Err() != nil {
			return
		}
		if res == windows.WAIT_OBJECT_0 {
			notify()
		}
	}
}

// --- проверка живости туннеля ---

type healthChecker struct {
	apiAddr string
	secret  string
	proxy   string
	client  *http.Client
}

func newHealthChecker(apiAddr, secret, proxy string) *healthChecker {
	return &healthChecker{
		apiAddr: apiAddr, secret: secret, proxy: proxy,
		client: &http.Client{Timeout: 12 * time.Second},
	}
}

// alive спрашивает у ядра задержку через сам туннель. Это честная
// проверка сквозной работы: поднятый TUN при мёртвом пире выглядит
// снаружи нормально, а трафик при этом уходит в никуда.
func (h *healthChecker) alive() (bool, string) {
	u := fmt.Sprintf("http://%s/proxies/%s/delay?timeout=5000&url=%s",
		h.apiAddr, url.PathEscape(h.proxy),
		url.QueryEscape("http://cp.cloudflare.com/generate_204"))
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return false, err.Error()
	}
	if h.secret != "" {
		req.Header.Set("Authorization", "Bearer "+h.secret)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		// само ядро недоступно -- это отдельная беда, но лечится тем же
		return false, "API ядра не отвечает: " + trim(err.Error())
	}
	defer resp.Body.Close()

	var body struct {
		Delay   int    `json:"delay"`
		Message string `json:"message"`
	}
	json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusOK || body.Delay == 0 {
		msg := body.Message
		if msg == "" {
			msg = resp.Status
		}
		return false, trim(msg)
	}
	return true, fmt.Sprintf("%d мс", body.Delay)
}

func trim(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 90 {
		return s[:90] + "…"
	}
	return s
}

// NetworkUp: есть ли физическая сеть. Нужна интерфейсу, чтобы
// отличить "туннель сломался" от "сети нет вообще".
func NetworkUp() bool { return physicalNetwork() }

// TunnelAlive: проверка снаружи службы -- ею пользуется трей,
// у которого нет доступа к состоянию супервизора.
func TunnelAlive(apiAddr, secret, proxy string) (bool, string) {
	return newHealthChecker(apiAddr, secret, proxy).alive()
}

// foreignTunnel: поднят ли ЧУЖОЙ туннельный адаптер.
//
// Если параллельно запущен другой клиент WireGuard с тем же ключом,
// сервер перебивает сессии: наш туннель падает, мы переподнимаем ядро,
// сессия снова перебивается -- и так по кругу. Перезапуск тут не лечит,
// а мешает, поэтому в такой ситуации мы просто не трогаем ядро.
func foreignTunnel() (bool, string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false, ""
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := ifc.Name
		if name == "Meta" || strings.EqualFold(name, "Meta") {
			continue // наш собственный
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok || n.IP.To4() == nil || tunRange.Contains(n.IP.To4()) {
				continue
			}
			// туннельные интерфейсы без широковещания и без шлюза:
			// признак point-to-point, как у WireGuard
			if ifc.Flags&net.FlagPointToPoint != 0 ||
				(ifc.Flags&net.FlagBroadcast == 0 && ifc.Flags&net.FlagMulticast == 0) {
				return true, name
			}
		}
	}
	return false, ""
}
