package ctl

import (
	"dpiswitch/internal/winexec"
	"sync"
	"time"

	"crypto/sha256"
	"encoding/hex"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// диапазон fake-ip из конфига mihomo: 198.18.0.1/16
var _, fakeIPRange, _ = net.ParseCIDR("198.18.0.0/15")

var (
	netIDMu   sync.Mutex
	netIDVal  string
	netIDWhen time.Time
)

// networkID кэшируется: он опрашивает route и arp, то есть запускает
// процессы, а статус в трее обновляется каждые несколько секунд.
// Смена сети за полминуты не потеряется -- цикл контроллера длиннее.
func networkID() string {
	netIDMu.Lock()
	defer netIDMu.Unlock()
	if netIDVal != "" && time.Since(netIDWhen) < 30*time.Second {
		return netIDVal
	}
	netIDVal = computeNetworkID()
	netIDWhen = time.Now()
	return netIDVal
}

func computeNetworkID() string {
	// Идентичность сети -- это шлюз и его MAC, и только они.
	//
	// Раньше сюда шли адреса ВСЕХ интерфейсов, и появление любого
	// лишнего адаптера (Bluetooth с APIPA, псевдоадаптер другого VPN)
	// считалось сменой сети: накопленные вердикты разом обнулялись.
	// Проверено на практике -- 192 домена улетели в пустоту.
	if gw := defaultGateway(); gw != "" {
		parts := []string{"gw=" + gw}
		if mac := arpMAC(gw); mac != "" {
			// отличает разные сети с одинаковым 192.168.1.x
			parts = append(parts, "mac="+mac)
		}
		sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
		return hex.EncodeToString(sum[:])[:16]
	}

	// шлюза нет -- падаем на подсети, но только на настоящие:
	// APIPA означает, что DHCP не ответил, и адрес там случайный
	nets := localNets()
	if len(nets) == 0 {
		return "unknown"
	}
	sort.Strings(nets)
	sum := sha256.Sum256([]byte(strings.Join(nets, "|")))
	return hex.EncodeToString(sum[:])[:16]
}

// парсим по числовым полям, а не по заголовкам: вывод route локализован
// поля: сеть, маска, шлюз, интерфейс, метрика
var zeroRoute = regexp.MustCompile(`^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s+\S+\s+(\d+)`)

// defaultGateway: шлюз ФИЗИЧЕСКОЙ сети.
//
// Маршрутов по умолчанию два: через сетевую карту и через наш TUN
// (198.18.0.2). Порядок строк в выводе route не гарантирован: после
// переподключения Wi-Fi первой оказалась строка TUN, и собственный
// туннель был принят за новую сеть -- с пустой памятью вердиктов.
// Поэтому TUN отбрасываем, а из остальных берём наименьшую метрику.
func defaultGateway() string {
	out, err := winexec.Output("route", "print", "-4", "0.0.0.0")
	if err != nil {
		return ""
	}
	return pickGateway(string(out))
}

func pickGateway(out string) string {
	best, bestMetric := "", -1
	for _, line := range strings.Split(out, "\n") {
		m := zeroRoute.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ip := net.ParseIP(m[1])
		if ip == nil || fakeIPRange.Contains(ip) {
			continue
		}
		metric, _ := strconv.Atoi(m[2])
		if bestMetric < 0 || metric < bestMetric {
			best, bestMetric = m[1], metric
		}
	}
	return best
}

var macRe = regexp.MustCompile(`([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}`)

func arpMAC(ip string) string {
	out, err := winexec.Output("arp", "-a", ip)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, ip) {
			if m := macRe.FindString(line); m != "" {
				return strings.ToLower(m)
			}
		}
	}
	return ""
}

func localNets() []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok || n.IP.To4() == nil {
				continue
			}
			// собственный TUN mihomo пропускаем: иначе идентификатор
			// зависит от того, поднят ли туннель, и память раздваивается
			// на одну и ту же физическую сеть
			if fakeIPRange.Contains(n.IP) {
				continue
			}
			out = append(out, "net="+n.String())
		}
	}
	return out
}
