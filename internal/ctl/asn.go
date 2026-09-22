package ctl

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"
)

// Память вердиктов привязана к ПРОВАЙДЕРУ (номеру автономной системы),
// а не к точке подключения.
//
// Блокировки ставит провайдер, поэтому вердикты одинаково верны для
// любого роутера и диапазона в его сети. Раньше ключом был шлюз с его
// MAC, и переключение между 2.4 и 5 ГГц одного роутера (у диапазонов
// разные MAC) считалось новой сетью: память начиналась с нуля, и все
// сайты на время уходили в туннель.
//
// Шлюз остаётся "адресом подключения": по нему видно, что сеть
// сменилась, и по нему кэшируется найденный провайдер.

// asnCacheTTL: как часто перепроверять провайдера за тем же шлюзом
// (роутер могли переключить на другой канал связи)
const asnCacheTTL = 24 * time.Hour

type attachment struct {
	Net     string    `json:"net"` // AS12389
	Checked time.Time `json:"checked"`
}

// lookupASN узнаёт провайдера по внешнему адресу ПРЯМОГО пути.
// Через туннель ответом был бы провайдер VPS.
func lookupASN(directAddr string) (string, error) {
	cl := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{
			Scheme: "socks5", Host: directAddr})},
	}
	var ip struct {
		Data struct {
			IP string `json:"ip"`
		} `json:"data"`
	}
	if err := getJSON(cl, "https://stat.ripe.net/data/whats-my-ip/data.json", &ip); err != nil {
		return "", fmt.Errorf("внешний адрес: %w", err)
	}
	if ip.Data.IP == "" {
		return "", errors.New("внешний адрес не получен")
	}
	var info struct {
		Data struct {
			ASNs []string `json:"asns"`
		} `json:"data"`
	}
	if err := getJSON(cl, "https://stat.ripe.net/data/network-info/data.json?resource="+
		url.QueryEscape(ip.Data.IP), &info); err != nil {
		return "", fmt.Errorf("провайдер: %w", err)
	}
	if len(info.Data.ASNs) == 0 {
		return "", fmt.Errorf("для %s провайдер неизвестен", ip.Data.IP)
	}
	return "AS" + info.Data.ASNs[0], nil
}

func getJSON(cl *http.Client, u string, v any) error {
	resp, err := cl.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// resolveNetwork: ключ памяти для текущего подключения.
//
// Провайдер не определился (сеть ещё поднимается, RIPE недоступен) --
// работаем под ключом шлюза, как раньше, и пробуем снова в следующем
// цикле. Брать вердикты прошлого провайдера "на всякий случай" нельзя:
// на чужой сети ложное "чисто" ломает сайты.
func resolveNetwork(cfg Config, st *state) string {
	att := networkID()
	if att == "unknown" {
		return att
	}
	cached, ok := st.attached(att)
	if ok && time.Since(cached.Checked) < asnCacheTTL {
		return cached.Net
	}

	var asn string
	var err error
	for i := 0; i < 3; i++ {
		if asn, err = lookupASN(cfg.DirectAddr); err == nil {
			break
		}
		time.Sleep(5 * time.Second)
	}
	if err != nil {
		if ok {
			// провайдер за этим шлюзом уже известен, просто не
			// перепроверился -- продолжаем с ним
			return cached.Net
		}
		log.Printf("провайдер не определён (%v), память по шлюзу %s", err, att)
		return att
	}
	st.attach(att, asn)
	if n := st.mergeInto(asn); n > 0 {
		log.Printf("провайдер %s: влито %d вердиктов из прежней памяти по шлюзу", asn, n)
	}
	return asn
}
