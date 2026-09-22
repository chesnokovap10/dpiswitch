// Конвертер конфигурации AmneziaWG (.conf) в конфигурацию mihomo.
// Порт прежнего gen-live.py: бинарь должен быть самодостаточным.
package awgconf

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
	"dpiswitch/internal/probe"
)

type Section map[string]string

type Conf struct {
	Interface Section
	Peer      Section
}

func Parse(text string) (*Conf, error) {
	c := &Conf{Interface: Section{}, Peer: Section{}}
	var cur Section
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			switch strings.ToLower(strings.Trim(line, "[]")) {
			case "interface":
				cur = c.Interface
			case "peer":
				cur = c.Peer
			default:
				cur = nil
			}
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		cur[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if c.Interface["PrivateKey"] == "" {
		return nil, fmt.Errorf("в конфиге нет PrivateKey")
	}
	if c.Peer["Endpoint"] == "" {
		return nil, fmt.Errorf("в конфиге нет Endpoint")
	}
	return c, nil
}

func ParseFile(path string) (*Conf, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(string(b))
}

var secretRe = regexp.MustCompile(`(?m)^secret:\s*'([^']+)'`)

// секрет переиспользуем: он прописан у трея и контроллера,
// новый при каждой генерации молча ломал бы им доступ к API
func keepSecret(existing string) string {
	if b, err := os.ReadFile(existing); err == nil {
		if m := secretRe.FindSubmatch(b); m != nil {
			return string(m[1])
		}
	}
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func quoteList(items []string) string {
	q := make([]string, 0, len(items))
	for _, i := range items {
		q = append(q, "'"+i+"'")
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// DNS: резолверы из секции [Interface]
func (c *Conf) DNS() []string {
	out := split(c.Interface["DNS"])
	if out == nil {
		out = []string{}
	}
	return out
}

// Render собирает конфигурацию mihomo из разобранного .conf.
func (c *Conf) Render() (string, error) {
	host, _, err := net.SplitHostPort(c.Peer["Endpoint"])
	if err != nil {
		return "", fmt.Errorf("не разобран Endpoint: %w", err)
	}

	if _, _, err := c.addrs(); err != nil {
		return "", err
	}
	// второй туннель (vpsde) -- если подгружен; битый исходник второго
	// не должен ломать первый, поэтому ошибка только в журнал
	var c2 *Conf
	if _, err := os.Stat(paths.SourceConf2()); err == nil {
		if cc, err := ParseFile(paths.SourceConf2()); err != nil {
			log.Printf("второй туннель не подключён: %v", err)
		} else if _, _, err := cc.addrs(); err != nil {
			log.Printf("второй туннель не подключён: %v", err)
		} else {
			c2 = cc
		}
	}

	dns := split(c.Interface["DNS"])
	set := ctl.LoadSettings(paths.Settings())
	// резолверы туннеля: из настроек, иначе из .conf
	tunDNS := dns
	if len(set.TunnelDNS) > 0 {
		tunDNS = set.TunnelDNS
	}
	directDNS := set.DirectDNS
	bootstrap := bootstrapDNS(directDNS)
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("# сгенерировано dpiswitch из source.conf -- править вручную нет смысла,")
	w("# файл перезаписывается при подгрузке конфига.")
	w("# пути провайдеров относительные: mihomo запрещает ссылки за пределы")
	w("# своего домашнего каталога, поэтому ядро запускается с -d <каталог данных>")
	w("mixed-port: 7890")
	w("allow-lan: false")
	w("mode: rule")
	w("log-level: info")
	w("ipv6: true")
	w("unified-delay: true")
	w("tcp-concurrent: true")
	w("# процесс ищется лениво -- только когда проверка дошла до правила")
	w("# с программой. при пустом списке исключений это ничего не стоит")
	w("find-process-mode: strict")
	w("external-controller: 127.0.0.1:9090")
	w("secret: '%s'", keepSecret(paths.Config()))
	w("")
	w("# отдельный вход для пробника: мимо правил, всегда напрямую.")
	w("# единственный способ дать пробнику прямой путь, пока TUN")
	w("# забирает весь остальной трафик.")
	w("listeners:")
	w("  - name: probe-direct")
	w("    type: mixed")
	w("    listen: 127.0.0.1")
	w("    port: 7892")
	w("    proxy: DIRECT")
	w("  # вход для туннельной пробы жёстко привязан к awg, а НЕ к группе:")
	w("  # при откате группы на DIRECT обе пробы пошли бы напрямую, и")
	w("  # детектор счёл бы чистым вообще всё -- самая дорогая ошибка")
	w("  - name: probe-tunnel")
	w("    type: mixed")
	w("    listen: 127.0.0.1")
	w("    port: 7891")
	w("    proxy: awg")
	w("")
	w("tun:")
	w("  enable: true")
	w("  stack: gvisor")
	if set.IPv6 {
		// IPv6 внутри туннеля: системе нужен IPv6-адрес и маршрут,
		// иначе программы даже не пробуют IPv6
		w("  inet6-address:")
		w("    - 'fdfe:dcba:9876::1/126'")
	}
	w("  auto-route: true")
	w("  auto-detect-interface: true")
	w("  dns-hijack:")
	w("    - any:53")
	w("")
	w("# восстанавливает домен из ClientHello для софта, который")
	w("# резолвит мимо нас (браузеры со своим DoH)")
	w("sniffer:")
	w("  enable: true")
	w("  override-destination: true")
	w("  skip-src-address:")
	w("    - 127.0.0.1/32")
	w("  sniff:")
	w("    TLS:")
	w("      ports: [443, 8443]")
	w("    QUIC:")
	w("      ports: [443]")
	w("    HTTP:")
	w("      ports: [80, 8080, 8880]")
	w("      override-destination: false")
	w("")
	w("dns:")
	w("  enable: true")
	w("  listen: 127.0.0.1:1053")
	w("  ipv6: true")
	w("  enhanced-mode: fake-ip")
	w("  fake-ip-range: 198.18.0.1/16")
	if set.IPv6 {
		// на AAAA тоже отвечаем фиктивным адресом: соединение придёт
		// с доменом, и правила "напрямую / в туннель" работают как для IPv4.
		//
		// Диапазон -- 2001:2::/48 (зарезервирован под тесты, RFC 5180),
		// а НЕ ULA fc00::/7. Chrome считает ULA локальной сетью и по
		// правилам Local Network Access молча режет запросы публичных
		// страниц к таким адресам (ERR_FAILED, до сети запрос не доходит).
		// С ULA ломались фреймы, WebSocket'ы и навигация: веб-Телеграм
		// висел на "Waiting for network", плеер на yummyani не грузился.
		// 198.18.0.0/15 для IPv4 Chrome локальным не считает -- берём
		// такой же тестовый диапазон для IPv6.
		w("  fake-ip-range6: '2001:2::/48'")
	}
	w("  fake-ip-filter:")
	w("    - '*.lan'")
	w("    - '*.local'")
	if net.ParseIP(host) == nil {
		w("    - '%s'", host)
	}
	if c2 != nil {
		if h2, _, err := net.SplitHostPort(c2.Peer["Endpoint"]); err == nil && net.ParseIP(h2) == nil {
			w("    - '%s'", h2)
		}
	}
	// Два резолвера под два пути.
	// Туннель резолвит сам, своим DNS внутри туннеля (remote-dns-resolve
	// у awg): адрес узла выбирается под VPS, через который трафик и пойдёт.
	// Прямой путь -- direct-nameserver, к которому ходим напрямую: CDN
	// выдаёт узел под провайдера пользователя. К нему же ходит пробник,
	// поэтому проверяется ровно тот узел, куда потом пойдёт трафик.
	// Откат группы tunnel на DIRECT при мёртвом туннеле тоже резолвится
	// через direct-nameserver -- без туннеля имена продолжают работать.
	// Все списки -- без смешения путей: ядро опрашивает резолверы списка
	// одновременно, и смесь давала бы ответы то от одного, то от другого.
	w("  # адреса серверов, заданных именем; только IP -- иначе курица и яйцо")
	w("  default-nameserver:")
	for _, d := range bootstrap {
		w("    - '%s'", d)
	}
	w("  # остальное (fake-ip-filter, служебные запросы) -- тем же прямым DNS")
	w("  nameserver:")
	for _, d := range directDNS {
		w("    - '%s'", d)
	}
	w("  direct-nameserver:")
	for _, d := range directDNS {
		w("    - '%s'", d)
	}
	w("  proxy-server-nameserver:")
	for _, d := range bootstrap {
		w("    - '%s'", d)
	}
	w("")
	w("# Группа с откатом. Без неё мёртвый туннель означал бы полное")
	w("# отсутствие интернета: все правила ведут в awg, а он не отвечает.")
	w("# fallback сам проверяет туннель и при его падении пускает трафик")
	w("# напрямую -- защиты в этот момент нет, зато связь есть.")
	w("proxy-groups:")
	w("  - name: tunnel")
	w("    type: fallback")
	w("    proxies:")
	w("      - awg")
	w("      - DIRECT")
	w("    url: 'http://cp.cloudflare.com/generate_204'")
	w("    interval: 30")
	// первая проверка идёт в момент старта ядра, когда рукопожатие
	// WireGuard ещё не завершено: DNS внутри туннеля теряется, повтор
	// через ~5 с. со стандартными 5 с проверка проваливалась, туннель
	// считался мёртвым, и до следующей проверки (30 с) группа пускала
	// всё напрямую -- включая заблокированное. до окончания проверки
	// туннель и так считается живым, так что запас ничего не стоит
	w("    timeout: 15000")
	w("    lazy: false")
	w("")
	w("  # второй туннель (vpsde) для пресетов и своего списка. Упал он --")
	w("  # трафик идёт первым туннелем (vpsru сам пересылает эти сервисы")
	w("  # на vpsde), упали оба -- напрямую. Второго туннеля нет -- та же")
	w("  # группа без него: пресеты просто закреплены за первым.")
	w("  - name: tunnel2")
	w("    type: fallback")
	w("    proxies:")
	if c2 != nil {
		w("      - awg2")
	}
	w("      - awg")
	w("      - DIRECT")
	w("    url: 'http://cp.cloudflare.com/generate_204'")
	w("    interval: 30")
	w("    timeout: 15000")
	w("    lazy: false")
	w("")
	w("rule-providers:")
	w("  # пресеты второго туннеля: выключенный пишется пустым, поэтому")
	w("  # включение и выключение не требуют перезапуска ядра")
	for _, p := range presets.All {
		w("  preset-%s:", p.ID)
		w("    type: file")
		w("    behavior: classical")
		w("    format: text")
		w("    path: ./preset-%s.txt", p.ID)
	}
	w("  awg2-hosts:")
	w("    type: file")
	w("    behavior: domain")
	w("    format: text")
	w("    path: ./awg2-hosts.txt")
	w("  # твои списки: контроллер их не трогает и не перезаписывает")
	w("  force-direct-apps:")
	w("    type: file")
	w("    behavior: classical")
	w("    format: text")
	w("    path: ./force-direct-apps.txt")
	w("  force-tunnel:")
	w("    type: file")
	w("    behavior: domain")
	w("    format: text")
	w("    path: ./force-tunnel.txt")
	w("  force-direct:")
	w("    type: file")
	w("    behavior: domain")
	w("    format: text")
	w("    path: ./force-direct.txt")
	w("  # память детектора: перезаписывается контроллером")
	w("  direct-verified:")
	w("    type: file")
	w("    behavior: domain")
	w("    format: text")
	w("    path: ./direct-verified.txt")
	w("")
	w("proxies:")
	c.writeProxy(w, "awg", tunDNS, set.IPv6)
	if c2 != nil {
		// DNS второго -- его собственный из .conf: резолвить имена
		// должен тот сервер, через который пойдёт трафик
		c2.writeProxy(w, "awg2", split(c2.Interface["DNS"]), set.IPv6)
	}
	w("")
	w("rules:")
	w("  # 1. сами эндпоинты -- всегда мимо туннеля, иначе петля")
	writeEndpointRule(w, host)
	if c2 != nil {
		if h2, _, err := net.SplitHostPort(c2.Peer["Endpoint"]); err == nil {
			writeEndpointRule(w, h2)
		}
	}
	w("")
	w("  # 2. локальные сети")
	w("  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve")
	w("  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve")
	w("  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve")
	w("  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve")
	w("  - IP-CIDR6,fe80::/10,DIRECT,no-resolve")
	w("")
	w("  # 3. программы-исключения: весь их трафик мимо туннеля")
	w("  - RULE-SET,force-direct-apps,DIRECT")
	w("")
	w("  # 4. второй туннель: пресеты и свой список -- детектор их не трогает")
	for _, p := range presets.All {
		w("  - RULE-SET,preset-%s,tunnel2", p.ID)
	}
	w("  - RULE-SET,awg2-hosts,tunnel2")
	w("")
	w("  # 5. твой принудительный туннель -- выигрывает у вердиктов детектора")
	w("  - RULE-SET,force-tunnel,tunnel")
	w("")
	w("  # 6. твой принудительный прямой путь")
	w("  - RULE-SET,force-direct,DIRECT")
	w("")
	w("  # 7. вердикты детектора")
	w("  - RULE-SET,direct-verified,DIRECT")
	w("")
	w("  # 8. по умолчанию всё в первый туннель")
	w("  - MATCH,tunnel")
	return b.String(), nil
}

// addrs: адреса интерфейса из [Interface] Address
func (c *Conf) addrs() (v4, v6 string, err error) {
	for _, a := range split(c.Interface["Address"]) {
		ip, _, _ := strings.Cut(a, "/")
		if strings.Contains(ip, ":") {
			v6 = ip
		} else {
			v4 = ip
		}
	}
	if v4 == "" {
		return "", "", fmt.Errorf("в конфиге нет адреса IPv4")
	}
	return v4, v6, nil
}

func writeEndpointRule(w func(string, ...any), host string) {
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			w("  - IP-CIDR,%s/32,DIRECT,no-resolve", host)
		} else {
			w("  - IP-CIDR6,%s/128,DIRECT,no-resolve", host)
		}
	} else {
		w("  - DOMAIN,%s,DIRECT", host)
	}
}

// writeProxy: исходящий AmneziaWG с указанным именем
func (c *Conf) writeProxy(w func(string, ...any), name string, tunDNS []string, ipv6 bool) {
	host, port, _ := net.SplitHostPort(c.Peer["Endpoint"])
	v4, v6, _ := c.addrs()
	mtu := c.Interface["MTU"]
	if mtu == "" {
		mtu = "1420"
	}
	keepalive := c.Peer["PersistentKeepalive"]
	if keepalive == "" {
		keepalive = "0"
	}
	w("  - name: %s", name)
	w("    type: wireguard")
	w("    server: %s", host)
	w("    port: %s", port)
	w("    ip: %s", v4)
	if v6 != "" {
		w("    ipv6: %s", v6)
	}
	w("    private-key: '%s'", c.Interface["PrivateKey"])
	w("    public-key: '%s'", c.Peer["PublicKey"])
	if k := c.Peer["PresharedKey"]; k != "" {
		w("    pre-shared-key: '%s'", k)
	}
	allowed := split(c.Peer["AllowedIPs"])
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}
	w("    allowed-ips: %s", quoteList(allowed))
	w("    mtu: %s", mtu)
	w("    persistent-keepalive: %s", keepalive)
	w("    udp: true")
	w("    remote-dns-resolve: true")
	if ipv6 {
		// IPv4 первым, IPv6 -- когда у сайта только он. Семейство, которое
		// выбрала программа, при fake-ip не сохраняется: ядро само заново
		// резолвит домен. С ipv6-prefer весь туннельный трафик уходил по
		// IPv6, а у VPS несколько IPv6-адресов, и часть из них геобазы
		// относят к Германии -- сайты видели то Россию, то Германию.
		// IPv4 у VPS один, страна всегда одна.
		w("    ip-version: ipv4-prefer")
	}
	if len(tunDNS) > 0 {
		w("    dns: %s", quoteList(tunDNS))
	}
	w("    amnezia-wg-option:")
	w("      version: 3")
	for _, k := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4"} {
		if v := c.Interface[k]; v != "" {
			w("      %s: %s", strings.ToLower(k), v)
		}
	}
	for _, k := range []string{"H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"} {
		if v := c.Interface[k]; v != "" {
			w("      %s: '%s'", strings.ToLower(k), v)
		}
	}
	strMap := [][2]string{
		{"HeaderProtectionKey", "header-protection-key"},
		{"ContentPaddingAddition", "content-padding-addition"},
		{"RekeyAfterTime", "rekey-after-time"},
		{"RekeyTimeout", "rekey-timeout"},
		{"RejectAfterTime", "reject-after-time"},
		{"KeepaliveTimeout", "keepalive-timeout"},
		{"MaxHandshakeAttempts", "max-handshake-attempts"},
	}
	for _, kv := range strMap {
		if v := c.Interface[kv[0]]; v != "" {
			w("      %s: '%s'", kv[1], v)
		}
	}
	for _, kv := range [][2]string{{"RandomTrailers", "random-trailers"}, {"DisableCookies", "disable-cookies"}} {
		switch strings.ToLower(c.Interface[kv[0]]) {
		case "on", "true", "1", "yes":
			w("      %s: true", kv[1])
		}
	}
}

// Regenerate пересобирает config.yaml из сохранённого исходника.
//
// Конфиг целиком генерируется, поэтому новая версия программы должна
// доносить свои изменения (правила, провайдеры) до уже установленной
// системы сама, без повторной загрузки .conf. Файл переписывается на
// месте, а не заменой: так сохраняются выставленные на него права,
// закрывающие приватный ключ. Возвращает true, если что-то изменилось.
func Regenerate() (bool, error) {
	c, err := ParseFile(paths.SourceConf())
	if err != nil {
		return false, err
	}
	out, err := c.Render()
	if err != nil {
		return false, err
	}
	if old, err := os.ReadFile(paths.Config()); err == nil && string(old) == out {
		return false, nil
	}
	f, err := os.OpenFile(paths.Config(), os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return false, err
	}
	if _, err := f.WriteString(out); err != nil {
		f.Close()
		return false, err
	}
	return true, f.Close()
}

// EnsureLists создаёт недостающие файлы списков: провайдер без
// файла не даёт ядру стартовать
func EnsureLists() {
	for _, p := range []string{paths.ForceDirect(), paths.ForceTunnel(),
		paths.Verified(), paths.ForceDirectApps(), paths.Awg2Hosts()} {
		if _, err := os.Stat(p); err != nil {
			os.WriteFile(p, []byte("# пусто\n"), 0o644)
		}
	}
	// пресеты второго туннеля -- по настройкам; без файлов ядро не стартует
	if err := presets.Write(ctl.LoadSettings(paths.Settings()).Awg2Presets); err != nil {
		log.Printf("пресеты не записаны: %v", err)
	}
}

// bootstrapDNS: резолверы, заданные адресом, а не именем. Обычный
// UDP/53 у части провайдеров режется, поэтому запасной вариант --
// тоже зашифрованный и тоже по IP.
func bootstrapDNS(list []string) []string {
	var out []string
	for _, d := range list {
		r, err := probe.ParseResolver(d)
		if err == nil && net.ParseIP(r.Host) != nil {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		out = []string{"https://77.88.8.8/dns-query", "tls://77.88.8.1"}
	}
	return out
}
