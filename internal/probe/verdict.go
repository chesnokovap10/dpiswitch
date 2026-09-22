package probe

import (
	"fmt"
	"sync/atomic"
	"time"
)

type Verdict string

const (
	Clean       Verdict = "CLEAN"        // прямой путь чист -- кандидат в DIRECT
	BlockedTCP  Verdict = "BLOCKED_TCP"  // рвётся на уровне соединения
	BlockedTLS  Verdict = "BLOCKED_TLS"  // рвётся на ClientHello -- фильтр по SNI
	MITM        Verdict = "MITM"         // подмена сертификата
	ContentDiff Verdict = "CONTENT_DIFF" // ответ отличается -- возможна заглушка
	BlockedQUIC Verdict = "BLOCKED_QUIC" // QUIC режется (TCP при этом может быть чист)
	Slower      Verdict = "SLOWER"       // блокировки нет, но прямой путь медленнее туннеля
	Inconcl     Verdict = "INCONCLUSIVE" // туннель тоже не работает, сравнивать не с чем
)

type Report struct {
	Domain    string  `json:"domain"`
	Time      string  `json:"time"`
	Verdict   Verdict `json:"verdict"`
	Reason    string  `json:"reason,omitempty"`
	Attempts  int     `json:"attempts"`
	TestedIP  string  `json:"tested_ip,omitempty"`
	DNSDirect string  `json:"dns_direct,omitempty"`
	DNSTunnel string  `json:"dns_tunnel,omitempty"`
	Port      int     `json:"port,omitempty"`
	Proto     string  `json:"proto,omitempty"`
	Note      string  `json:"note,omitempty"`
	// Aborted: проверка сорвалась по нашей стороне (ядро перезапускалось),
	// результат ничего не говорит о сайте и в память идти не должен
	Aborted  bool       `json:"aborted,omitempty"`
	DirectMs int64      `json:"direct_ms,omitempty"`
	TunnelMs int64      `json:"tunnel_ms,omitempty"`
	Direct   PathResult `json:"direct"`
	Tunnel   PathResult `json:"tunnel"`
}

// Проба: N проходов подряд, CLEAN только если чисты все.
// асимметрия намеренная -- ложное "чисто" ломает сайт,
// ложное "заблокировано" стоит лишь крюка через туннель.
// "не заблокирован" и "быстрее" -- разные вещи. домен, который открывается
// напрямую, но медленнее туннеля, переключать незачем: станет только хуже.
// запас по множителю и абсолютный -- чтобы близкие значения не дёргались.
const slowMargin = 10 * time.Millisecond

// множитель настраивается из интерфейса; читается пробами из разных
// горутин, поэтому хранится атомарно (в тысячных долях)
var slowFactorMilli atomic.Int64

func init() { slowFactorMilli.Store(1200) }

func SetSlowFactor(f float64) { slowFactorMilli.Store(int64(f * 1000)) }

func slowFactor() float64 { return float64(slowFactorMilli.Load()) / 1000 }

// CheckProto: udp=true означает пробу QUIC на этом порту.
func CheckProto(direct, tunnel Dialer, dom string, port, attempts int, udp bool) Report {
	rep := checkProto(direct, tunnel, dom, port, attempts, udp)
	// неудача, пока ядро перезапускается, выглядит как блокировка: входы
	// пробника просто не отвечают. засчитать её -- значит откатить в
	// туннель рабочий сайт и отодвинуть его перепроверку
	if rep.Verdict != Clean && (!direct.Alive() || !tunnel.Alive()) {
		rep.Verdict, rep.Aborted = Inconcl, true
		rep.Reason = "ядро недоступно (перезапуск?), проверка не в счёт"
	}
	return rep
}

func checkProto(direct, tunnel Dialer, dom string, port, attempts int, udp bool) Report {
	proto := "tcp"
	if udp {
		proto = "quic"
	}
	rep := Report{Domain: dom, Port: port, Proto: proto, Time: time.Now().Format(time.RFC3339), Attempts: attempts}

	var ip string
	if len(direct.DNS) > 0 {
		// проверяем ровно тот узел, на который пойдёт прямой трафик:
		// адрес берём у того же резолвера, что и ядро. подмену ответа
		// поймает проверка сертификата -- на чужом узле она не пройдёт.
		// не ответил резолвер -- прямой трафик тоже не заработал бы
		ips, err := LookupAny(direct, direct.DNS, dom)
		if err != nil {
			rep.Verdict, rep.Reason = Inconcl, "прямой DNS не ответил: "+errText(err)
			return rep
		}
		rep.DNSDirect = JoinIPs(ips)
		ip = ips[0]
	} else {
		// эталонный резолв -- через туннель, он заведомо не подменён
		tunIPs, err := ResolveVia(tunnel, dom)
		if err != nil || len(tunIPs) == 0 {
			rep.Verdict, rep.Reason = Inconcl, "не резолвится даже через туннель: "+errText(err)
			return rep
		}
		rep.DNSTunnel = JoinIPs(tunIPs)
		dirIPs, _ := ResolveVia(direct, dom)
		rep.DNSDirect = JoinIPs(dirIPs)
		ip = tunIPs[0]
	}

	// обе стороны проверяем на ОДНОМ узле, иначе сравнение бессмысленно:
	// у CDN разные узлы блокируются по-разному
	rep.TestedIP = ip

	// берём лучшее измерение из проходов, а не последнее: минимум
	// устойчивее к случайным всплескам, чем среднее
	var bestDirect, bestTunnel time.Duration
	for i := 0; i < attempts; i++ {
		var d, t PathResult
		switch {
		case udp:
			d, t = RunQUIC(direct, ip, port, dom), RunQUIC(tunnel, ip, port, dom)
		case port == 443:
			d, t = Run(direct, ip, dom), Run(tunnel, ip, dom)
		default:
			d, t = RunTCP(direct, ip, port), RunTCP(tunnel, ip, port)
		}
		rep.Direct, rep.Tunnel = d, t
		v, reason := Judge(d, t)
		// для QUIC рукопожатие неразделимо, поэтому обе "транспортные"
		// неудачи означают одно и то же -- пакеты не дошли
		if udp && (v == BlockedTCP || v == BlockedTLS) {
			v = BlockedQUIC
		}
		rep.Verdict, rep.Reason = v, reason
		if v != Clean {
			return rep // первый же не-чистый проход решает
		}
		if dt := d.TCPTime + d.TLSTime; bestDirect == 0 || dt < bestDirect {
			bestDirect = dt
		}
		if tt := t.TCPTime + t.TLSTime; bestTunnel == 0 || tt < bestTunnel {
			bestTunnel = tt
		}
	}
	rep.DirectMs = bestDirect.Milliseconds()
	rep.TunnelMs = bestTunnel.Milliseconds()

	if bestTunnel > 0 && bestDirect > time.Duration(float64(bestTunnel)*slowFactor())+slowMargin {
		rep.Verdict = Slower
		rep.Reason = fmt.Sprintf("прямой путь медленнее: %d мс против %d через туннель",
			bestDirect.Milliseconds(), bestTunnel.Milliseconds())
		return rep
	}

	// расхождение наборов адресов между путями НЕ является признаком блокировки:
	// резолверы применяют EDNS Client Subnet, и с адреса VPS тот же google
	// отдаёт другой узел CDN, чем с домашнего адреса. проверено на example.com.
	return rep
}

func Judge(d, t PathResult) (Verdict, string) {
	if !t.TCPOk {
		return Inconcl, "туннельный путь недоступен: " + ClassifyErr(t)
	}
	if !d.TCPOk {
		return BlockedTCP, ClassifyErr(d)
	}
	// проба без TLS (не 443): дальше сравнивать нечего
	if !t.TLSOk && !d.TLSOk {
		return Clean, ""
	}
	if !t.TLSOk {
		return Inconcl, "туннельный путь недоступен: " + ClassifyErr(t)
	}
	if !d.TLSOk {
		return BlockedTLS, ClassifyErr(d)
	}
	// сравнивать отпечатки сертификатов нельзя -- у CDN разные узлы отдают
	// разные валидные сертификаты. признак подмены: цепочка прямого пути
	// не проходит проверку, а туннельного проходит.
	if t.CertValid && !d.CertValid {
		return MITM, "сертификат на прямом пути не проходит проверку цепочки (CN=" + d.CertCN + ")"
	}
	if d.HTTPStatus != 0 && t.HTTPStatus != 0 && d.HTTPStatus != t.HTTPStatus {
		// туннель -- не абсолютный эталон. выход у нас в дата-центре,
		// и Cloudflare отдаёт таким адресам challenge вместо контента.
		// если напрямую приходит нормальный ответ, а через туннель
		// заградительный статус -- испорчен туннель, и уводить домен
		// в него значит выбрать заведомо сломанный путь.
		if d.HTTPStatus < 400 && isChallenge(t.HTTPStatus) {
			return Clean, ""
		}
		return ContentDiff, fmt.Sprintf("HTTP %d напрямую против %d через туннель", d.HTTPStatus, t.HTTPStatus)
	}
	if d.BodyLen > 0 && t.BodyLen > 0 && !isChallenge(t.HTTPStatus) {
		ratio := float64(d.BodyLen) / float64(t.BodyLen)
		if ratio < 0.25 || ratio > 4 {
			return ContentDiff, fmt.Sprintf("размер ответа %d против %d байт", d.BodyLen, t.BodyLen)
		}
	}
	return Clean, ""
}

// статусы, которыми отвечает защита от ботов, а не сам сайт
func isChallenge(code int) bool {
	return code == 403 || code == 429 || code == 503
}

func errText(err error) string {
	if err == nil {
		return "-"
	}
	return Truncate(err.Error(), 70)
}
