package ctl

import (
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"

	"dpiswitch/internal/probe"
)

// Семейства поддоменов.
//
// Сервисы вроде speedtest.ru раздают трафик по пулу хостов (*.qms.ru)
// и каждый раз берут новые. Каждый новый хост сначала идёт в туннель
// и ждёт проверки -- а замер длится меньше, чем проверка. Если же у
// домена набралось несколько чистых поддоменов и ни одного
// заблокированного, домен целиком ведёт себя одинаково, и новые хосты
// разумно пускать напрямую сразу.
//
// Страховка от ошибки: хосты семейства, пущенные напрямую без проверки,
// ловит suspectDirect (соединение открыто, данных нет) -- после чего
// хост проверяется, и первый же плохой вердикт снимает всё семейство.
//
// Граница "домена" -- по списку публичных суффиксов вместе с частными
// (github.io, cloudfront.net, appspot.com): иначе чужие друг другу
// сайты на общем хостинге слились бы в одно семейство.

// minFamily: сколько чистых поддоменов нужно для вывода о домене
const minFamily = 3

type family struct {
	Domain string `json:"domain"`
	Clean  int    `json:"clean"`
}

// badForFamily: вердикты, говорящие, что домен НЕ однороден.
// INCONCLUSIVE ничего не говорит о блокировке и не считается.
// SLOWER считается: часть хостов напрямую хуже, значит обобщать нельзя.
func badForFamily(v probe.Verdict) bool {
	return v != probe.Clean && v != probe.Inconcl
}

func familyOf(dom string) string {
	f, err := publicsuffix.EffectiveTLDPlusOne(dom)
	if err != nil {
		return ""
	}
	return f
}

// families: домены, чьи поддомены можно пускать напрямую целиком
func (s *state) families(id string) []family {
	s.mu.Lock()
	defer s.mu.Unlock()
	clean := map[string]int{}
	bad := map[string]bool{}
	for dom, e := range s.Networks[id] {
		f := familyOf(dom)
		if f == "" {
			continue
		}
		switch {
		case e.Verdict == probe.Clean:
			clean[f]++
		case badForFamily(e.Verdict):
			bad[f] = true
		}
	}
	var out []family
	for f, n := range clean {
		if n >= minFamily && !bad[f] {
			out = append(out, family{Domain: f, Clean: n})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

// directRules: содержимое списка прямого пути -- проверенные домены
// и, если включено, семейства в записи "+.домен"
func directRules(cfg Config, st *state, id string) (rules []string, fams []family) {
	rules = st.verified(id)
	if !cfg.Families {
		return rules, nil
	}
	fams = st.families(id)
	covered := map[string]bool{}
	for _, f := range fams {
		covered[f.Domain] = true
		rules = append(rules, "+."+f.Domain)
	}
	// хосты, покрытые семейством, в списке уже лишние
	out := rules[:0]
	for _, r := range rules {
		if !strings.HasPrefix(r, "+.") && covered[familyOf(r)] {
			continue
		}
		out = append(out, r)
	}
	sort.Strings(out)
	return out, fams
}
