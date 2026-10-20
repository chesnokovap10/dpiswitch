package webui

import (
	"net/url"
	"strings"
	"testing"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/nrpt"
	"dpiswitch/internal/paths"
)

// The DNS policy's setting is off until switched on, sits after the DNS
// cache, is saved without restarting the core, and links to its help.
func TestNRPTSetting(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	page := func() string { return do(t, h, "GET", "/settings", nil, nil).Body.String() }

	if ctl.LoadSettings(paths.Settings()).NRPT {
		t.Fatal("on by default: a service that dies leaves no name resolving")
	}
	b := page()
	if !strings.Contains(b, `<select id="nrpt" name="nrpt"><option value="1" >On</option><option value="0" selected>Off</option>`) {
		t.Fatalf("the row is not there, or not off:\n%s", b)
	}
	if c, n, u := strings.Index(b, `id="dns_cache"`), strings.Index(b, `id="nrpt"`), strings.Index(b, `id="udp_guard"`); !(c < n && n < u) {
		t.Errorf("the row is not between the DNS cache and the UDP guard: %d %d %d", c, n, u)
	}
	if strings.Contains(b, `data-poll="/frag/settings/nrptstate"`) {
		t.Error("the state refreshes itself with the setting off")
	}
	for _, w := range []string{`href="/help#h-nrpt"`, "or the ISP", "Should the service die", "Off by default"} {
		if !strings.Contains(b, w) {
			t.Errorf("the row lacks %q", w)
		}
	}
	for lang, ws := range map[string][]string{
		"en": {`id="h-nrpt"`, "Name Resolution Policy Table", "in 30 seconds", "Group Policy", `href="/settings#nrpt"`},
		"ru": {`id="h-nrpt"`, "таблицу политик разрешения имён", "через 30 секунд", "групповой политики", `href="/settings#nrpt"`},
	} {
		help := do(t, h, "GET", "/help", nil, map[string]string{"Cookie": "lang=" + lang}).Body.String()
		for _, w := range ws {
			if !strings.Contains(help, w) {
				t.Errorf("the %s help lacks %q", lang, w)
			}
		}
	}

	set := func(v string) string {
		return do(t, h, "POST", "/act/set", url.Values{"field": {"nrpt"}, "value": {v}}, nil).Body.String()
	}
	if b := set("1"); !strings.Contains(b, "msg ok") || strings.Contains(b, "the core restarts, the tunnel drops") {
		t.Fatalf("switching it on:\n%s", b)
	}
	if !ctl.LoadSettings(paths.Settings()).NRPT {
		t.Fatal("not saved")
	}
	if !strings.Contains(page(), `data-poll="/frag/settings/nrptstate"`) {
		t.Error("the state does not refresh itself with the setting on")
	}
	was := ctl.DefaultSettings()
	now := was
	now.NRPT = true
	if !was.SameCore(now) {
		t.Error("the DNS policy counts as a setting that restarts the core")
	}
	if set("0"); ctl.LoadSettings(paths.Settings()).NRPT {
		t.Error("not switched off")
	}
	set("1")
	do(t, h, "POST", "/act/defaults", url.Values{}, nil)
	if ctl.LoadSettings(paths.Settings()).NRPT {
		t.Error("still on after the defaults")
	}
}

// What the service wrote is worded, state by state, in both languages.
func TestNRPTStates(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	if _, err := ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error { set.NRPT = true; return nil }); err != nil {
		t.Fatal(err)
	}
	frag := func(lang string) string {
		return do(t, h, "GET", "/frag/settings/nrptstate", nil, map[string]string{"Cookie": "lang=" + lang}).Body.String()
	}
	if b := frag("en"); !strings.Contains(b, "has not reported yet") {
		t.Errorf("nothing said by the service, and the page says: %s", b)
	}
	for _, c := range []struct {
		st     nrpt.Status
		en, ru string
		class  string
	}{
		{nrpt.Status{State: nrpt.StateOn}, "In place: every name goes to the tunnel", "Действует: каждое имя уходит к DNS туннеля.", "ok-t"},
		{nrpt.Status{State: nrpt.StateWait, Why: nrpt.WhyCore}, "Waiting for the core to run.", "Ждёт запуска ядра.", "muted"},
		{nrpt.Status{State: nrpt.StateWait, Why: nrpt.WhyAdapter}, "Waiting for the DPI Switch adapter", "Ждёт адаптер DPI Switch", "muted"},
		{nrpt.Status{State: nrpt.StateWait, Why: nrpt.WhyTraffic}, "names sent there would find nothing", "остались бы без ответа", "warn-t"},
		{nrpt.Status{State: nrpt.StateFail, Why: nrpt.WhyPolicy}, "Group Policy has name resolution rules of its own", "в групповой политике есть свои правила", "bad-t"},
		{nrpt.Status{State: nrpt.StateFail, Why: nrpt.WhyIgnored}, "Windows does not apply it", "Windows его не применяет", "bad-t"},
		{nrpt.Status{State: nrpt.StateFail, Why: nrpt.WhyOther, Err: "Access is denied"}, "Windows refused the rule (Access is denied)", "Windows отклонила правило (Access is denied)", "bad-t"},
	} {
		if err := c.st.Save(paths.NRPT()); err != nil {
			t.Fatal(err)
		}
		if b := frag("en"); !strings.Contains(b, c.en) || !strings.Contains(b, `class="`+c.class+`"`) {
			t.Errorf("%s/%s in English, want %q in %s:\n%s", c.st.State, c.st.Why, c.en, c.class, b)
		}
		if b := frag("ru"); !strings.Contains(b, c.ru) {
			t.Errorf("%s/%s in Russian, want %q:\n%s", c.st.State, c.st.Why, c.ru, b)
		}
	}
	st := s.statusFn()
	st.ServiceRun = false
	s.statusFn = func() status { return st }
	if b := frag("en"); !strings.Contains(b, "The service is stopped: Windows asks names as usual.") {
		t.Errorf("a stopped service, and the page says: %s", b)
	}
	st.ServiceRun = true
	if _, err := ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error { set.NRPT = false; return nil }); err != nil {
		t.Fatal(err)
	}
	if b := strings.TrimSpace(frag("en")); b != "" {
		t.Errorf("the setting is off, and the part says: %s", b)
	}
}
