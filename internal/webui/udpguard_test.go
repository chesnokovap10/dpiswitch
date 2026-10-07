package webui

import (
	"net/url"
	"strings"
	"testing"

	"dpiswitch/internal/ctl"
	"dpiswitch/internal/paths"
	"dpiswitch/internal/udpguard"
)

// The UDP guard's setting is off until it is switched on, is saved without
// restarting the core -- the service takes the filters in and out by itself
// -- and the row says what the service reports of it, in both languages.
func TestUDPGuardSetting(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	page := func() string { return do(t, h, "GET", "/settings", nil, nil).Body.String() }

	if ctl.LoadSettings(paths.Settings()).UDPGuard {
		t.Fatal("the guard is on by default: it cuts off what needs UDP out of the adapter")
	}
	b := page()
	if !strings.Contains(b, `<select id="udp_guard" name="udp_guard"><option value="1" >On</option><option value="0" selected>Off</option>`) {
		t.Fatalf("the row is not there, or not off:\n%s", b)
	}
	if strings.Contains(b, `data-poll="/frag/settings/guard"`) {
		t.Error("the guard's state refreshes itself with the guard off")
	}
	// what it is for and what it breaks are both said, whatever the state
	for _, w := range []string{"WebRTC", "Windows Filtering Platform", "firewall off", "WireGuard", "casting to a TV", "Off by default"} {
		if !strings.Contains(b, w) {
			t.Errorf("the description lacks %q", w)
		}
	}

	set := func(v string) string {
		return do(t, h, "POST", "/act/set", url.Values{"field": {"udp_guard"}, "value": {v}}, nil).Body.String()
	}
	if b := set("1"); !strings.Contains(b, "msg ok") || strings.Contains(b, "the core restarts, the tunnel drops") {
		t.Fatalf("switching it on:\n%s", b)
	}
	if !ctl.LoadSettings(paths.Settings()).UDPGuard {
		t.Fatal("not saved")
	}
	if !strings.Contains(page(), `data-poll="/frag/settings/guard"`) {
		t.Error("the guard's state does not refresh itself with the guard on")
	}
	// it is no setting of the core's: it changes nothing the core is built from
	was := ctl.DefaultSettings()
	now := was
	now.UDPGuard = true
	if !was.SameCore(now) {
		t.Error("the guard counts as a setting that restarts the core")
	}

	// a value that is not 1 is off
	if set("0"); ctl.LoadSettings(paths.Settings()).UDPGuard {
		t.Error("not switched off")
	}
	// and the defaults put it off
	set("1")
	do(t, h, "POST", "/act/defaults", url.Values{}, nil)
	if ctl.LoadSettings(paths.Settings()).UDPGuard {
		t.Error("still on after the defaults")
	}
}

// What the service wrote is worded as it is: one text for each state and
// reason, and the Windows error where there is one.
func TestUDPGuardStates(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	if _, err := ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error { set.UDPGuard = true; return nil }); err != nil {
		t.Fatal(err)
	}
	frag := func(lang string) string {
		return do(t, h, "GET", "/frag/settings/guard", nil, map[string]string{"Cookie": "lang=" + lang}).Body.String()
	}

	// a service that has said nothing: an older one does not know the setting
	if b := frag("en"); !strings.Contains(b, "has not reported yet") {
		t.Errorf("nothing said by the service, and the page says: %s", b)
	}

	for _, c := range []struct {
		st      udpguard.Status
		en, ru  string
		class   string
		absent  string
		explain string
	}{
		{st: udpguard.Status{State: udpguard.StateOn, Rules: 8},
			en: "In place: UDP leaves the physical adapters only from the core and to the local network.",
			ru: "Работает: UDP через физические адаптеры уходит только от ядра", class: "ok-t"},
		{st: udpguard.Status{State: udpguard.StateOn, Rules: 8, Checked: true},
			en: "In place, and checked: the engine dropped a test packet sent out of the adapter by its own address.",
			ru: "Работает, проверено: движок сбросил тестовый пакет, отправленный с адреса адаптера.", class: "ok-t"},
		{st: udpguard.Status{State: udpguard.StateWait, Why: udpguard.WhyCore},
			en: "Waiting for the core to run.", ru: "Ждёт запуска ядра.", class: "muted"},
		{st: udpguard.Status{State: udpguard.StateWait, Why: udpguard.WhyAdapter},
			en: "Waiting for the DPI Switch adapter", ru: "Ждёт адаптер DPI Switch", class: "muted"},
		{st: udpguard.Status{State: udpguard.StateWait, Why: udpguard.WhyTraffic},
			en: "traffic from the DPI Switch adapter -- something takes it first", ru: "Windows не пускает трафик программ в адаптер", class: "warn-t"},
		{st: udpguard.Status{State: udpguard.StateFail, Why: udpguard.WhyEngine, Err: "The RPC server is unavailable."},
			en: "the Windows Filtering Platform does not answer", ru: "платформа фильтрации Windows не отвечает", class: "bad-t"},
		{st: udpguard.Status{State: udpguard.StateFail, Why: udpguard.WhyOther, Err: "The object already exists."},
			en: "Windows refused a filter (The object already exists.)", ru: "Windows отказала в фильтре (The object already exists.)", class: "bad-t"},
	} {
		if err := c.st.Save(paths.UDPGuard()); err != nil {
			t.Fatal(err)
		}
		if b := frag("en"); !strings.Contains(b, c.en) || !strings.Contains(b, `class="`+c.class+`"`) {
			t.Errorf("%s/%s in English, want %q in %s:\n%s", c.st.State, c.st.Why, c.en, c.class, b)
		}
		if b := frag("ru"); !strings.Contains(b, c.ru) {
			t.Errorf("%s/%s in Russian, want %q:\n%s", c.st.State, c.st.Why, c.ru, b)
		}
		// the Windows error is shown whole, and escaped
		if c.st.Err != "" {
			if b := frag("en"); !strings.Contains(b, c.st.Err) {
				t.Errorf("the error %q is not shown", c.st.Err)
			}
		}
	}

	// the page itself carries the state with it, not only the part that refreshes
	udpguard.Status{State: udpguard.StateOn, Rules: 8}.Save(paths.UDPGuard())
	if b := do(t, h, "GET", "/settings", nil, nil).Body.String(); !strings.Contains(b, "In place: UDP leaves") {
		t.Error("the settings page does not carry the guard's state")
	}

	// with the service stopped, what its file says is of a run that is over
	st := s.statusFn()
	st.ServiceRun = false
	s.statusFn = func() status { return st }
	if b := frag("en"); !strings.Contains(b, "The service is stopped: nothing is blocked.") || strings.Contains(b, "In place") {
		t.Errorf("a stopped service, and the page says: %s", b)
	}
	st.ServiceRun = true

	// and with the setting off the part says nothing, a file or not
	if _, err := ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error { set.UDPGuard = false; return nil }); err != nil {
		t.Fatal(err)
	}
	if b := strings.TrimSpace(frag("en")); b != "" {
		t.Errorf("the guard is off, and the part says: %s", b)
	}
}

// An error out of Windows with markup in it is text, not markup.
func TestUDPGuardErrorIsEscaped(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	if _, err := ctl.UpdateSettings(paths.Settings(), func(set *ctl.Settings) error { set.UDPGuard = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := (udpguard.Status{State: udpguard.StateFail, Why: udpguard.WhyOther, Err: "<script>x</script>"}).Save(paths.UDPGuard()); err != nil {
		t.Fatal(err)
	}
	b := do(t, h, "GET", "/frag/settings/guard", nil, nil).Body.String()
	if strings.Contains(b, "<script>") || !strings.Contains(b, "&lt;script&gt;") {
		t.Fatalf("not escaped: %s", b)
	}
}
