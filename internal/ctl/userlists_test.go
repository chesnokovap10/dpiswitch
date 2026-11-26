package ctl

import (
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"dpiswitch/internal/paths"
	"dpiswitch/internal/presets"
)

// A line of a user list is a site, an address or a program, written the one
// way the core reads it; anything else is refused.
func TestParseEntry(t *testing.T) {
	for in, want := range map[string]struct {
		kind int
		v    string
	}{
		"Example.COM":                       {EntryName, "example.com"},
		"+.example.org":                     {EntryName, "+.example.org"},
		"https://www.example.com:8443/path": {EntryName, "www.example.com"},
		"example.com:443":                   {EntryName, "example.com"},
		"https://example.com?ref=123":       {EntryName, "example.com"},
		"https://example.com:8443?ref=1":    {EntryName, "example.com"},
		"https://example.com#top":           {EntryName, "example.com"},
		"example.com/?a=b#c":                {EntryName, "example.com"},
		"+.Example.*":                       {EntryName, "+.example.*"},
		"a.*.example.com":                   {EntryName, "a.*.example.com"},
		".example.*":                        {EntryName, ".example.*"},
		"*.*.example.com":                   {EntryName, "*.*.example.com"},
		"+.пример.*":                        {EntryName, "+.xn--e1afmkfd.*"},
		"1.2.3.4":                           {EntryIP, "1.2.3.4"},
		"1.2.3.4/32":                        {EntryIP, "1.2.3.4"},
		"192.168.12.0/16":                   {EntryIP, "192.168.0.0/16"},
		"10.0.0.0/8":                        {EntryIP, "10.0.0.0/8"},
		"2001:DB8::1":                       {EntryIP, "2001:db8::1"},
		"2001:db8::/32":                     {EntryIP, "2001:db8::/32"},
		"https://1.2.3.4:8443/x":            {EntryIP, "1.2.3.4"},
		"[2001:db8::1]:443":                 {EntryIP, "2001:db8::1"},
		"Telegram.exe":                      {EntryApp, "Telegram.exe"},
		"пример.рф":                         {EntryName, "xn--e1afmkfd.xn--p1ai"},
		"+.Госуслуги.рф":                    {EntryName, "+.xn--c1aapkosapc.xn--p1ai"},
		"https://пример.рф/путь":            {EntryName, "xn--e1afmkfd.xn--p1ai"},
		"example.com.":                      {EntryName, "example.com"},
		"http://[2001:db8::1]/x":            {EntryIP, "2001:db8::1"},
		"[2001:db8::1]":                     {EntryIP, "2001:db8::1"},
		`"C:\Games\Steam\steam.exe"`:        {EntryApp, `C:\Games\Steam\steam.exe`},
	} {
		kind, v, err := ParseEntry(in)
		if err != nil || kind != want.kind || v != want.v {
			t.Errorf("%q: %d %q %v, want %d %q", in, kind, v, err, want.kind, want.v)
		}
	}
	for _, bad := range []string{"bad host", "MATCH,DIRECT", "a,b.exe", "300.1.1.1/8", "",
		"example.com:abc", "site..com", ".example..com", "example.com:", "example.com:0", "example.com:70000",
		"*", "+.*", "*.*", "1.2.*", "ex*ample.com", "example.+", "a.+.com"} {
		if _, _, err := ParseEntry(bad); err == nil {
			t.Errorf("%q taken", bad)
		}
	}
}

// enabled_presets follows only the enabled presets, regardless of which
// route file holds the virtual row, and becomes empty when it is removed.
func TestEnabledPresets(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	all := presets.Load()
	if len(all) == 0 || len(PresetRules(all[0])) == 0 {
		t.Fatal("no shipped preset with rules")
	}
	if _, err := UpdateSettings(paths.Settings(), func(s *Settings) error {
		s.Awg2Presets = []string{all[0].ID}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(paths.User(paths.Awg2List), []byte("own.example\nown.exe\n"), 0o644)
	os.WriteFile(paths.User(paths.DirectList), []byte(EnabledPresets+"\nstrict.example\n"), 0o644)
	changed := SyncUserFiles()
	if !contains(changed, EnabledPresetsProvider) || !Synced(paths.DirectList) {
		t.Fatalf("changed %v, synced %v", changed, Synced(paths.DirectList))
	}
	b, err := os.ReadFile(paths.EnabledPresets())
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	for _, want := range []string{PresetRules(all[0])[0]} {
		if !strings.Contains(body, want+"\n") {
			t.Errorf("generated enabled_presets lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "own.example") || strings.Contains(body, "own.exe") {
		t.Fatalf("enabled_presets contains the old awg2 own list:\n%s", body)
	}
	os.WriteFile(paths.User(paths.DirectList), []byte("strict.example\n"), 0o644)
	if got := SyncUserFiles(); !contains(got, EnabledPresetsProvider) {
		t.Fatalf("marker removal did not change provider: %v", got)
	}
	if b, _ := os.ReadFile(paths.EnabledPresets()); strings.Contains(string(b), PresetRules(all[0])[0]) {
		t.Fatalf("marker removed, rules remain:\n%s", b)
	}
}

// A list goes to the core as three files, one per kind; lines of none of
// them are left out, and the program list's old "PROCESS-NAME,x" lines are
// read as programs.
func TestSplitList(t *testing.T) {
	in := strings.Join([]string{"# mine", "example.com", "1.2.3.4", "192.168.12.0/16", "telegram.exe",
		"C:/a b/x.exe", "PROCESS-NAME,old.exe", "DOMAIN-SUFFIX,evil.com", "MATCH,DIRECT", "bad host"}, "\n")
	got := splitList([]byte(in)).bodies(paths.DirectList)
	want := map[string]string{
		paths.DirectList:                "+.evil.com\nexample.com\n",
		paths.IPList(paths.DirectList):  "1.2.3.4/32\n192.168.0.0/16\n",
		paths.AppList(paths.DirectList): "PROCESS-PATH,C:\\a b\\x.exe\nPROCESS-NAME,old.exe\nPROCESS-NAME,telegram.exe\n",
	}
	for f, w := range want {
		if string(got[f]) != w {
			t.Errorf("%s: %q, want %q", f, got[f], w)
		}
	}
	if b := splitList(nil).bodies(paths.TunnelList); string(b[paths.TunnelList]) != "# empty\n" {
		t.Fatalf("empty: %q", b[paths.TunnelList])
	}
}

func TestParseList(t *testing.T) {
	in := strings.Join([]string{
		"# comment", "DOMAIN,Example.com", "DOMAIN-SUFFIX,example.org", "IP-CIDR,192.168.12.3/24,no-resolve",
		"PROCESS-NAME,Telegram.exe", "0.0.0.0 hosts.example", "||ads.example^", "ENABLED_PRESETS", "example.com", "bad host",
	}, "\n")
	d := ParseList(in, ListPolicy{AllowEnabledPresets: true})
	want := "enabled_presets\n+.ads.example\n+.example.org\nexample.com\nhosts.example\n192.168.12.0/24\nTelegram.exe"
	if got := strings.Join(d.Values(), "\n"); got != want {
		t.Errorf("parsed list:\n%s\nwant:\n%s", got, want)
	}
	if len(d.Issues) != 1 || d.Issues[0].Line != 10 || d.Issues[0].Raw != "bad host" {
		t.Fatalf("issues: %+v", d.Issues)
	}
	if len(d.Normalized) != 7 || len(d.Duplicates) != 1 || d.Duplicates[0].FirstLine != 2 || d.Duplicates[0].Line != 9 {
		t.Fatalf("normalization: changes %+v, duplicates %+v", d.Normalized, d.Duplicates)
	}
	if d := ParseList("enabled_presets", ListPolicy{}); len(d.Entries) != 0 || len(d.Issues) != 1 {
		t.Fatalf("macro outside routing rules: %+v", d)
	}
}

func TestParseImportedListFormats(t *testing.T) {
	in := strings.Join([]string{
		"payload: # Mihomo provider",
		"  - 'DOMAIN-SUFFIX,Example.net,Proxy'",
		`  - "IP-CIDR,192.168.7.9/24,DIRECT,no-resolve"`,
		"  - PROCESS-NAME,Telegram.exe,REJECT",
		"0.0.0.0 ads.example tracker.example # hosts aliases",
		"127.0.0.1 localhost.example ads.example",
		"https://www.example.org/path#fragment # imported URL",
		"[Adblock Plus 2.0]",
		"! a comment",
		"||options.example^$third-party",
		`"C:\Program Files\Folder #1\app.exe"`,
	}, "\n")
	d := ParseList(in, ListPolicy{})
	if len(d.Issues) != 0 {
		t.Fatalf("issues: %+v", d.Issues)
	}
	want := "+.example.net\n+.options.example\nads.example\nlocalhost.example\ntracker.example\nwww.example.org\n192.168.7.0/24\nC:\\Program Files\\Folder #1\\app.exe\nTelegram.exe"
	if got := strings.Join(d.Values(), "\n"); got != want {
		t.Errorf("parsed import:\n%s\nwant:\n%s", got, want)
	}
	if len(d.Duplicates) != 1 || d.Duplicates[0].Value != "ads.example" || d.Duplicates[0].FirstLine != 5 || d.Duplicates[0].Line != 6 {
		t.Fatalf("duplicates: %+v", d.Duplicates)
	}
	if len(d.Normalized) != 10 {
		t.Fatalf("normalizations: %+v", d.Normalized)
	}
}

func TestImportedListCommentsDoNotHideInvalidNativeLines(t *testing.T) {
	d := ParseList("bad host # not a hosts or YAML comment\n@@||allowed.example^", ListPolicy{})
	if len(d.Entries) != 0 || len(d.Issues) != 2 {
		t.Fatalf("invalid native lines were hidden: %+v", d)
	}
}

func TestParseImportedListRejectsUnknownRules(t *testing.T) {
	d := ParseList("payload:\n  - GEOIP,CN,DIRECT\n  - IP-CIDR,10.0.0.0/8,DIRECT,bad-option", ListPolicy{})
	if len(d.Entries) != 0 || len(d.Issues) != 2 || d.Issues[0].Line != 2 || d.Issues[1].Line != 3 {
		t.Fatalf("unknown rules: %+v", d)
	}
}

func TestDomainRuleRelation(t *testing.T) {
	for _, c := range []struct {
		rule, container string
		overlap, within bool
	}{
		{"example.com", "example.com", true, true},
		{"api.example.com", "+.example.com", true, true},
		{"+.example.com", ".example.com", true, false},
		{".example.com", "+.example.com", true, true},
		{"*.example.com", ".example.com", true, true},
		{"example.com", ".example.com", false, false},
		{"a.*.example.com", "+.example.com", true, true},
		{"+.example.*", "+.example.com", true, false},
		{"+.example.com", "+.example.*", true, true},
		{"+.foo.*", "+.bar.com", false, false},
		{"+.example.com", "*.example.com", true, false},
		{"*.example.com", "+.example.com", true, true},
		{"+.a.example.com", "*.example.com", true, false},
		{"API.Example.COM", "+.example.com", true, true},
	} {
		overlap, within := DomainRuleRelation(c.rule, c.container)
		if overlap != c.overlap || within != c.within {
			t.Errorf("%s in %s: overlap %v, within %v; want %v, %v", c.rule, c.container, overlap, within, c.overlap, c.within)
		}
	}
}

func TestParseEntryDomainLimits(t *testing.T) {
	for _, line := range []string{
		strings.Repeat("a", 64) + ".example",
		strings.Repeat("a.", 126) + "aa",
	} {
		if _, _, err := ParseEntry(line); err == nil {
			t.Errorf("accepted an overlong domain: %q", line)
		}
	}
}

func FuzzParseListRoundTrip(f *testing.F) {
	for _, seed := range []string{
		"example.com\n10.0.0.1\ntelegram.exe",
		"DOMAIN-SUFFIX,Example.org\nIP-CIDR,192.168.1.7/24,no-resolve\nENABLED_PRESETS",
		"0.0.0.0 ads.example\n||tracker.example^\n# comment",
		"[Adblock Plus 2.0]\n! comment\n||tracker.example^$third-party",
		"bad host\nDOMAIN,too,many",
		"+.пример.рф\nC:/Program Files/App/app.exe",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 1<<20 {
			t.Skip()
		}
		d := ParseList(text, ListPolicy{AllowEnabledPresets: true})
		if len(d.Issues) != 0 {
			return
		}
		canonical := strings.Join(d.Values(), "\n")
		again := ParseList(canonical, ListPolicy{AllowEnabledPresets: true})
		if len(again.Issues) != 0 || len(again.Duplicates) != 0 {
			t.Fatalf("canonical list did not parse cleanly: %+v", again)
		}
		if got := strings.Join(again.Values(), "\n"); got != canonical {
			t.Fatalf("round trip changed canonical list:\n%s\ninto:\n%s", canonical, got)
		}
	})
}

// The programs' list of its own from before is taken into the direct list
// until that is saved.
func TestSyncOldApps(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(paths.User(paths.AppsList), []byte("PROCESS-NAME,wow.exe\n"), 0o644)
	SyncUserFiles()
	if got := listRules(paths.ForceDirectApps()); len(got) != 1 || got[0] != "PROCESS-NAME,wow.exe" {
		t.Fatalf("old program list not taken: %v", got)
	}
	os.WriteFile(paths.User(paths.DirectList), []byte("bank.example\n10.1.0.0/16\n"), 0o644)
	SyncUserFiles()
	if got := listRules(paths.ForceDirectApps()); len(got) != 1 || !Synced(paths.DirectList) {
		t.Fatalf("programs lost beside the direct list: %v", got)
	}
	if got := listRules(paths.Data(paths.IPList(paths.DirectList))); len(got) != 1 || got[0] != "10.1.0.0/16" {
		t.Fatalf("addresses: %v", got)
	}
}

// The service copies what the user changed, says which providers changed,
// writes the presets the settings ask for, and reads no list through a link.
func TestSyncUserFiles(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := paths.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(paths.Data(paths.DirectList), []byte("# empty\n"), 0o644)
	os.WriteFile(paths.User(paths.DirectList), []byte("example.com\n"), 0o644)
	got := SyncUserFiles()
	if !contains(got, "force-direct") || !Synced(paths.DirectList) {
		t.Fatalf("changed %v, synced %v", got, Synced(paths.DirectList))
	}
	if !contains(got, PresetsProvider) {
		t.Fatalf("presets not written: %v", got)
	}
	if again := SyncUserFiles(); len(again) != 0 {
		t.Fatalf("nothing changed, yet %v", again)
	}
	// a user list that is a link is not followed
	os.Remove(paths.User(paths.TunnelList))
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", paths.User(paths.TunnelList), t.TempDir()).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v %s", err, out)
	}
	if got := SyncUserFiles(); contains(got, "force-tunnel") {
		t.Fatalf("a junction was taken as a list: %v", got)
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// An unreadable memory is set aside, not overwritten by the empty one.
func TestLoadStateBad(t *testing.T) {
	p := t.TempDir() + `\state.json`
	os.WriteFile(p, []byte(`{"networks": {"AS1": `), 0o644)
	st := loadState(p)
	if len(st.Networks) != 0 {
		t.Fatalf("%v", st.Networks)
	}
	if b, err := os.ReadFile(p + ".bad"); err != nil || !strings.Contains(string(b), "AS1") {
		t.Fatalf("not set aside: %q %v", b, err)
	}
	if err := st.save(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p + ".bad"); !strings.Contains(string(b), "AS1") {
		t.Fatal("the saved copy was overwritten")
	}
}

// Observe only is a plain-direct catch-all. The cut is limited to names the
// detector verified and therefore never takes unrelated composite-site hosts.
func TestObserveFilesQUICDecoy(t *testing.T) {
	rules := func(b []byte) []string {
		var out []string
		for _, l := range strings.Split(string(b), "\n") {
			if l != "" && !strings.HasPrefix(l, "#") {
				out = append(out, l)
			}
		}
		return out
	}
	for _, c := range []struct {
		split, decoy bool
		plain, cut   string
	}{
		{true, true, "NETWORK,tcp NETWORK,udp", ""},
		{true, false, "NETWORK,tcp NETWORK,udp", ""},
		{false, true, "NETWORK,tcp NETWORK,udp", ""},
		{false, false, "NETWORK,tcp NETWORK,udp", ""},
	} {
		plain, cut := observeFiles(Settings{SplitHello: c.split, QUICFake: c.decoy})
		if got := strings.Join(rules(plain), " "); got != c.plain {
			t.Errorf("cut %v, decoy %v: plain %q, want %q", c.split, c.decoy, got, c.plain)
		}
		if got := strings.Join(rules(cut), " "); got != c.cut {
			t.Errorf("cut %v, decoy %v: cut %q, want %q", c.split, c.decoy, got, c.cut)
		}
	}
}

// A "*" is one whole label anywhere in a line, as the core reads it.
func TestMatchDomainRuleWildcard(t *testing.T) {
	for _, c := range []struct {
		rule, host string
		want       bool
	}{
		{"+.example.*", "example.com", true},
		{"+.example.*", "a.b.example.net", true},
		{"+.example.*", "example.co.uk", false},
		{"+.example.*", "notexample.com", false},
		{"example.*", "example.ru", true},
		{"example.*", "a.example.ru", false},
		{".example.*", "example.ru", false},
		{".example.*", "a.example.ru", true},
		{"a.*.example.com", "a.b.example.com", true},
		{"a.*.example.com", "a.b.c.example.com", false},
		{"*.example.com", "b.example.com", true},
		{"*.example.com", "a.b.example.com", false},
		{"+.example.com", "example.com", true},
		{".example.com", "example.com", false},
		{"example.com", "example.com", true},
	} {
		if got := MatchDomainRule(c.rule, c.host); got != c.want {
			t.Errorf("%s ~ %s: %v", c.rule, c.host, got)
		}
	}
	n := loadPinned(nil)
	n.add("+.example.*")
	n.add(nameRule("a.*.other.com"))
	// "*." one level deep, as the core has it: a deeper name is not pinned,
	// and is probed -- unprobed, a family's rule sent it direct
	n.add(nameRule("*.third.com"))
	for dom, want := range map[string]bool{"x.example.com": true, "a.b.other.com": true, "example.co.uk": false, "b.b.other.com": false,
		"a.third.com": true, "b.a.third.com": false, "third.com": false} {
		if n.has(dom) != want {
			t.Errorf("pinned %s: %v", dom, !want)
		}
	}
}

// A preset's line with a "*" past its start is a regex the core matches by
// one label, read back as the line it was.
func TestPresetWildcard(t *testing.T) {
	for line, re := range map[string]string{
		"+.example.*":     `DOMAIN-REGEX,^(.+\.)?example\.[^.]+$`,
		".example.*":      `DOMAIN-REGEX,^.+\.example\.[^.]+$`,
		"example.*":       `DOMAIN-REGEX,^example\.[^.]+$`,
		"a.*.example.com": `DOMAIN-REGEX,^a\.[^.]+\.example\.com$`,
		"*.example.com":   `DOMAIN-REGEX,^[^.]+\.example\.com$`,
		".example.com":    `DOMAIN-REGEX,^.+\.example\.com$`,
		"+.example.com":   `DOMAIN-SUFFIX,example.com`,
	} {
		if got := nameRule(line); got != re {
			t.Errorf("%s: %s", line, got)
		}
		if back := PresetNameLine(re); back != line {
			t.Errorf("%s read back as %q", re, back)
		}
	}
}

func TestClassifyListLines(t *testing.T) {
	text := "\n# note\nexample.com\n192.0.2.1\n192.0.2.0/24\ngame.exe\nenabled_presets\nbad host\n0.0.0.0 one.example two.example"
	got := ClassifyListLines(text, ListPolicy{AllowEnabledPresets: true})
	want := []ListLineClass{
		{Kind: "blank"}, {Kind: "comment"}, {Kind: "site"}, {Kind: "ip"},
		{Kind: "network"}, {Kind: "program"}, {Kind: "presets"}, {Kind: "error"},
		{Kind: "site", Count: 2},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("classes:\n got %#v\nwant %#v", got, want)
	}
}
