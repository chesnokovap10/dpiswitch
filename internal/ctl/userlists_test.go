package ctl

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"dpiswitch/internal/paths"
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
		"example.com:abc", "example.com:", "example.com:0", "example.com:70000"} {
		if _, _, err := ParseEntry(bad); err == nil {
			t.Errorf("%q taken", bad)
		}
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
		paths.DirectList:                "example.com\n",
		paths.IPList(paths.DirectList):  "1.2.3.4/32\n192.168.0.0/16\n",
		paths.AppList(paths.DirectList): "PROCESS-NAME,telegram.exe\nPROCESS-PATH,C:\\a b\\x.exe\nPROCESS-NAME,old.exe\n",
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

// Observe only with the cut on sends everything the cut's way -- its QUIC
// too, the decoy ahead of it. The decoy off, QUIC goes plain and TCP alone
// is cut: direct-split always carries the decoy.
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
		{true, true, "", "NETWORK,tcp NETWORK,udp"},
		{true, false, "NETWORK,udp", "NETWORK,tcp"},
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
