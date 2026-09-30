package webui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A browser that has not switched the language gets the tray's -- the one
// last switched to, else Windows' -- and not its own Accept-Language; one
// that has keeps its cookie.
func TestPagesSpeakTheTraysLanguage(t *testing.T) {
	s, dir := testServer(t)
	s.LangFile = filepath.Join(dir, "lang")
	h := s.Handler()
	shown := func(hdr map[string]string) string {
		body := do(t, h, "GET", "/overview", nil, hdr).Body.String()
		for _, l := range []string{"ru", "en"} {
			if strings.Contains(body, `<html lang="`+l+`">`) {
				return l
			}
		}
		t.Fatalf("no language on the page:\n%s", body)
		return ""
	}
	for _, l := range []string{"ru", "en"} {
		if err := os.WriteFile(s.LangFile, []byte(l+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		other := map[string]string{"ru": "en-US,en;q=0.9", "en": "ru-RU,ru;q=0.9"}[l]
		if got := shown(map[string]string{"Accept-Language": other}); got != l {
			t.Errorf("lang file %s, browser %s: the page is in %s", l, other, got)
		}
	}
	// the file says en: a cookie of ru wins
	if got := shown(map[string]string{"Cookie": "lang=ru"}); got != "ru" {
		t.Errorf("cookie ru: the page is in %s", got)
	}
	// no file: Windows' language, whatever it is here
	os.Remove(s.LangFile)
	if got, want := shown(nil), SavedLang(s.LangFile); got != want {
		t.Errorf("no lang file: the page is in %s, Windows says %s", got, want)
	}
}
