package webui

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// The program's language is the one its pages were last shown in: the tray
// -- menu, tooltip, messages -- follows it. A switch pressed on a page is
// kept in LangFile, so the tray starts in it next time too; before either,
// Windows' own display language -- the pages' too (see withLang).

// Tr: a string in the language given, from the same table as the pages'
func Tr(lang, en string) string { return tr(lang, en) }

// SavedLang: the language last switched to on a page, else Windows'
func SavedLang(file string) string {
	if file != "" {
		if b, err := os.ReadFile(file); err == nil {
			if l := strings.TrimSpace(string(b)); l == "ru" || l == "en" {
				return l
			}
		}
	}
	if ls, err := windows.GetUserPreferredUILanguages(windows.MUI_LANGUAGE_NAME); err == nil && len(ls) > 0 &&
		strings.HasPrefix(strings.ToLower(ls[0]), "ru") {
		return "ru"
	}
	return "en"
}

// Lang: the language the pages were last shown in
func (s *Server) Lang() string {
	s.mu.Lock()
	l := s.lang
	s.mu.Unlock()
	if l == "" {
		return SavedLang(s.LangFile)
	}
	return l
}

// shownIn: a page was shown in l; a switch (saved) is kept for the next start
func (s *Server) shownIn(l string, saved bool) {
	s.mu.Lock()
	changed := s.lang != l
	s.lang = l
	s.mu.Unlock()
	if saved && s.LangFile != "" {
		_ = os.MkdirAll(filepath.Dir(s.LangFile), 0o700)
		_ = os.WriteFile(s.LangFile, []byte(l+"\n"), 0o600)
	}
	if changed && s.OnLang != nil {
		s.OnLang()
	}
}
