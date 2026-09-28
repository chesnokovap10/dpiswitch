package tray

import (
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"
)

// A tooltip is cut to what the icon's tip holds, at a whole character: at
// 120 bytes a Russian one kept some 60 letters of 127, and could end in
// half a letter.
func TestClipTip(t *testing.T) {
	ru := "DPI Switch — туннель не отвечает: " + strings.Repeat("ошибка ", 30)
	for _, c := range []struct {
		in   string
		want int // UTF-16 units kept
	}{
		{"DPI Switch — tunnel up (60 ms)", 30},
		{strings.Repeat("a", 200), 127},
		{ru, 127},
		{strings.Repeat("😀", 70), 126}, // a pair does not fit in the 127th unit
	} {
		got := clipTip(c.in)
		if !utf8.ValidString(got) || !strings.HasPrefix(c.in, got) {
			t.Errorf("%q: cut badly: %q", c.in, got)
		}
		if n := len(utf16.Encode([]rune(got))); n != c.want {
			t.Errorf("%.20q...: %d units kept, want %d", c.in, n, c.want)
		}
	}
}
