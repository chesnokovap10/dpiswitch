package webui

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// tail reads a log from its end: the last lines, whole, as they were.
func TestTail(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var small, big strings.Builder
	for i := 1; i <= 10; i++ {
		fmt.Fprintf(&small, "line %d\r\n", i)
	}
	// past the window, with lines long enough that it starts mid-line
	for i := 1; i <= 5000; i++ {
		fmt.Fprintf(&big, "line %d %s\n", i, strings.Repeat("x", 90))
	}
	for _, tc := range []struct {
		name, body string
		lines      int
		first      string
		last       string
		count      int
	}{
		{"short, CRLF", small.String(), 400, "line 1", "line 10", 10},
		{"past the window", big.String(), 400, "line 4601 " + strings.Repeat("x", 90),
			"line 5000 " + strings.Repeat("x", 90), 400},
		{"no newline at the end", "a\nb\nc", 2, "b", "c", 2},
		{"empty", "", 400, "", "", 1},
	} {
		got, err := tail(write(strings.ReplaceAll(tc.name, " ", "_")+".log", tc.body), tc.lines)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		ls := strings.Split(got, "\n")
		if len(ls) != tc.count || ls[0] != tc.first || ls[len(ls)-1] != tc.last {
			t.Errorf("%s: %d lines, first %q, last %q", tc.name, len(ls), ls[0], ls[len(ls)-1])
		}
	}
	if _, err := tail(filepath.Join(dir, "missing.log"), 400); err == nil {
		t.Error("a missing log gave no error")
	}
}

// A second copy opens the UI that answers as DPI Switch with its key, not
// whatever holds the first candidate port -- another program, or another
// user's DPI Switch.
func TestAnswers(t *testing.T) {
	s, _ := testServer(t)
	s.Key = strings.Repeat("ab", 32)
	ours := httptest.NewServer(s.Handler())
	defer ours.Close()
	// another account's process on a candidate port: it sees whatever the
	// question carries, and passes it on to the real UI
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.String()+fmt.Sprint(r.Header), s.Key) {
			leaked.Store(true)
		}
		resp, err := http.Get(ours.URL + r.URL.String())
		if err != nil {
			return
		}
		defer resp.Body.Close()
		io.Copy(w, resp.Body)
	}))
	defer other.Close()
	cl := &http.Client{Timeout: time.Second}
	if !answers(cl, strings.TrimPrefix(ours.URL, "http://"), s.Key) {
		t.Fatal("our UI not recognised")
	}
	if answers(cl, strings.TrimPrefix(ours.URL, "http://"), strings.Repeat("cd", 32)) {
		t.Fatal("a UI with another key taken for ours")
	}
	if answers(cl, strings.TrimPrefix(other.URL, "http://"), s.Key) {
		t.Fatal("another program passing on our UI's answer taken for our UI")
	}
	if leaked.Load() {
		t.Fatal("the key went to another program")
	}
	if answers(cl, "127.0.0.1:1", s.Key) {
		t.Fatal("a closed port answered")
	}
}
