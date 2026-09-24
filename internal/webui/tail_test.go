package webui

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// A second copy opens the UI that answers as DPI Switch, not whatever
// holds the first candidate port.
func TestAnswers(t *testing.T) {
	ours := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/status" {
			w.Write([]byte(`{"version":"1.0.7","data_dir":"C:/ProgramData/dpiswitch"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ours.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>someone else</html>`))
	}))
	defer other.Close()
	cl := &http.Client{Timeout: time.Second}
	if !answers(cl, strings.TrimPrefix(ours.URL, "http://")) {
		t.Fatal("our UI not recognised")
	}
	if answers(cl, strings.TrimPrefix(other.URL, "http://")) {
		t.Fatal("another program taken for our UI")
	}
	if answers(cl, "127.0.0.1:1") {
		t.Fatal("a closed port answered")
	}
}
