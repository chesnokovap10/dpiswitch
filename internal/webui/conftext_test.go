package webui

import (
	"bytes"
	"mime/multipart"
	"net/http/httptest"
	"strings"
	"testing"
)

// A .conf past confMax is refused, not cut to its first part.
func TestConfTextTooLarge(t *testing.T) {
	form := func(field, text string, file bool) (string, string) {
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		if file {
			fw, _ := w.CreateFormFile(field, "a.conf")
			fw.Write([]byte(text))
		} else {
			w.WriteField(field, text)
		}
		w.Close()
		return b.String(), w.FormDataContentType()
	}
	big := "[Interface]\n" + strings.Repeat("# x\n", confMax/4)
	for _, file := range []bool{true, false} {
		field := "text"
		if file {
			field = "file"
		}
		body, ct := form(field, big, file)
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.Header.Set("Content-Type", ct)
		if _, err := confText(r); err == nil {
			t.Errorf("file=%v: a .conf of %d bytes taken", file, len(big))
		}
		body, ct = form(field, "[Interface]\nPrivateKey = x\n", file)
		r = httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.Header.Set("Content-Type", ct)
		if _, err := confText(r); err != nil {
			t.Errorf("file=%v: a small .conf refused: %v", file, err)
		}
	}
}
