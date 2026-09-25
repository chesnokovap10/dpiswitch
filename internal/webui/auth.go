package webui

// The UI listens on 127.0.0.1, and loopback is shared by every user of the
// machine: guard keeps other web sites out, not another account's
// processes. Anyone signed in could send the forms -- load their own .conf
// and take the whole machine's traffic to their server, stop the tunnel.
//
// So every request carries a key. It is kept in the user's own profile,
// where other unprivileged accounts cannot read it, and survives restarts:
// an open tab and a bookmark keep working. The tray opens the UI with the
// key in the address; the first request trades it for a cookie and is
// sent on to the same page without it.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"dpiswitch/internal/paths"
)

const (
	keyParam  = "k"
	keyHeader = "X-DPISwitch-Key"
)

// KeyPath: where the key lives -- %LOCALAPPDATA%, readable by this user,
// SYSTEM and administrators only.
func KeyPath() (string, error) {
	dir := os.Getenv("LOCALAPPDATA")
	if dir == "" {
		return "", errors.New("LOCALAPPDATA is not set")
	}
	return filepath.Join(dir, paths.AppName, "ui.key"), nil
}

// LoadKey reads the key, making one the first time. A key that could not
// be kept is still returned with the error: the UI stays closed to others,
// only an open tab will not outlive a restart.
func LoadKey() (string, error) {
	p, err := KeyPath()
	if err == nil {
		if b, rerr := os.ReadFile(p); rerr == nil {
			if k := strings.TrimSpace(string(b)); len(k) >= 32 {
				return k, nil
			}
		}
	}
	var b [32]byte
	rand.Read(b[:]) // never fails (crypto/rand)
	k := hex.EncodeToString(b[:])
	if err != nil {
		return k, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return k, err
	}
	return k, os.WriteFile(p, []byte(k), 0o600)
}

// WithKey: an address of the UI that lets its first request in.
func WithKey(addr, key string) string {
	if key == "" {
		return addr
	}
	return addr + "?" + keyParam + "=" + key
}

// cookieName: one per port -- cookies do not tell ports apart, and two
// sessions of one account run two UIs on two ports.
func cookieName(host string) string {
	_, port, _ := strings.Cut(host, ":")
	return "dpiswitch_" + port
}

func (s *Server) auth(h http.Handler) http.Handler {
	if s.Key == "" {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == helloPath {
			h.ServeHTTP(w, r)
			return
		}
		if k := r.URL.Query().Get(keyParam); k != "" && s.keyOK(k) {
			http.SetCookie(w, &http.Cookie{Name: cookieName(r.Host), Value: s.Key, Path: "/",
				MaxAge: 400 * 24 * 3600, HttpOnly: true, SameSite: http.SameSiteStrictMode})
			// the same page, without the key in the address bar
			q := r.URL.Query()
			q.Del(keyParam)
			u := url.URL{Path: r.URL.Path, RawQuery: q.Encode()}
			http.Redirect(w, r, u.String(), http.StatusSeeOther)
			return
		}
		if c, err := r.Cookie(cookieName(r.Host)); err == nil && s.keyOK(c.Value) || s.keyOK(r.Header.Get(keyHeader)) {
			h.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`<!doctype html><meta charset="utf-8"><title>DPI Switch</title>
<p>Open DPI Switch from its tray icon.</p><p>Откройте DPI Switch через значок в трее.</p>`))
	})
}

// helloPath: where a second copy asks whether this is its UI (see answers).
// Open without the key: it gives out nothing but a proof of holding it.
const helloPath = "/api/hello"

// helloProof: how a UI holding key answers the challenge nonce on port. The
// port is the one the UI itself listens on: a process of another account
// sitting on a candidate port cannot pass on a real UI's answer as its own,
// since that one names the real UI's port.
func helloProof(key, port, nonce string) string {
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte("dpiswitch-hello|" + port + "|" + nonce))
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Server) handleHello(w http.ResponseWriter, r *http.Request) {
	nonce := r.URL.Query().Get("n")
	la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok || len(nonce) < 16 || len(nonce) > 128 {
		http.Error(w, "bad challenge", http.StatusBadRequest)
		return
	}
	_, port, _ := net.SplitHostPort(la.String())
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(helloProof(s.Key, port, nonce)))
}

func (s *Server) keyOK(k string) bool {
	return k != "" && subtle.ConstantTimeCompare([]byte(k), []byte(s.Key)) == 1
}
