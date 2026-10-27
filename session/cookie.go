package session

import (
	"net/http"
	"time"
)

func (m *Manager) setCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, m.cookie(value, maxAge))
}

func (m *Manager) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, m.cookie("", -1))
}

// cookie is the single source of attributes for set and clear: a browser only drops a cookie
// when name, path, Secure and SameSite match the one it holds.
func (m *Manager) cookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     m.cookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// maxAgeUntil rounds up: MaxAge 0 would be written as no Max-Age, a browser-session cookie
// that outlives the refresh token.
func maxAgeUntil(expiresAt, now time.Time) int {
	remaining := expiresAt.Sub(now)
	return int((remaining + time.Second - 1) / time.Second)
}
