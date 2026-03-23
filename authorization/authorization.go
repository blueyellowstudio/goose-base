package authorization

import (
	"net/http"
	"strings"
)

const (
	CookieMaxAge = 7 * 24 * 60 * 60
)

// extractToken returns the authorization token from the request, refreshtoken
func (a *Authorization) extractToken(r *http.Request) string {
	// First, try Authorization header
	authHeader := r.Header.Get("Authorization")
	if token := strings.TrimPrefix(authHeader, "Bearer "); token != "" && token != authHeader {
		return token
	}

	// Then, try cookie
	cookie, err := r.Cookie(a.TokenCookieName)
	if err == nil && cookie.Value != "" {
		return cookie.Value
	}

	return ""
}
