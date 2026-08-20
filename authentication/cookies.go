package authentication

import (
	"net/http"

	"github.com/blueyellowstudio/goose-base/identityManager"
)

// SetAuthCookie writes the access and refresh tokens as HttpOnly cookies, which is how
// this package keeps a session out of reach of JavaScript. A nil authToken is a no-op.
//
// Exported as a pair with ClearAuthCookie so a service can establish or drop a session
// from a handler it owns — an accept-invite or delete-account flow that also writes
// application tables, say. Use these rather than hand-building the cookies: a browser
// only drops a cookie when the expiring Set-Cookie repeats the same name, path, Secure
// and SameSite, so a hand-rolled half leaves a session cookie logout cannot delete.
func (a *Authentication) SetAuthCookie(w http.ResponseWriter, authToken *identityManager.AuthResponse) {
	isProduction := a.isProduction
	if authToken == nil {
		return
	}

	sameSite := http.SameSiteLaxMode
	if isProduction {
		sameSite = http.SameSiteStrictMode
	}

	cookie := &http.Cookie{
		Name:     a.tokenCookieName,
		Value:    authToken.AccessToken,
		Path:     "/",
		MaxAge:   CookieMaxAge,
		HttpOnly: true,
		Secure:   isProduction,
		SameSite: sameSite,
	}
	http.SetCookie(w, cookie)

	refreshCookie := &http.Cookie{
		Name:     a.refreshTokenCookieName,
		Value:    authToken.RefreshToken,
		Path:     a.refreshPath,
		MaxAge:   CookieMaxAge,
		HttpOnly: true,
		Secure:   isProduction,
		SameSite: sameSite,
	}
	http.SetCookie(w, refreshCookie)
}

// ClearAuthCookie expires both session cookies. Every attribute below must keep
// mirroring SetAuthCookie — the browser matches on name, path, Secure and SameSite and
// silently keeps the original otherwise. Change one, change both.
func (a *Authentication) ClearAuthCookie(w http.ResponseWriter) {
	isProduction := a.isProduction

	sameSite := http.SameSiteLaxMode
	if isProduction {
		sameSite = http.SameSiteStrictMode
	}

	cookie := &http.Cookie{
		Name:     a.tokenCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isProduction,
		SameSite: sameSite,
	}
	http.SetCookie(w, cookie)

	refreshCookie := &http.Cookie{
		Name:     a.refreshTokenCookieName,
		Value:    "",
		Path:     a.refreshPath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isProduction,
		SameSite: sameSite,
	}
	http.SetCookie(w, refreshCookie)
}
