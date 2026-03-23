package authentication

import (
	"net/http"

	"github.com/blueyellowstudio/goose-base/identityManager"
)

func (a *Authentication) setAuthCookie(w http.ResponseWriter, authToken *identityManager.AuthResponse) {
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
		Path:     "/",
		MaxAge:   CookieMaxAge,
		HttpOnly: true,
		Secure:   isProduction,
		SameSite: sameSite,
	}
	http.SetCookie(w, refreshCookie)
}

func (a *Authentication) clearAuthCookie(w http.ResponseWriter) {
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
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isProduction,
		SameSite: sameSite,
	}
	http.SetCookie(w, refreshCookie)
}
