package authentication

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/blueyellowstudio/goose-base/identityManager"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// LoginHook runs after a login has written a new session cookie pair and before the
// response is sent, so it may add cookies or headers of its own to w. userID is the
// subject of the new access token.
//
// It cannot fail the login: the session exists by the time it runs, so the hook logs
// its own errors. A token refresh is not a login and never runs it.
type LoginHook func(w http.ResponseWriter, r *http.Request, userID uuid.UUID)

// SetOnLogin installs the post-login hook. Pass nil to remove it.
//
// Without a hook every login behaves exactly as it did before hooks existed: no token is
// parsed.
func (a *Authentication) SetOnLogin(hook LoginHook) {
	a.onLogin = hook
}

// startSession writes the session cookies of a completed login, then runs the login hook.
func (a *Authentication) startSession(w http.ResponseWriter, r *http.Request, session *identityManager.AuthResponse) {
	a.SetAuthCookie(w, session)
	if a.onLogin == nil || session == nil {
		return
	}

	userID, err := subjectOf(session.AccessToken)
	if err != nil {
		slog.Error("login hook skipped: new access token carries no user id", "path", r.URL.Path, "err", err)
		return
	}
	a.onLogin(w, r, userID)
}

// subjectOf reads the user id of an access token the identity provider has just issued.
// The signature is not checked: the token comes from our own call to the provider, never
// from the browser.
func subjectOf(accessToken string) (uuid.UUID, error) {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(accessToken, claims); err != nil {
		return uuid.Nil, fmt.Errorf("parse access token: %w", err)
	}

	subject, _ := claims["sub"].(string)
	userID, err := uuid.Parse(subject)
	if err != nil {
		return uuid.Nil, fmt.Errorf("access token subject is not a user id: %w", err)
	}
	return userID, nil
}
