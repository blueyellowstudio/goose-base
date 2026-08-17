package authentication

import (
	"encoding/json"
	"net/http"
)

// SessionResponse answers "who am I, and am I still signed in" for a client that
// authenticates through HttpOnly cookies and therefore cannot read its own token.
// The identity fields are omitted while the caller is anonymous.
type SessionResponse struct {
	Authenticated bool   `json:"authenticated"`
	UserID        string `json:"userId,omitempty"`
	Email         string `json:"email,omitempty"`
	Username      string `json:"username,omitempty"`
	Role          string `json:"role,omitempty"`
}

// SessionHandler reports the session carried by the request's cookie.
//
// It must be mounted on the PUBLIC router, not behind Authorization.Handler: a
// missing or expired cookie is the normal state of a logged-out visitor, so the
// handler always answers 200 with {"authenticated": false} instead of 401. Being
// public it cannot read the identity from the context and validates the token
// itself via Authorization.IdentityFromRequest.
func (a *Authentication) SessionHandler(w http.ResponseWriter, r *http.Request) {
	response := SessionResponse{Authenticated: false}

	if a.authorizer != nil {
		if identity, ok := a.authorizer.IdentityFromRequest(r); ok {
			response = SessionResponse{
				Authenticated: true,
				UserID:        identity.UserID.String(),
				Email:         identity.UserEmail,
				Username:      identity.Username,
				Role:          identity.Role,
			}
		}
	}

	// no-store keeps a proxy or the bfcache from serving one user's session to another.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}
