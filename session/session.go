// Package session provides provider-neutral server-side sessions: the browser holds only an
// opaque cookie, the tokens stay on the server.
package session

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound is returned by Store.Get when no session has the given id.
	ErrNotFound = errors.New("session: not found")
	// ErrRefreshRejected means the identity provider refused the refresh token.
	ErrRefreshRejected = errors.New("session: refresh rejected")
	// ErrRefreshExpired means the refresh token has already expired, so no session can be created.
	ErrRefreshExpired = errors.New("session: refresh token already expired")

	// errNoRefresher is a transient failure: NewManager accepts a nil Refresher, so a session
	// that needs a refresh must not crash the request.
	errNoRefresher = errors.New("session: no refresher configured")
)

// Refresher exchanges a refresh token for a new token set at the identity provider.
type Refresher interface {
	Refresh(ctx context.Context, refreshToken string) (Tokens, error)
}

// Tokens is the token set issued by the identity provider.
type Tokens struct {
	AccessToken      string
	RefreshToken     string
	IssuedAt         time.Time // zero when unknown
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
}

// Session is one logged-in browser. It holds only value fields: stores copy it by plain assignment.
type Session struct {
	// ID is the hex SHA-256 of the cookie value (D3), never the cookie value itself.
	ID        string
	Subject   string
	Tokens    Tokens
	CreatedAt time.Time
}

// expired is true at the boundary: a refresh token expiring exactly now is already unusable.
func expired(t Tokens, now time.Time) bool {
	return !t.RefreshExpiresAt.After(now)
}
