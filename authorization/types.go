package authorization

import (
	"context"
	"fmt"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/blueyellowstudio/goose-base/identityManager"
)

type Tokens = identityManager.AuthResponse
type Authorization struct {
	TokenCookieName string
	jwtSecret       []byte
	jwks            keyfunc.Keyfunc
	TokenHandler    TokenHandler
	isProduction    bool
}

func NewAuthorization(tokenCookieName string, jwtSecret string, tokenHandler TokenHandler, isProduction bool) *Authorization {
	return &Authorization{
		TokenCookieName: tokenCookieName,
		jwtSecret:       []byte(jwtSecret),
		TokenHandler:    tokenHandler,
		isProduction:    isProduction,
	}
}

func NewAuthorizationDefault(jwtSecret string, tokenHandler TokenHandler, isProduction bool) *Authorization {
	return NewAuthorization("token", jwtSecret, tokenHandler, isProduction)
}

// NewAuthorizationWithJWKS enables ES256 (asymmetric) token verification via a
// Supabase project's JWKS endpoint, e.g. "<project>.supabase.co/auth/v1/.well-known/jwks.json".
// jwtSecret may be left empty to disable the legacy HS256 fallback entirely; otherwise
// both signing methods are accepted side by side during migration.
func NewAuthorizationWithJWKS(ctx context.Context, tokenCookieName string, jwtSecret string, jwksURL string, tokenHandler TokenHandler, isProduction bool) (*Authorization, error) {
	jwks, err := keyfunc.NewDefaultCtx(ctx, []string{jwksURL})
	if err != nil {
		return nil, fmt.Errorf("failed to load JWKS from %q: %w", jwksURL, err)
	}

	a := NewAuthorization(tokenCookieName, jwtSecret, tokenHandler, isProduction)
	a.jwks = jwks
	return a, nil
}
