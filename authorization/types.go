package authorization

import "github.com/blueyellowstudio/goose-base/identityManager"

type Tokens = identityManager.AuthResponse
type Authorization struct {
	TokenCookieName        string
	RefreshTokenCookieName string
	jwtSecret              []byte
	TokenHandler           TokenHandler
	isProduction           bool
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
