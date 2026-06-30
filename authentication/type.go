package authentication

import (
	"net/http"

	"github.com/blueyellowstudio/goose-base/authorization"
	"github.com/blueyellowstudio/goose-base/identityManager"
)

type LoginRedirectConfig struct {
	RedirectToTokenLoginAfterMagicLinkFailed bool
	TokenLoginPath                           string
	LoginErrorPath                           string
	AcceptInvitePath                         string

	// frontend url to direct to for the reset password flow
	SetPasswordPath string
}

type Authentication struct {
	identities             identityManager.IdentityManager
	tokenHandler           authorization.TokenHandler
	appUrl                 string
	tokenCookieName        string
	refreshTokenCookieName string
	isProduction           bool
	LoginRedirectConfig    LoginRedirectConfig
	refreshPath            string
}

func NewAuthentication(identityManager identityManager.IdentityManager,
	tokenHandler authorization.TokenHandler,
	appUrl, tokenCookieName, refreshTokenCookieName string,
	isProduction bool,
	loginRedirectConfig LoginRedirectConfig) *Authentication {

	return &Authentication{
		identities:             identityManager,
		tokenHandler:           tokenHandler,
		appUrl:                 appUrl,
		tokenCookieName:        tokenCookieName,
		refreshTokenCookieName: refreshTokenCookieName,
		isProduction:           isProduction,
		LoginRedirectConfig:    loginRedirectConfig,
		refreshPath:            "/",
	}
}

func (a *Authentication) SetRefreshPath(path string) {
	a.refreshPath = path
}

// respondWithError sends an error response
func (a *Authentication) respondWithError(w http.ResponseWriter, statusCode int, message string) {
	http.Error(w, message, statusCode)
}
