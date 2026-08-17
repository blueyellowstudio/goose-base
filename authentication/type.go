package authentication

import (
	"net/http"

	"github.com/blueyellowstudio/goose-base/authorization"
	"github.com/blueyellowstudio/goose-base/identityManager"
)

type LoginRedirectConfig struct {
	RedirectToTokenLoginAfterMagicLinkFailed bool
	// frontend url which starts the magic token login, this is a frontend url, it needs the Email to enter and call the, /do-auth/token-login ("StartLoginHandler")
	TokenLoginPath   string
	LoginErrorPath   string
	AcceptInvitePath string

	// frontend url to direct to for the reset password flow
	SetPasswordPath string
}

type Authentication struct {
	identities             identityManager.IdentityManager
	tokenHandler           authorization.TokenHandler
	authorizer             *authorization.Authorization
	appUrl                 string
	tokenCookieName        string
	refreshTokenCookieName string
	isProduction           bool
	LoginRedirectConfig    LoginRedirectConfig
	refreshPath            string
	oauth                  OAuthConfig
}

// NewAuthentication builds the authentication handlers. The authorizer is needed by
// handlers that are mounted on the public router and therefore have to validate the
// request token themselves instead of reading it from the context, see SessionHandler.
//
// oauthConfig supplies the Supabase project URL and the absolute callback URL used by
// the PKCE handlers. Pass the zero value when the OAuth routes are not mounted — the
// start handler then refuses rather than building a half-formed authorize URL.
func NewAuthentication(identityManager identityManager.IdentityManager,
	tokenHandler authorization.TokenHandler,
	authorizer *authorization.Authorization,
	appUrl, tokenCookieName, refreshTokenCookieName string,
	isProduction bool,
	loginRedirectConfig LoginRedirectConfig,
	oauthConfig OAuthConfig) *Authentication {

	return &Authentication{
		identities:             identityManager,
		tokenHandler:           tokenHandler,
		authorizer:             authorizer,
		appUrl:                 appUrl,
		tokenCookieName:        tokenCookieName,
		refreshTokenCookieName: refreshTokenCookieName,
		isProduction:           isProduction,
		LoginRedirectConfig:    loginRedirectConfig,
		refreshPath:            "/",
		oauth:                  oauthConfig,
	}
}

func (a *Authentication) SetRefreshPath(path string) {
	a.refreshPath = path
}

// respondWithError sends an error response
func (a *Authentication) respondWithError(w http.ResponseWriter, statusCode int, message string) {
	http.Error(w, message, statusCode)
}
