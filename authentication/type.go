package authentication

import (
	"context"
	"net/http"

	"github.com/blueyellowstudio/goose-base/authorization"
	"github.com/blueyellowstudio/goose-base/identityManager"
	"github.com/google/uuid"
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
	onRegistered           RegisterHook
	onLogin                LoginHook
}

// RegisterHook runs after RegisterHandler's signup returned a user id. It never runs for
// an address Supabase reports as already registered: that request proved nothing about
// owning the address, so it must not write data for the account behind it.
//
// Its error is logged and changes nothing the caller sees — no 500, no deleted user. A
// status that depended on the hook would tell an anonymous caller which addresses are
// new. A failed hook therefore leaves an identity without its application row; repair
// that in a login hook (SetOnLogin), where the user id comes from a verified token.
//
// It MUST be idempotent and MUST NOT overwrite a row that is already present: req is
// anonymous input, and Supabase may return the existing id for an address that signed
// up earlier but never confirmed.
type RegisterHook func(ctx context.Context, userID uuid.UUID, req RegisterRequest) error

// SetOnRegistered installs the post-registration hook. Pass nil to remove it.
//
// Without a hook RegisterHandler behaves exactly as it did before hooks existed: no
// user id is parsed.
func (a *Authentication) SetOnRegistered(hook RegisterHook) {
	a.onRegistered = hook
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
