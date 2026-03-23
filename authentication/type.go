package authentication

import (
	"net/http"

	"github.com/blueyellowstudio/goose-base/authorization"
	"github.com/blueyellowstudio/goose-base/identityManager"
)

type Authentication struct {
	identities             identityManager.IdentityManager
	authorization          authorization.Authorization
	appUrl                 string
	tokenCookieName        string
	refreshTokenCookieName string
	isProduction           bool
}

func NewAuthentication(identityManager identityManager.IdentityManager,
	authorization authorization.Authorization,
	appUrl, tokenCookieName, refreshTokenCookieName string,
	isProduction bool) *Authentication {

	return &Authentication{
		identities:             identityManager,
		authorization:          authorization,
		appUrl:                 appUrl,
		tokenCookieName:        tokenCookieName,
		refreshTokenCookieName: refreshTokenCookieName,
		isProduction:           isProduction,
	}
}

// respondWithError sends an error response
func (a *Authentication) respondWithError(w http.ResponseWriter, statusCode int, message string) {
	http.Error(w, message, statusCode)
}
