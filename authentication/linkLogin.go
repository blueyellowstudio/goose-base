package authentication

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
)

const (
	LinkTypeInvite    = "invite"
	LinkTypeMagicLink = "magiclink"
	LinkTypeRecovery  = "recovery"
	LinkTypeSignup    = "signup"
)

func (a *Authentication) AuthLinkHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	linkType := r.URL.Query().Get("type")

	if token == "" || linkType == "" {
		slog.Error("Missing token or type in auth link request")
		a.redirectToError(w, r, "Missing token or type parameter")
		return
	}

	if !isValidLinkType(linkType) {
		slog.Error("Invalid link type", "type", linkType)
		a.redirectToError(w, r, "Invalid link type")
		return
	}

	redirectURL := a.getRedirectURLForLinkType(linkType)
	tokenResp, err := a.identities.VerifyTokenHash(r.Context(), token, linkType)
	if err != nil {
		slog.Error("Failed to verify auth link token", "error", err, "type", linkType)

		if a.LoginRedirectConfig.RedirectToTokenLoginAfterMagicLinkFailed {
			a.redirectToMagicLogin(w, r, redirectURL)
			return
		}

		a.redirectToError(w, r, "Invalid or expired link")
		return
	}

	a.setAuthCookie(w, tokenResp)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func isValidLinkType(linkType string) bool {
	switch linkType {
	case LinkTypeInvite, LinkTypeMagicLink, LinkTypeRecovery, LinkTypeSignup:
		return true
	default:
		return false
	}
}

func (a *Authentication) getRedirectURLForLinkType(linkType string) string {
	appURL := a.appUrl

	switch linkType {
	case LinkTypeInvite:
		return appURL + a.LoginRedirectConfig.AcceptInvitePath
	case LinkTypeRecovery:
		return appURL + a.LoginRedirectConfig.SetPasswordPath
	case LinkTypeMagicLink, LinkTypeSignup:
		return appURL + "/"
	default:
		return appURL + "/"
	}
}

func (a *Authentication) redirectToError(w http.ResponseWriter, r *http.Request, message string) {
	appURL := a.appUrl
	errorPath := a.LoginRedirectConfig.LoginErrorPath

	errorURL := fmt.Sprintf("%s%s?message=%s", appURL, errorPath, url.QueryEscape(message))
	http.Redirect(w, r, errorURL, http.StatusFound)
}

func (a *Authentication) redirectToMagicLogin(w http.ResponseWriter, r *http.Request, redirecrUrl string) {
	appURL := a.appUrl
	link := appURL + a.LoginRedirectConfig.ToeknLoginPath
	if redirecrUrl != "" {
		link += "?redirect=" + url.QueryEscape(redirecrUrl)
	}
	http.Redirect(w, r, link, http.StatusFound)
}
