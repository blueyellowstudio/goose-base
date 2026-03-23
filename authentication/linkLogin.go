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

	tokenResp, err := a.identities.VerifyTokenHash(r.Context(), token, linkType)
	if err != nil {
		slog.Error("Failed to verify auth link token", "error", err, "type", linkType)
		a.redirectToError(w, r, "Invalid or expired link")
		return
	}

	a.setAuthCookie(w, tokenResp)

	redirectURL := a.getRedirectURLForLinkType(linkType)
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
		return appURL + "/accept-invite"
	case LinkTypeRecovery:
		return appURL + "/set-password"
	case LinkTypeMagicLink, LinkTypeSignup:
		return appURL + "/"
	default:
		return appURL + "/"
	}
}

func (a *Authentication) redirectToError(w http.ResponseWriter, r *http.Request, message string) {
	appURL := a.appUrl

	errorURL := fmt.Sprintf("%s/auth-error?message=%s", appURL, url.QueryEscape(message))
	http.Redirect(w, r, errorURL, http.StatusFound)
}
