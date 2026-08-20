package authentication

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// Supported OAuth providers. The provider segment of the start route is attacker
// controlled, and it is interpolated into the Supabase authorize URL — without this
// allow-list the endpoint would forward arbitrary strings to Supabase and act as an
// open redirect.
const (
	OAuthProviderGoogle = "google"
	OAuthProviderApple  = "apple"
)

var allowedOAuthProviders = map[string]struct{}{
	OAuthProviderGoogle: {},
	OAuthProviderApple:  {},
}

const (
	// defaultOAuthCookiePath scopes the temporary PKCE cookies to the OAuth routes so
	// they are not attached to every other request. Override via OAuthConfig.CookiePath
	// when the handlers are mounted somewhere else.
	defaultOAuthCookiePath = "/do-auth/oauth"

	oauthStateCookieName    = "oauthState"
	oauthVerifierCookieName = "oauthVerifier"

	// oauthTempCookieMaxAge bounds the time an unfinished authorization can be resumed.
	oauthTempCookieMaxAge = 600 // 10 minutes

	// oauthVerifierBytes is the raw entropy behind the PKCE verifier. 32 bytes encode to
	// 43 base64url characters, inside RFC 7636's 43..128 range.
	oauthVerifierBytes = 32
	oauthStateBytes    = 32
)

// oauthFailedMessage is the only thing a failed OAuth round trip ever tells the browser.
// The provider's own error body can name accounts and internal reasons, so it stays in
// the server log.
const oauthFailedMessage = "Sign in failed, please try again"

// OAuthConfig carries the two absolute URLs the OAuth flow needs. Both are supplied by
// the caller — the library never reads the environment itself.
type OAuthConfig struct {
	// SupabaseURL is the Supabase project URL, e.g. https://xyz.supabase.co.
	SupabaseURL string
	// CallbackURL is the absolute URL of OAuthCallbackHandler, e.g.
	// https://api.example.com/do-auth/oauth/callback. It must also be on the Supabase
	// dashboard's redirect allow-list or Supabase refuses the flow.
	CallbackURL string
	// CookiePath scopes the temporary state/verifier cookies. Defaults to
	// "/do-auth/oauth"; it must be a prefix of the callback path or the cookies are not
	// sent back.
	CookiePath string
}

// OAuthStartHandler begins a server-side PKCE authorization.
//
// The provider comes from the route as {provider}. It is read with r.PathValue, which
// both net/http's ServeMux and chi (v5.1+, which copies its URL params into the request)
// populate — that keeps this package free of a router dependency.
//
// Mount as: r.Get("/do-auth/oauth/{provider}", auth.OAuthStartHandler)
func (a *Authentication) OAuthStartHandler(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if _, ok := allowedOAuthProviders[provider]; !ok {
		slog.Error("OAuth start rejected: unsupported provider", "path", r.URL.Path, "provider", provider)
		a.redirectToError(w, r, oauthFailedMessage)
		return
	}

	if a.oauth.SupabaseURL == "" || a.oauth.CallbackURL == "" {
		slog.Error("OAuth start rejected: OAuthConfig is incomplete", "path", r.URL.Path, "provider", provider)
		a.redirectToError(w, r, oauthFailedMessage)
		return
	}

	verifier, err := randomURLSafeString(oauthVerifierBytes)
	if err != nil {
		slog.Error("OAuth start failed: could not generate PKCE verifier", "path", r.URL.Path, "err", err)
		a.redirectToError(w, r, oauthFailedMessage)
		return
	}

	state, err := randomURLSafeString(oauthStateBytes)
	if err != nil {
		slog.Error("OAuth start failed: could not generate state", "path", r.URL.Path, "err", err)
		a.redirectToError(w, r, oauthFailedMessage)
		return
	}

	// Supabase's /auth/v1/authorize does not round-trip a caller supplied state
	// parameter — it mints its own for the handshake with the provider. Carrying ours in
	// the redirect_to query is what survives the trip, because Supabase appends ?code= to
	// that URL rather than replacing it.
	redirectTo, err := withQueryParam(a.oauth.CallbackURL, "state", state)
	if err != nil {
		slog.Error("OAuth start failed: invalid callback URL", "path", r.URL.Path, "err", err)
		a.redirectToError(w, r, oauthFailedMessage)
		return
	}

	a.setOAuthTempCookie(w, oauthVerifierCookieName, verifier)
	a.setOAuthTempCookie(w, oauthStateCookieName, state)

	query := url.Values{}
	query.Set("provider", provider)
	query.Set("redirect_to", redirectTo)
	query.Set("code_challenge", oauthCodeChallenge(verifier))
	query.Set("code_challenge_method", "s256")

	authorizeURL := strings.TrimSuffix(a.oauth.SupabaseURL, "/") + "/auth/v1/authorize?" + query.Encode()
	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

// OAuthCallbackHandler completes the PKCE flow: it validates the state, exchanges the
// authorization code for a session through the identity manager, and hands the browser
// nothing but cookies. No token ever reaches the URL or a script.
//
// Mount as: r.Get("/do-auth/oauth/callback", auth.OAuthCallbackHandler)
func (a *Authentication) OAuthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	// The provider reports its own failures as ?error=. Log it, show the generic message.
	if providerError := r.URL.Query().Get("error"); providerError != "" {
		slog.Error("OAuth callback: provider reported an error", "path", r.URL.Path,
			"providerError", providerError, "description", r.URL.Query().Get("error_description"))
		a.failOAuthCallback(w, r)
		return
	}

	stateCookie, err := r.Cookie(oauthStateCookieName)
	if err != nil || stateCookie.Value == "" {
		slog.Error("OAuth callback rejected: state cookie missing", "path", r.URL.Path, "err", err)
		a.failOAuthCallback(w, r)
		return
	}

	state := r.URL.Query().Get("state")
	if subtle.ConstantTimeCompare([]byte(state), []byte(stateCookie.Value)) != 1 {
		slog.Error("OAuth callback rejected: state mismatch", "path", r.URL.Path)
		a.failOAuthCallback(w, r)
		return
	}

	verifierCookie, err := r.Cookie(oauthVerifierCookieName)
	if err != nil || verifierCookie.Value == "" {
		slog.Error("OAuth callback rejected: PKCE verifier cookie missing", "path", r.URL.Path, "err", err)
		a.failOAuthCallback(w, r)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		slog.Error("OAuth callback rejected: no authorization code", "path", r.URL.Path)
		a.failOAuthCallback(w, r)
		return
	}

	authResponse, err := a.identities.ExchangeOAuthCode(r.Context(), code, verifierCookie.Value)
	if err != nil {
		slog.Error("OAuth callback failed: code exchange rejected", "path", r.URL.Path, "err", err)
		a.failOAuthCallback(w, r)
		return
	}

	a.clearOAuthTempCookies(w)
	a.SetAuthCookie(w, authResponse)
	http.Redirect(w, r, a.appUrl, http.StatusFound)
}

// failOAuthCallback drops the single-use PKCE cookies and sends the browser to the
// frontend's error screen. It never writes an auth cookie.
func (a *Authentication) failOAuthCallback(w http.ResponseWriter, r *http.Request) {
	a.clearOAuthTempCookies(w)
	a.redirectToError(w, r, oauthFailedMessage)
}

// oauthCodeChallenge derives the RFC 7636 S256 challenge: base64url(sha256(verifier)),
// unpadded, hashed over the ASCII verifier string rather than its decoded bytes.
func oauthCodeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// randomURLSafeString returns numBytes of crypto/rand entropy as unpadded base64url.
func randomURLSafeString(numBytes int) (string, error) {
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// withQueryParam returns rawURL with key=value set on its query string.
func withQueryParam(rawURL, key, value string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set(key, value)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func (a *Authentication) oauthCookiePath() string {
	if a.oauth.CookiePath != "" {
		return a.oauth.CookiePath
	}
	return defaultOAuthCookiePath
}

// setOAuthTempCookie writes one of the short-lived PKCE cookies.
//
// SameSite is deliberately Lax in BOTH environments, unlike SetAuthCookie which uses
// Strict in production. The callback is a cross-site top-level navigation — the browser
// arrives at it from the provider's domain — and Strict cookies are not sent on those.
// A Strict state/verifier cookie would simply be absent at the callback and every login
// would fail the state check. Lax still covers the flow: it permits exactly this
// top-level GET and nothing else, and the cookies are single use, path scoped and expire
// in ten minutes.
func (a *Authentication) setOAuthTempCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     a.oauthCookiePath(),
		MaxAge:   oauthTempCookieMaxAge,
		HttpOnly: true,
		Secure:   a.isProduction,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearOAuthTempCookies expires the PKCE cookies. Attributes must match the ones used to
// set them or the browser keeps the originals.
func (a *Authentication) clearOAuthTempCookies(w http.ResponseWriter) {
	for _, name := range []string{oauthStateCookieName, oauthVerifierCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     a.oauthCookiePath(),
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   a.isProduction,
			SameSite: http.SameSiteLaxMode,
		})
	}
}
