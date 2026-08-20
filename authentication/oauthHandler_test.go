package authentication

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/blueyellowstudio/goose-base/identityManager"
)

func cookieByName(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestOAuthCodeChallenge_RFC7636Vector pins the S256 derivation to the worked example in
// RFC 7636 Appendix B. A wrong encoding here fails only at the provider, far from the bug.
func TestOAuthCodeChallenge_RFC7636Vector(t *testing.T) {
	const (
		verifier      = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		wantChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)

	if got := oauthCodeChallenge(verifier); got != wantChallenge {
		t.Fatalf("expected challenge %q, got %q", wantChallenge, got)
	}
}

func TestRandomURLSafeString_IsUnpaddedAndUnique(t *testing.T) {
	first, err := randomURLSafeString(oauthVerifierBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, err := randomURLSafeString(oauthVerifierBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if first == second {
		t.Fatal("expected two distinct random strings")
	}
	// 32 bytes of base64url without padding is 43 characters, inside RFC 7636's 43..128.
	if len(first) != 43 {
		t.Fatalf("expected a 43 character verifier, got %d (%q)", len(first), first)
	}
	for _, r := range first {
		if r == '=' || r == '+' || r == '/' {
			t.Fatalf("expected unpadded base64url, got %q", first)
		}
	}
}

func TestOAuthStartHandler_RedirectsWithPKCEChallenge(t *testing.T) {
	a := newTestAuthentication(&mockIdentityManager{}, &mockAuthTokenHandler{}, false)

	req := httptest.NewRequest(http.MethodGet, "/do-auth/oauth/google", nil)
	req.SetPathValue("provider", OAuthProviderGoogle)
	rr := httptest.NewRecorder()

	a.OAuthStartHandler(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, rr.Code)
	}

	location, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("failed to parse Location: %v", err)
	}
	if location.Host != "project.supabase.test" || location.Path != "/auth/v1/authorize" {
		t.Fatalf("expected the Supabase authorize endpoint, got %q", location.String())
	}

	query := location.Query()
	if query.Get("provider") != OAuthProviderGoogle {
		t.Fatalf("expected provider=google, got %q", query.Get("provider"))
	}
	if query.Get("code_challenge_method") != "s256" {
		t.Fatalf("expected code_challenge_method=s256, got %q", query.Get("code_challenge_method"))
	}

	cookies := rr.Result().Cookies()
	verifierCookie := cookieByName(cookies, oauthVerifierCookieName)
	stateCookie := cookieByName(cookies, oauthStateCookieName)
	if verifierCookie == nil || stateCookie == nil {
		t.Fatal("expected both the verifier and the state cookie to be set")
	}

	// The challenge in the URL must match the verifier that was handed to the browser.
	if got := oauthCodeChallenge(verifierCookie.Value); got != query.Get("code_challenge") {
		t.Fatalf("code_challenge %q does not match the verifier cookie (want %q)", query.Get("code_challenge"), got)
	}

	// The state has to ride along in redirect_to, since Supabase does not round-trip a
	// caller supplied state parameter.
	redirectTo, err := url.Parse(query.Get("redirect_to"))
	if err != nil {
		t.Fatalf("failed to parse redirect_to: %v", err)
	}
	if redirectTo.Query().Get("state") != stateCookie.Value {
		t.Fatalf("expected redirect_to to carry state %q, got %q", stateCookie.Value, redirectTo.Query().Get("state"))
	}

	for _, c := range []*http.Cookie{verifierCookie, stateCookie} {
		if !c.HttpOnly {
			t.Fatalf("cookie %q must be HttpOnly", c.Name)
		}
		if c.Path != defaultOAuthCookiePath {
			t.Fatalf("cookie %q: expected path %q, got %q", c.Name, defaultOAuthCookiePath, c.Path)
		}
		if c.MaxAge != oauthTempCookieMaxAge {
			t.Fatalf("cookie %q: expected MaxAge %d, got %d", c.Name, oauthTempCookieMaxAge, c.MaxAge)
		}
		if c.Secure {
			t.Fatalf("cookie %q must not be Secure outside production", c.Name)
		}
	}
}

// TestOAuthStartHandler_UsesLaxSameSiteInProduction guards the one place this package
// deliberately diverges from SetAuthCookie: Strict cookies are not sent on the
// cross-site top-level navigation back from the provider, so the callback would never
// see them.
func TestOAuthStartHandler_UsesLaxSameSiteInProduction(t *testing.T) {
	for _, isProduction := range []bool{false, true} {
		a := newTestAuthentication(&mockIdentityManager{}, &mockAuthTokenHandler{}, isProduction)

		req := httptest.NewRequest(http.MethodGet, "/do-auth/oauth/apple", nil)
		req.SetPathValue("provider", OAuthProviderApple)
		rr := httptest.NewRecorder()

		a.OAuthStartHandler(rr, req)

		cookies := rr.Result().Cookies()
		if len(cookies) != 2 {
			t.Fatalf("isProduction=%v: expected 2 cookies, got %d", isProduction, len(cookies))
		}
		for _, c := range cookies {
			if c.SameSite != http.SameSiteLaxMode {
				t.Fatalf("isProduction=%v: cookie %q must be SameSite=Lax, got %v", isProduction, c.Name, c.SameSite)
			}
			if c.Secure != isProduction {
				t.Fatalf("isProduction=%v: cookie %q Secure=%v", isProduction, c.Name, c.Secure)
			}
		}
	}
}

func TestOAuthStartHandler_RejectsUnknownProvider(t *testing.T) {
	a := newTestAuthentication(&mockIdentityManager{}, &mockAuthTokenHandler{}, false)

	req := httptest.NewRequest(http.MethodGet, "/do-auth/oauth/evil", nil)
	req.SetPathValue("provider", "https://attacker.example")
	rr := httptest.NewRecorder()

	a.OAuthStartHandler(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, rr.Code)
	}
	if location := rr.Header().Get("Location"); !strings.HasPrefix(location, "https://app.test/login-error") {
		t.Fatalf("expected a redirect to the login error page, got %q", location)
	}
	if len(rr.Result().Cookies()) != 0 {
		t.Fatal("expected no cookies for an unsupported provider")
	}
}

func TestOAuthCallbackHandler_StateMismatchSetsNoAuthCookie(t *testing.T) {
	exchanged := false
	idm := &mockIdentityManager{
		exchangeOAuthCode: func(ctx context.Context, code, verifier string) (*identityManager.AuthResponse, error) {
			exchanged = true
			return &identityManager.AuthResponse{AccessToken: "access", RefreshToken: "refresh"}, nil
		},
	}
	a := newTestAuthentication(idm, &mockAuthTokenHandler{}, false)

	req := httptest.NewRequest(http.MethodGet, "/do-auth/oauth/callback?code=auth-code&state=attacker-state", nil)
	req.AddCookie(&http.Cookie{Name: oauthStateCookieName, Value: "browser-state"})
	req.AddCookie(&http.Cookie{Name: oauthVerifierCookieName, Value: "verifier"})
	rr := httptest.NewRecorder()

	a.OAuthCallbackHandler(rr, req)

	if exchanged {
		t.Fatal("expected no code exchange when the state does not match")
	}
	if rr.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, rr.Code)
	}
	if location := rr.Header().Get("Location"); !strings.HasPrefix(location, "https://app.test/login-error") {
		t.Fatalf("expected a redirect to the login error page, got %q", location)
	}

	cookies := rr.Result().Cookies()
	if cookieByName(cookies, "token") != nil || cookieByName(cookies, "refresh") != nil {
		t.Fatal("expected no auth cookie on a state mismatch")
	}
	// The single-use PKCE cookies are dropped so the flow cannot be retried with them.
	for _, name := range []string{oauthStateCookieName, oauthVerifierCookieName} {
		c := cookieByName(cookies, name)
		if c == nil || c.MaxAge != -1 {
			t.Fatalf("expected cookie %q to be expired", name)
		}
	}
}

func TestOAuthCallbackHandler_MissingStateCookieIsRejected(t *testing.T) {
	a := newTestAuthentication(&mockIdentityManager{}, &mockAuthTokenHandler{}, false)

	req := httptest.NewRequest(http.MethodGet, "/do-auth/oauth/callback?code=auth-code&state=some-state", nil)
	rr := httptest.NewRecorder()

	a.OAuthCallbackHandler(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, rr.Code)
	}
	if cookieByName(rr.Result().Cookies(), "token") != nil {
		t.Fatal("expected no auth cookie without a state cookie")
	}
}

func TestOAuthCallbackHandler_ExchangeFailureRedirectsWithGenericMessage(t *testing.T) {
	idm := &mockIdentityManager{
		exchangeOAuthCode: func(ctx context.Context, code, verifier string) (*identityManager.AuthResponse, error) {
			return nil, errors.New("supabase exchange oauth code: user banned: alice@example.com")
		},
	}
	a := newTestAuthentication(idm, &mockAuthTokenHandler{}, false)

	req := httptest.NewRequest(http.MethodGet, "/do-auth/oauth/callback?code=auth-code&state=browser-state", nil)
	req.AddCookie(&http.Cookie{Name: oauthStateCookieName, Value: "browser-state"})
	req.AddCookie(&http.Cookie{Name: oauthVerifierCookieName, Value: "verifier"})
	rr := httptest.NewRecorder()

	a.OAuthCallbackHandler(rr, req)

	location := rr.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse Location: %v", err)
	}
	if parsed.Path != "/login-error" {
		t.Fatalf("expected a redirect to /login-error, got %q", location)
	}
	if got := parsed.Query().Get("message"); got != oauthFailedMessage {
		t.Fatalf("expected the generic message, got %q", got)
	}
	if cookieByName(rr.Result().Cookies(), "token") != nil {
		t.Fatal("expected no auth cookie after a failed exchange")
	}
}

func TestOAuthCallbackHandler_HappyPathSetsCookiesAndRedirectsToApp(t *testing.T) {
	var gotCode, gotVerifier string
	idm := &mockIdentityManager{
		exchangeOAuthCode: func(ctx context.Context, code, verifier string) (*identityManager.AuthResponse, error) {
			gotCode, gotVerifier = code, verifier
			return &identityManager.AuthResponse{AccessToken: "access-token", RefreshToken: "refresh-token"}, nil
		},
	}
	a := newTestAuthentication(idm, &mockAuthTokenHandler{}, false)

	req := httptest.NewRequest(http.MethodGet, "/do-auth/oauth/callback?code=auth-code&state=browser-state", nil)
	req.AddCookie(&http.Cookie{Name: oauthStateCookieName, Value: "browser-state"})
	req.AddCookie(&http.Cookie{Name: oauthVerifierCookieName, Value: "pkce-verifier"})
	rr := httptest.NewRecorder()

	a.OAuthCallbackHandler(rr, req)

	if gotCode != "auth-code" || gotVerifier != "pkce-verifier" {
		t.Fatalf("expected the code and verifier to be forwarded, got %q / %q", gotCode, gotVerifier)
	}
	if rr.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, rr.Code)
	}
	if got := rr.Header().Get("Location"); got != "https://app.test" {
		t.Fatalf("expected a redirect to the app URL, got %q", got)
	}

	cookies := rr.Result().Cookies()
	tokenCookie := cookieByName(cookies, "token")
	refreshCookie := cookieByName(cookies, "refresh")
	if tokenCookie == nil || tokenCookie.Value != "access-token" {
		t.Fatalf("expected the access token cookie, got %+v", tokenCookie)
	}
	if refreshCookie == nil || refreshCookie.Value != "refresh-token" {
		t.Fatalf("expected the refresh token cookie, got %+v", refreshCookie)
	}
	if !tokenCookie.HttpOnly {
		t.Fatal("the access token cookie must be HttpOnly")
	}

	for _, name := range []string{oauthStateCookieName, oauthVerifierCookieName} {
		c := cookieByName(cookies, name)
		if c == nil || c.MaxAge != -1 {
			t.Fatalf("expected the single-use cookie %q to be expired", name)
		}
	}
}
