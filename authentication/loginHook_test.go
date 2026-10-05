package authentication

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blueyellowstudio/goose-base/identityManager"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const hookMarkerCookieName = "hook_marker"

// loginHookRecorder installs a login hook that records every call and adds a marker
// cookie, so a test sees both that the hook ran and that its cookie reached the response.
type loginHookRecorder struct {
	userIds []uuid.UUID
}

func recordLoginHook(a *Authentication) *loginHookRecorder {
	recorder := &loginHookRecorder{}
	a.SetOnLogin(func(w http.ResponseWriter, _ *http.Request, userId uuid.UUID) {
		recorder.userIds = append(recorder.userIds, userId)
		http.SetCookie(w, &http.Cookie{Name: hookMarkerCookieName, Value: userId.String()})
	})
	return recorder
}

// sessionFor is what the identity provider answers a login with: a JWT naming the user.
func sessionFor(t *testing.T, userId uuid.UUID) *identityManager.AuthResponse {
	t.Helper()
	return &identityManager.AuthResponse{
		AccessToken:  signedTestToken(t, jwt.MapClaims{"sub": userId.String()}),
		RefreshToken: "refresh-token",
	}
}

func assertHookRanOnceFor(t *testing.T, recorder *loginHookRecorder, rr *httptest.ResponseRecorder, want uuid.UUID) {
	t.Helper()
	if len(recorder.userIds) != 1 || recorder.userIds[0] != want {
		t.Fatalf("hook calls = %v, want exactly [%s]", recorder.userIds, want)
	}
	marker := cookieByName(rr.Result().Cookies(), hookMarkerCookieName)
	if marker == nil || marker.Value != want.String() {
		t.Fatalf("the hook's cookie did not reach the response, got %+v", marker)
	}
}

func assertHookDidNotRun(t *testing.T, recorder *loginHookRecorder) {
	t.Helper()
	if len(recorder.userIds) != 0 {
		t.Fatalf("hook ran for %v, want no call", recorder.userIds)
	}
}

func postJSON(path, body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
}

func TestLoginHandler_RunsLoginHookWithUserId(t *testing.T) {
	userId := uuid.New()
	a := newTestAuthentication(&mockIdentityManager{
		authenticate: func(context.Context, string, string) (*identityManager.AuthResponse, error) {
			return sessionFor(t, userId), nil
		},
	}, &mockAuthTokenHandler{}, true)
	recorder := recordLoginHook(a)
	rr := httptest.NewRecorder()

	a.LoginHandler(rr, postJSON("/login", `{"email":"user@example.com","password":"Password1"}`))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	assertHookRanOnceFor(t, recorder, rr, userId)
}

func TestVerifyTokenHandler_RunsLoginHook(t *testing.T) {
	userId := uuid.New()
	a := newTestAuthentication(&mockIdentityManager{
		verifyEmailOtp: func(context.Context, string, string, identityManager.EmailOtpType) (*identityManager.AuthResponse, error) {
			return sessionFor(t, userId), nil
		},
	}, &mockAuthTokenHandler{}, true)
	recorder := recordLoginHook(a)
	rr := httptest.NewRecorder()

	a.GetVerifyTokenHandler(identityManager.EmailOtpTypeEmail)(rr, postJSON("/verify", `{"email":"user@example.com","token":"123456"}`))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	assertHookRanOnceFor(t, recorder, rr, userId)
}

func TestAuthLinkHandler_RunsLoginHook(t *testing.T) {
	userId := uuid.New()
	a := newTestAuthentication(&mockIdentityManager{
		verifyTokenHash: func(context.Context, string, string) (*identityManager.AuthResponse, error) {
			return sessionFor(t, userId), nil
		},
	}, &mockAuthTokenHandler{}, false)
	recorder := recordLoginHook(a)
	rr := httptest.NewRecorder()

	a.AuthLinkHandler(rr, httptest.NewRequest(http.MethodGet, "/auth-link?token=abc&type="+LinkTypeMagicLink, nil))

	if rr.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, rr.Code)
	}
	assertHookRanOnceFor(t, recorder, rr, userId)
}

func TestOAuthCallbackHandler_RunsLoginHook(t *testing.T) {
	userId := uuid.New()
	a := newTestAuthentication(&mockIdentityManager{
		exchangeOAuthCode: func(context.Context, string, string) (*identityManager.AuthResponse, error) {
			return sessionFor(t, userId), nil
		},
	}, &mockAuthTokenHandler{}, false)
	recorder := recordLoginHook(a)
	req := httptest.NewRequest(http.MethodGet, "/do-auth/oauth/callback?code=auth-code&state=browser-state", nil)
	req.AddCookie(&http.Cookie{Name: oauthStateCookieName, Value: "browser-state"})
	req.AddCookie(&http.Cookie{Name: oauthVerifierCookieName, Value: "pkce-verifier"})
	rr := httptest.NewRecorder()

	a.OAuthCallbackHandler(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, rr.Code)
	}
	assertHookRanOnceFor(t, recorder, rr, userId)
}

// A refresh renews an existing session; running the hook there would let it overwrite
// whatever the service stored at login on every token renewal.
func TestRefreshAuthHandler_DoesNotRunLoginHook(t *testing.T) {
	a := newTestAuthentication(&mockIdentityManager{
		refreshToken: func(context.Context, string) (*identityManager.AuthResponse, error) {
			return sessionFor(t, uuid.New()), nil
		},
	}, &mockAuthTokenHandler{}, true)
	recorder := recordLoginHook(a)
	rr := httptest.NewRecorder()

	a.RefreshAuthHandler(rr, postJSON("/refresh", `{"refresh_token":"old-refresh"}`))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	assertHookDidNotRun(t, recorder)
}

func TestLoginHandler_FailedLoginDoesNotRunLoginHook(t *testing.T) {
	a := newTestAuthentication(&mockIdentityManager{
		authenticate: func(context.Context, string, string) (*identityManager.AuthResponse, error) {
			return nil, errors.New("invalid credentials")
		},
	}, &mockAuthTokenHandler{}, true)
	recorder := recordLoginHook(a)
	rr := httptest.NewRecorder()

	a.LoginHandler(rr, postJSON("/login", `{"email":"user@example.com","password":"wrong"}`))

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
	assertHookDidNotRun(t, recorder)
}

// The hook cannot fail a login: a token the hook cannot read only skips the hook.
func TestLoginHandler_TokenWithoutUserIdSkipsHookButKeepsLogin(t *testing.T) {
	a := newTestAuthentication(&mockIdentityManager{}, &mockAuthTokenHandler{}, true) // answers "access", not a JWT
	recorder := recordLoginHook(a)
	rr := httptest.NewRecorder()

	a.LoginHandler(rr, postJSON("/login", `{"email":"user@example.com","password":"Password1"}`))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	if got := len(rr.Result().Cookies()); got != 2 {
		t.Fatalf("expected the 2 session cookies, got %d", got)
	}
	assertHookDidNotRun(t, recorder)
}
