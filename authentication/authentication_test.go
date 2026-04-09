package authentication

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blueyellowstudio/goose-base/authorization"
	"github.com/blueyellowstudio/goose-base/identityManager"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type mockIdentityManager struct {
	register                func(ctx context.Context, name, email, password string) (*identityManager.RegisterResponse, error)
	authenticate            func(ctx context.Context, email, password string) (*identityManager.AuthResponse, error)
	refreshToken            func(ctx context.Context, refreshToken string) (*identityManager.AuthResponse, error)
	verifyEmailOtp          func(ctx context.Context, email, token string, otpType identityManager.EmailOtpType) (*identityManager.AuthResponse, error)
	verifyTokenHash         func(ctx context.Context, tokenHash, linkType string) (*identityManager.AuthResponse, error)
	sendMagicLink           func(ctx context.Context, email string) error
	sendPasswordResetEmail  func(ctx context.Context, email string) error
	resendVerificationEmail func(ctx context.Context, email string) error
	sendInvite              func(ctx context.Context, email string, metadata map[string]interface{}) (uuid.UUID, error)
	createManagedUser       func(ctx context.Context, email, displayName string, companyUUID uuid.UUID, username *string) (*identityManager.AdminUserResponse, error)
	getUserEmail            func(ctx context.Context, userID uuid.UUID) (string, error)
	updateUserPassword      func(ctx context.Context, userID uuid.UUID, password string) error
	disableUser             func(ctx context.Context, userID uuid.UUID) error
	deleteUser              func(ctx context.Context, userID uuid.UUID) error
}

func (m *mockIdentityManager) Register(ctx context.Context, name, email, password string) (*identityManager.RegisterResponse, error) {
	if m.register != nil {
		return m.register(ctx, name, email, password)
	}
	return &identityManager.RegisterResponse{UserID: "u1"}, nil
}

func (m *mockIdentityManager) Authenticate(ctx context.Context, email, password string) (*identityManager.AuthResponse, error) {
	if m.authenticate != nil {
		return m.authenticate(ctx, email, password)
	}
	return &identityManager.AuthResponse{AccessToken: "access", RefreshToken: "refresh"}, nil
}

func (m *mockIdentityManager) RefreshToken(ctx context.Context, refreshToken string) (*identityManager.AuthResponse, error) {
	if m.refreshToken != nil {
		return m.refreshToken(ctx, refreshToken)
	}
	return &identityManager.AuthResponse{AccessToken: "access", RefreshToken: "refresh"}, nil
}

func (m *mockIdentityManager) VerifyEmailOtp(ctx context.Context, email, token string, otpType identityManager.EmailOtpType) (*identityManager.AuthResponse, error) {
	if m.verifyEmailOtp != nil {
		return m.verifyEmailOtp(ctx, email, token, otpType)
	}
	return &identityManager.AuthResponse{AccessToken: "access", RefreshToken: "refresh"}, nil
}

func (m *mockIdentityManager) VerifyTokenHash(ctx context.Context, tokenHash, linkType string) (*identityManager.AuthResponse, error) {
	if m.verifyTokenHash != nil {
		return m.verifyTokenHash(ctx, tokenHash, linkType)
	}
	return &identityManager.AuthResponse{AccessToken: "access", RefreshToken: "refresh"}, nil
}

func (m *mockIdentityManager) SendMagicLink(ctx context.Context, email string) error {
	if m.sendMagicLink != nil {
		return m.sendMagicLink(ctx, email)
	}
	return nil
}

func (m *mockIdentityManager) SendPasswordResetEmail(ctx context.Context, email string) error {
	if m.sendPasswordResetEmail != nil {
		return m.sendPasswordResetEmail(ctx, email)
	}
	return nil
}

func (m *mockIdentityManager) ResendVerificationEmail(ctx context.Context, email string) error {
	if m.resendVerificationEmail != nil {
		return m.resendVerificationEmail(ctx, email)
	}
	return nil
}

func (m *mockIdentityManager) SendInvite(ctx context.Context, email string, metadata map[string]interface{}) (uuid.UUID, error) {
	if m.sendInvite != nil {
		return m.sendInvite(ctx, email, metadata)
	}
	return uuid.New(), nil
}

func (m *mockIdentityManager) CreateManagedUser(ctx context.Context, email, displayName string, companyUUID uuid.UUID, username *string) (*identityManager.AdminUserResponse, error) {
	if m.createManagedUser != nil {
		return m.createManagedUser(ctx, email, displayName, companyUUID, username)
	}
	return &identityManager.AdminUserResponse{ID: uuid.NewString(), Email: email}, nil
}

func (m *mockIdentityManager) GetUserEmail(ctx context.Context, userID uuid.UUID) (string, error) {
	if m.getUserEmail != nil {
		return m.getUserEmail(ctx, userID)
	}
	return "user@example.com", nil
}

func (m *mockIdentityManager) UpdateUserPassword(ctx context.Context, userID uuid.UUID, password string) error {
	if m.updateUserPassword != nil {
		return m.updateUserPassword(ctx, userID, password)
	}
	return nil
}

func (m *mockIdentityManager) DisableUser(ctx context.Context, userID uuid.UUID) error {
	if m.disableUser != nil {
		return m.disableUser(ctx, userID)
	}
	return nil
}

func (m *mockIdentityManager) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	if m.deleteUser != nil {
		return m.deleteUser(ctx, userID)
	}
	return nil
}

type mockAuthTokenHandler struct {
	getIdentityFromContext func(ctx context.Context) (authorization.ContextIdentity, error)
}

func (m *mockAuthTokenHandler) CreateContext(ctx context.Context, claims jwt.MapClaims) (context.Context, error) {
	return ctx, nil
}

func (m *mockAuthTokenHandler) CreateDebugContext(ctx context.Context, userID uuid.UUID) (context.Context, error) {
	return ctx, nil
}

func (m *mockAuthTokenHandler) ValidateToken(claims jwt.MapClaims) error {
	return nil
}

func (m *mockAuthTokenHandler) GetIdentityFromContext(ctx context.Context) (authorization.ContextIdentity, error) {
	if m.getIdentityFromContext != nil {
		return m.getIdentityFromContext(ctx)
	}
	return authorization.ContextIdentity{}, errors.New("no identity")
}

func newTestAuthentication(idm identityManager.IdentityManager, tokenHandler authorization.TokenHandler, isProduction bool) *Authentication {
	loginRedirectConfig := LoginRedirectConfig{
		RedirectToTokenLoginAfterMagicLinkFailed: false,
		TokenLoginPath:                           "/token-login",
		LoginErrorPath:                           "/login-error",
		AcceptInvitePath:                         "/accept-invite",
		SetPasswordPath:                          "/set-password",
	}
	return NewAuthentication(idm, tokenHandler, "https://app.test", "token", "refresh", isProduction, loginRedirectConfig)
}

func TestSetAuthCookie_UsesLaxInDebugMode(t *testing.T) {
	a := newTestAuthentication(&mockIdentityManager{}, &mockAuthTokenHandler{}, false)
	rr := httptest.NewRecorder()

	a.setAuthCookie(rr, &identityManager.AuthResponse{AccessToken: "a", RefreshToken: "r"})

	res := rr.Result()
	cookies := res.Cookies()
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}
	for _, c := range cookies {
		if c.Secure {
			t.Fatal("expected non-secure cookies in non-production")
		}
		if c.SameSite != http.SameSiteLaxMode {
			t.Fatalf("expected SameSite Lax, got %v", c.SameSite)
		}
	}
}

func TestLoginHandler_MethodNotAllowed(t *testing.T) {
	a := newTestAuthentication(&mockIdentityManager{}, &mockAuthTokenHandler{}, true)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)

	a.LoginHandler(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestLoginHandler_SetsCookiesOnSuccess(t *testing.T) {
	idm := &mockIdentityManager{
		authenticate: func(ctx context.Context, email, password string) (*identityManager.AuthResponse, error) {
			if email != "user@example.com" || password != "Password1" {
				return nil, errors.New("unexpected credentials")
			}
			return &identityManager.AuthResponse{AccessToken: "a-token", RefreshToken: "r-token"}, nil
		},
	}
	a := newTestAuthentication(idm, &mockAuthTokenHandler{}, true)

	body := bytes.NewBufferString(`{"email":"user@example.com","password":"Password1"}`)
	req := httptest.NewRequest(http.MethodPost, "/login", body)
	rr := httptest.NewRecorder()

	a.LoginHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	if len(rr.Result().Cookies()) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(rr.Result().Cookies()))
	}
	if !strings.Contains(rr.Body.String(), `"success":true`) {
		t.Fatalf("expected success response body, got %s", rr.Body.String())
	}
}

func TestRefreshAuthHandler_UsesCookieFallback(t *testing.T) {
	usedToken := ""
	idm := &mockIdentityManager{
		refreshToken: func(ctx context.Context, refreshToken string) (*identityManager.AuthResponse, error) {
			usedToken = refreshToken
			return &identityManager.AuthResponse{AccessToken: "new-access", RefreshToken: "new-refresh"}, nil
		},
	}
	a := newTestAuthentication(idm, &mockAuthTokenHandler{}, false)

	req := httptest.NewRequest(http.MethodPost, "/refresh", bytes.NewBufferString(`{}`))
	req.AddCookie(&http.Cookie{Name: "refresh", Value: "cookie-refresh"})
	rr := httptest.NewRecorder()

	a.RefreshAuthHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	if usedToken != "cookie-refresh" {
		t.Fatalf("expected refresh token from cookie, got %q", usedToken)
	}
}

func TestVerifyEmailHandler_RequiresEmailAndToken(t *testing.T) {
	a := newTestAuthentication(&mockIdentityManager{}, &mockAuthTokenHandler{}, false)
	req := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewBufferString(`{"email":""}`))
	rr := httptest.NewRecorder()

	a.GetVerifyTokenHandler(identityManager.EmailOtpTypeSignup)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestAuthLinkHandler_InvalidTypeRedirectsToError(t *testing.T) {
	a := newTestAuthentication(&mockIdentityManager{}, &mockAuthTokenHandler{}, false)
	req := httptest.NewRequest(http.MethodGet, "/auth-link?token=abc&type=invalid", nil)
	rr := httptest.NewRecorder()

	a.AuthLinkHandler(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, rr.Code)
	}
	location := rr.Header().Get("Location")
	if !strings.Contains(location, "/login-error?") {
		t.Fatalf("expected redirect to auth-error, got %q", location)
	}
}

func TestResetPasswordHandler_UnauthorizedWithoutIdentity(t *testing.T) {
	a := newTestAuthentication(&mockIdentityManager{}, &mockAuthTokenHandler{}, false)
	req := httptest.NewRequest(http.MethodPost, "/reset-password", bytes.NewBufferString(`{"password":"StrongPass1"}`))
	rr := httptest.NewRecorder()

	a.ResetPasswordHandler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestChangePasswordHandler_RejectsWeakPassword(t *testing.T) {
	th := &mockAuthTokenHandler{
		getIdentityFromContext: func(ctx context.Context) (authorization.ContextIdentity, error) {
			return authorization.ContextIdentity{UserID: uuid.New(), UserEmail: "u@example.com"}, nil
		},
	}
	a := newTestAuthentication(&mockIdentityManager{}, th, false)

	payload := map[string]string{"currentPassword": "CurrentPass1", "newPassword": "weak"}
	b, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/change-password", bytes.NewBuffer(b))
	rr := httptest.NewRecorder()

	a.ChangePasswordHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}
