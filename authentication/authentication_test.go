package authentication

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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
	exchangeOAuthCode       func(ctx context.Context, code, verifier string) (*identityManager.AuthResponse, error)
	sendMagicLink           func(ctx context.Context, email string) error
	sendPasswordResetEmail  func(ctx context.Context, email string) error
	resendVerificationEmail func(ctx context.Context, email string) error
	sendInvite              func(ctx context.Context, email string, metadata map[string]interface{}) (uuid.UUID, error)
	createManagedUser       func(ctx context.Context, email, displayName string, companyUUID uuid.UUID, username *string) (*identityManager.AdminUserResponse, error)
	getUserEmail            func(ctx context.Context, userID uuid.UUID) (string, error)
	getUserIdByEmail        func(ctx context.Context, email string) (uuid.UUID, error)
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

func (m *mockIdentityManager) ExchangeOAuthCode(ctx context.Context, code, verifier string) (*identityManager.AuthResponse, error) {
	if m.exchangeOAuthCode != nil {
		return m.exchangeOAuthCode(ctx, code, verifier)
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

func (m *mockIdentityManager) GetUserIdByEmail(ctx context.Context, email string) (uuid.UUID, error) {
	if m.getUserIdByEmail != nil {
		return m.getUserIdByEmail(ctx, email)
	}
	return uuid.Nil, identityManager.ErrUserNotFound
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
	createContext          func(ctx context.Context, claims jwt.MapClaims) (context.Context, error)
	getIdentityFromContext func(ctx context.Context) (authorization.ContextIdentity, error)
}

func (m *mockAuthTokenHandler) CreateContext(ctx context.Context, claims jwt.MapClaims) (context.Context, error) {
	if m.createContext != nil {
		return m.createContext(ctx, claims)
	}
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

const testJWTSecret = "test-secret"

func newTestAuthentication(idm identityManager.IdentityManager, tokenHandler authorization.TokenHandler, isProduction bool) *Authentication {
	loginRedirectConfig := LoginRedirectConfig{
		RedirectToTokenLoginAfterMagicLinkFailed: false,
		TokenLoginPath:                           "/token-login",
		LoginErrorPath:                           "/login-error",
		AcceptInvitePath:                         "/accept-invite",
		SetPasswordPath:                          "/set-password",
	}
	authorizer := authorization.NewAuthorization("token", testJWTSecret, tokenHandler, isProduction)
	oauthConfig := OAuthConfig{
		SupabaseURL: "https://project.supabase.test",
		CallbackURL: "https://api.test/do-auth/oauth/callback",
	}
	return NewAuthentication(idm, tokenHandler, authorizer, "https://app.test", "token", "refresh", isProduction, loginRedirectConfig, oauthConfig)
}

func signedTestToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return tokenString
}

func TestSetAuthCookie_UsesLaxInDebugMode(t *testing.T) {
	a := newTestAuthentication(&mockIdentityManager{}, &mockAuthTokenHandler{}, false)
	rr := httptest.NewRecorder()

	a.SetAuthCookie(rr, &identityManager.AuthResponse{AccessToken: "a", RefreshToken: "r"})

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

// postRegister runs RegisterHandler over the given JSON body and returns the recorder.
func postRegister(t *testing.T, a *Authentication, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	a.RegisterHandler(rr, req)
	return rr
}

func TestRegisterHandler_RejectsWeakPassword(t *testing.T) {
	called := 0
	idm := &mockIdentityManager{
		register: func(ctx context.Context, name, email, password string) (*identityManager.RegisterResponse, error) {
			called++
			return &identityManager.RegisterResponse{UserID: uuid.NewString()}, nil
		},
	}
	a := newTestAuthentication(idm, &mockAuthTokenHandler{}, true)

	rr := postRegister(t, a, `{"username":"user","email":"user@example.com","password":"weak"}`)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
	if called != 0 {
		t.Fatalf("expected Register not to be called for invalid input, got %d calls", called)
	}
	// The response must not name the rule that failed.
	if body := strings.ToLower(rr.Body.String()); strings.Contains(body, "password") && (strings.Contains(body, "short") || strings.Contains(body, "upper") || strings.Contains(body, "digit")) {
		t.Fatalf("expected a generic rejection message, got %q", rr.Body.String())
	}
}

func TestRegisterHandler_RejectsInvalidEmail(t *testing.T) {
	a := newTestAuthentication(&mockIdentityManager{}, &mockAuthTokenHandler{}, true)

	rr := postRegister(t, a, `{"username":"user","email":"not-an-email","password":"StrongPass1"}`)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestRegisterHandler_CreatesUserWithoutSettingCookie(t *testing.T) {
	called := 0
	var gotName, gotEmail, gotPassword string
	idm := &mockIdentityManager{
		register: func(ctx context.Context, name, email, password string) (*identityManager.RegisterResponse, error) {
			called++
			gotName, gotEmail, gotPassword = name, email, password
			return &identityManager.RegisterResponse{UserID: "11111111-1111-1111-1111-111111111111"}, nil
		},
	}
	a := newTestAuthentication(idm, &mockAuthTokenHandler{}, true)

	rr := postRegister(t, a, `{"username":"user","email":"user@example.com","password":"StrongPass1"}`)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, rr.Code)
	}
	if called != 1 {
		t.Fatalf("expected Register to be called once, got %d", called)
	}
	if gotName != "user" || gotEmail != "user@example.com" || gotPassword != "StrongPass1" {
		t.Fatalf("unexpected Register arguments: name=%q email=%q password=%q", gotName, gotEmail, gotPassword)
	}
	if !strings.Contains(rr.Body.String(), `"success":true`) {
		t.Fatalf("expected success response body, got %s", rr.Body.String())
	}

	// Supabase returns no session for an unconfirmed signup, so this handler has
	// nothing to store — the cookie is set later by the OTP verification handler.
	if cookies := rr.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("expected no cookies to be set, got %d", len(cookies))
	}
	if setCookie := rr.Header().Values("Set-Cookie"); len(setCookie) != 0 {
		t.Fatalf("expected no Set-Cookie header, got %v", setCookie)
	}
}

func TestRegisterHandler_DuplicateEmailIsIndistinguishableFromSuccess(t *testing.T) {
	const validBody = `{"username":"user","email":"taken@example.com","password":"StrongPass1"}`

	// Supabase's own duplicate-signup responses: 200 with an empty "identities"
	// array when email confirmation is on, 422 "User already registered" when off.
	duplicateErrors := map[string]error{
		"confirmation enabled":  errors.New("supabase signup: no identity returned"),
		"confirmation disabled": errors.New("supabase signup: User already registered"),
	}

	fresh := newTestAuthentication(&mockIdentityManager{
		register: func(ctx context.Context, name, email, password string) (*identityManager.RegisterResponse, error) {
			return &identityManager.RegisterResponse{UserID: "11111111-1111-1111-1111-111111111111"}, nil
		},
	}, &mockAuthTokenHandler{}, true)
	freshResponse := postRegister(t, fresh, validBody)

	for name, duplicateErr := range duplicateErrors {
		t.Run(name, func(t *testing.T) {
			called := 0
			a := newTestAuthentication(&mockIdentityManager{
				register: func(ctx context.Context, name, email, password string) (*identityManager.RegisterResponse, error) {
					called++
					return nil, duplicateErr
				},
			}, &mockAuthTokenHandler{}, true)

			rr := postRegister(t, a, validBody)

			if called != 1 {
				t.Fatalf("expected Register to be called once, got %d", called)
			}
			if rr.Code != freshResponse.Code {
				t.Fatalf("expected the same status as a fresh signup (%d), got %d", freshResponse.Code, rr.Code)
			}
			// Byte-identical bodies are the point: anything that differs lets an
			// anonymous caller enumerate which addresses are registered.
			if rr.Body.String() != freshResponse.Body.String() {
				t.Fatalf("expected the same body as a fresh signup %q, got %q", freshResponse.Body.String(), rr.Body.String())
			}
			if cookies := rr.Result().Cookies(); len(cookies) != 0 {
				t.Fatalf("expected no cookies to be set, got %d", len(cookies))
			}
		})
	}
}

func TestRegisterHandler_IdentityManagerFailureIsNotReportedAsSuccess(t *testing.T) {
	a := newTestAuthentication(&mockIdentityManager{
		register: func(ctx context.Context, name, email, password string) (*identityManager.RegisterResponse, error) {
			return nil, errors.New("supabase signup: status 503: service unavailable")
		},
	}, &mockAuthTokenHandler{}, true)

	rr := postRegister(t, a, `{"username":"user","email":"user@example.com","password":"StrongPass1"}`)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestRegisterHandler_MethodNotAllowed(t *testing.T) {
	a := newTestAuthentication(&mockIdentityManager{}, &mockAuthTokenHandler{}, true)
	req := httptest.NewRequest(http.MethodGet, "/register", nil)
	rr := httptest.NewRecorder()

	a.RegisterHandler(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

type sessionIdentityKey struct{}

// newSessionTokenHandler carries the identity through the context the same way a
// real TokenHandler does: CreateContext stores what the claims say, and
// GetIdentityFromContext reads it back.
func newSessionTokenHandler(identity authorization.ContextIdentity) *mockAuthTokenHandler {
	return &mockAuthTokenHandler{
		createContext: func(ctx context.Context, claims jwt.MapClaims) (context.Context, error) {
			return context.WithValue(ctx, sessionIdentityKey{}, identity), nil
		},
		getIdentityFromContext: func(ctx context.Context) (authorization.ContextIdentity, error) {
			stored, ok := ctx.Value(sessionIdentityKey{}).(authorization.ContextIdentity)
			if !ok {
				return authorization.ContextIdentity{}, errors.New("no identity")
			}
			return stored, nil
		},
	}
}

// recordingLogHandler captures every emitted log record so a test can assert that a
// normal anonymous request produces no slog.Error.
type recordingLogHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingLogHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingLogHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *recordingLogHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *recordingLogHandler) WithGroup(string) slog.Handler { return h }

func (h *recordingLogHandler) errorRecords() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	var errs []slog.Record
	for _, r := range h.records {
		if r.Level >= slog.LevelError {
			errs = append(errs, r)
		}
	}
	return errs
}

func captureLogs(t *testing.T) *recordingLogHandler {
	t.Helper()
	previous := slog.Default()
	handler := &recordingLogHandler{}
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return handler
}

func decodeSessionResponse(t *testing.T, rr *httptest.ResponseRecorder) SessionResponse {
	t.Helper()
	var got SessionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("failed to decode session response %q: %v", rr.Body.String(), err)
	}
	return got
}

func TestSessionHandler_WithoutCookieReportsAnonymous(t *testing.T) {
	logs := captureLogs(t)
	a := newTestAuthentication(&mockIdentityManager{}, &mockAuthTokenHandler{}, true)

	req := httptest.NewRequest(http.MethodGet, "/session", nil)
	rr := httptest.NewRecorder()

	a.SessionHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	got := decodeSessionResponse(t, rr)
	if got.Authenticated {
		t.Fatal("expected authenticated:false without a cookie")
	}
	if got.UserID != "" || got.Email != "" || got.Username != "" || got.Role != "" {
		t.Fatalf("expected no identity fields, got %+v", got)
	}
	if body := rr.Body.String(); !strings.Contains(body, `"authenticated":false`) {
		t.Fatalf("expected authenticated:false in body, got %s", body)
	}
	if cacheControl := rr.Header().Get("Cache-Control"); cacheControl != "no-store" {
		t.Fatalf("expected Cache-Control no-store, got %q", cacheControl)
	}
	if errs := logs.errorRecords(); len(errs) != 0 {
		t.Fatalf("expected no error logs for an anonymous request, got %d (first: %q)", len(errs), errs[0].Message)
	}
}

func TestSessionHandler_WithValidCookieEchoesClaims(t *testing.T) {
	userID := uuid.New()
	identity := authorization.ContextIdentity{
		UserID:    userID,
		UserEmail: "user@example.com",
		Username:  "user",
		Role:      "admin",
	}
	a := newTestAuthentication(&mockIdentityManager{}, newSessionTokenHandler(identity), true)

	token := signedTestToken(t, jwt.MapClaims{
		"sub": userID.String(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	req := httptest.NewRequest(http.MethodGet, "/session", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: token})
	rr := httptest.NewRecorder()

	a.SessionHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	got := decodeSessionResponse(t, rr)
	want := SessionResponse{
		Authenticated: true,
		UserID:        userID.String(),
		Email:         "user@example.com",
		Username:      "user",
		Role:          "admin",
	}
	if got != want {
		t.Fatalf("expected %+v, got %+v", want, got)
	}
}

func TestSessionHandler_WithExpiredTokenReportsAnonymous(t *testing.T) {
	logs := captureLogs(t)
	identity := authorization.ContextIdentity{
		UserID:    uuid.New(),
		UserEmail: "user@example.com",
		Username:  "user",
		Role:      "admin",
	}
	a := newTestAuthentication(&mockIdentityManager{}, newSessionTokenHandler(identity), true)

	token := signedTestToken(t, jwt.MapClaims{
		"sub": identity.UserID.String(),
		"exp": time.Now().Add(-time.Hour).Unix(),
	})
	req := httptest.NewRequest(http.MethodGet, "/session", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: token})
	rr := httptest.NewRecorder()

	a.SessionHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	got := decodeSessionResponse(t, rr)
	if got.Authenticated {
		t.Fatal("expected authenticated:false for an expired token")
	}
	if errs := logs.errorRecords(); len(errs) != 0 {
		t.Fatalf("expected no error logs for an expired token, got %d (first: %q)", len(errs), errs[0].Message)
	}
}

func TestSessionHandler_WithoutAuthorizerReportsAnonymous(t *testing.T) {
	a := NewAuthentication(&mockIdentityManager{}, &mockAuthTokenHandler{}, nil, "https://app.test", "token", "refresh", true, LoginRedirectConfig{}, OAuthConfig{})

	req := httptest.NewRequest(http.MethodGet, "/session", nil)
	rr := httptest.NewRecorder()

	a.SessionHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	if got := decodeSessionResponse(t, rr); got.Authenticated {
		t.Fatal("expected authenticated:false without an authorizer")
	}
}

// TestCookieMethods_SetAndClearAgreeOnAttributes guards the reason both methods are
// exported as a pair: a browser only drops a cookie when the expiring Set-Cookie
// carries the same name, path and flags as the one that created it. A mismatch leaves
// a session cookie that logout cannot delete.
func TestCookieMethods_SetAndClearAgreeOnAttributes(t *testing.T) {
	for _, isProduction := range []bool{true, false} {
		t.Run(map[bool]string{true: "production", false: "debug"}[isProduction], func(t *testing.T) {
			a := newTestAuthentication(&mockIdentityManager{}, &mockAuthTokenHandler{}, isProduction)

			setRecorder := httptest.NewRecorder()
			a.SetAuthCookie(setRecorder, &identityManager.AuthResponse{AccessToken: "a", RefreshToken: "r"})

			clearRecorder := httptest.NewRecorder()
			a.ClearAuthCookie(clearRecorder)

			set := setRecorder.Result().Cookies()
			cleared := clearRecorder.Result().Cookies()
			if len(set) != 2 || len(cleared) != 2 {
				t.Fatalf("expected 2 cookies each, got %d set and %d cleared", len(set), len(cleared))
			}

			for i := range set {
				s, c := set[i], cleared[i]
				if s.Name != c.Name || s.Path != c.Path || s.Secure != c.Secure ||
					s.SameSite != c.SameSite || s.HttpOnly != c.HttpOnly {
					t.Errorf("attributes differ for %q:\n set:     %+v\n cleared: %+v", s.Name, s, c)
				}
				if c.MaxAge >= 0 {
					t.Errorf("cleared cookie %q needs a negative MaxAge, got %d", c.Name, c.MaxAge)
				}
			}
		})
	}
}

func TestIsPasswordAcceptable(t *testing.T) {
	cases := map[string]bool{
		"Str0ngEnough":  true,
		"Sh0rtAA":       false, // 7 characters
		"alllowercase1": false, // no uppercase
		"ALLUPPERCASE1": false, // no lowercase
		"NoDigitsHere":  false, // no digit
		"":              false,
	}

	for password, want := range cases {
		if got := IsPasswordAcceptable(password); got != want {
			t.Errorf("IsPasswordAcceptable(%q) = %v, want %v", password, got, want)
		}
	}
}

const registerHookBody = `{"username":"user","email":"taken@example.com","password":"StrongPass1","firstName":"Fresh"}`

// duplicateSignupErr is what identityManager.Register reports for an address Supabase
// already knows, with email confirmation enabled.
var duplicateSignupErr = errors.New("supabase signup: no identity returned")

func TestRegisterHandler_HookFiresWithNewUserIdOnFreshSignup(t *testing.T) {
	const newUserID = "11111111-1111-1111-1111-111111111111"

	var gotID uuid.UUID
	var gotReq RegisterRequest
	a := newTestAuthentication(&mockIdentityManager{
		register: func(ctx context.Context, name, email, password string) (*identityManager.RegisterResponse, error) {
			return &identityManager.RegisterResponse{UserID: newUserID}, nil
		},
	}, &mockAuthTokenHandler{}, true)
	a.SetOnRegistered(func(_ context.Context, userID uuid.UUID, req RegisterRequest) error {
		gotID, gotReq = userID, req
		return nil
	})

	rr := postRegister(t, a, registerHookBody)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, rr.Code)
	}
	if gotID.String() != newUserID {
		t.Fatalf("hook got id %s, want %s", gotID, newUserID)
	}
	if gotReq.FirstName != "Fresh" || gotReq.Username != "user" {
		t.Errorf("hook lost request fields: %+v", gotReq)
	}
}

// The hook fires for an address that already exists too, with the id resolved by
// lookup. That is what lets an idempotent hook repair an application row that was
// never written — it is the same call, not a separate healing path.
func TestRegisterHandler_HookFiresWithLookedUpIdForExistingAddress(t *testing.T) {
	existingID := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	var gotID uuid.UUID
	a := newTestAuthentication(&mockIdentityManager{
		register: func(ctx context.Context, name, email, password string) (*identityManager.RegisterResponse, error) {
			return nil, duplicateSignupErr
		},
		getUserIdByEmail: func(_ context.Context, email string) (uuid.UUID, error) {
			if email != "taken@example.com" {
				return uuid.Nil, identityManager.ErrUserNotFound
			}
			return existingID, nil
		},
	}, &mockAuthTokenHandler{}, true)
	a.SetOnRegistered(func(_ context.Context, userID uuid.UUID, _ RegisterRequest) error {
		gotID = userID
		return nil
	})

	rr := postRegister(t, a, registerHookBody)

	if rr.Code != http.StatusCreated {
		t.Fatalf("a duplicate must stay indistinguishable: got status %d, want %d", rr.Code, http.StatusCreated)
	}
	if gotID != existingID {
		t.Fatalf("hook got id %s, want the existing user %s", gotID, existingID)
	}
}

func TestRegisterHandler_FailingHookDeletesTheUserItJustCreated(t *testing.T) {
	const newUserID = "11111111-1111-1111-1111-111111111111"

	var deleted []uuid.UUID
	a := newTestAuthentication(&mockIdentityManager{
		register: func(ctx context.Context, name, email, password string) (*identityManager.RegisterResponse, error) {
			return &identityManager.RegisterResponse{UserID: newUserID}, nil
		},
		deleteUser: func(_ context.Context, userID uuid.UUID) error {
			deleted = append(deleted, userID)
			return nil
		},
	}, &mockAuthTokenHandler{}, true)
	a.SetOnRegistered(func(_ context.Context, _ uuid.UUID, _ RegisterRequest) error {
		return errors.New("database is down")
	})

	rr := postRegister(t, a, registerHookBody)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, rr.Code)
	}
	if len(deleted) != 1 || deleted[0].String() != newUserID {
		t.Fatalf("expected the new user to be deleted, got %v", deleted)
	}
}

// SECURITY: the compensating delete must fire only for a user this request created.
// In the already-registered branch a failing hook would otherwise turn "register with
// an address you do not own" into a way to delete somebody else's account.
func TestRegisterHandler_FailingHookNeverDeletesAPreExistingUser(t *testing.T) {
	existingID := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	var deleted []uuid.UUID
	a := newTestAuthentication(&mockIdentityManager{
		register: func(ctx context.Context, name, email, password string) (*identityManager.RegisterResponse, error) {
			return nil, duplicateSignupErr
		},
		getUserIdByEmail: func(_ context.Context, _ string) (uuid.UUID, error) {
			return existingID, nil
		},
		deleteUser: func(_ context.Context, userID uuid.UUID) error {
			deleted = append(deleted, userID)
			return nil
		},
	}, &mockAuthTokenHandler{}, true)
	a.SetOnRegistered(func(_ context.Context, _ uuid.UUID, _ RegisterRequest) error {
		return errors.New("database is down")
	})

	postRegister(t, a, registerHookBody)

	if len(deleted) != 0 {
		t.Fatalf("SECURITY: a failing hook deleted a pre-existing account: %v", deleted)
	}
}

// A lookup failure leaves nothing to heal, but the response must not say so: a status
// that differs from a fresh signup tells an anonymous caller the address is taken.
func TestRegisterHandler_UnresolvableAddressStillAnswersCreated(t *testing.T) {
	hookFired := false
	a := newTestAuthentication(&mockIdentityManager{
		register: func(ctx context.Context, name, email, password string) (*identityManager.RegisterResponse, error) {
			return nil, duplicateSignupErr
		},
		getUserIdByEmail: func(_ context.Context, _ string) (uuid.UUID, error) {
			return uuid.Nil, errors.New("supabase get user by email: status 500")
		},
	}, &mockAuthTokenHandler{}, true)
	a.SetOnRegistered(func(_ context.Context, _ uuid.UUID, _ RegisterRequest) error {
		hookFired = true
		return nil
	})

	rr := postRegister(t, a, registerHookBody)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, rr.Code)
	}
	if hookFired {
		t.Fatal("the hook must not fire without a resolved user id")
	}
}

// Services that install no hook must be untouched by any of this, including the
// non-UUID user ids a fake identity manager may return.
func TestRegisterHandler_NoHookLeavesBehaviourUnchanged(t *testing.T) {
	lookups := 0
	a := newTestAuthentication(&mockIdentityManager{
		getUserIdByEmail: func(_ context.Context, _ string) (uuid.UUID, error) {
			lookups++
			return uuid.Nil, identityManager.ErrUserNotFound
		},
	}, &mockAuthTokenHandler{}, true)

	rr := postRegister(t, a, registerHookBody)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, rr.Code)
	}
	if lookups != 0 {
		t.Fatalf("expected no lookup without a hook, got %d", lookups)
	}
}
