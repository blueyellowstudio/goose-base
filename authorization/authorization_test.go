package authorization

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type mockTokenHandler struct {
	createContext         func(ctx context.Context, claims jwt.MapClaims) (context.Context, error)
	createDebugContext    func(ctx context.Context, userID string) (context.Context, error)
	validateToken         func(claims jwt.MapClaims) error
	getIdentityFromContext func(ctx context.Context) (ContextIdentity, error)
}

func (m *mockTokenHandler) CreateContext(ctx context.Context, claims jwt.MapClaims) (context.Context, error) {
	if m.createContext != nil {
		return m.createContext(ctx, claims)
	}
	return ctx, nil
}

func (m *mockTokenHandler) CreateDebugContext(ctx context.Context, userID string) (context.Context, error) {
	if m.createDebugContext != nil {
		return m.createDebugContext(ctx, userID)
	}
	return ctx, nil
}

func (m *mockTokenHandler) ValidateToken(claims jwt.MapClaims) error {
	if m.validateToken != nil {
		return m.validateToken(claims)
	}
	return nil
}

func (m *mockTokenHandler) GetIdentityFromContext(ctx context.Context) (ContextIdentity, error) {
	if m.getIdentityFromContext != nil {
		return m.getIdentityFromContext(ctx)
	}
	return ContextIdentity{UserID: uuid.Nil}, nil
}

func signedToken(t *testing.T, method jwt.SigningMethod, secret []byte, claims jwt.MapClaims) string {
	t.Helper()
	tkn := jwt.NewWithClaims(method, claims)
	tokenString, err := tkn.SignedString(secret)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return tokenString
}

func TestExtractToken_HeaderTakesPrecedenceOverCookie(t *testing.T) {
	a := Authorization{TokenCookieName: "token"}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer header-token")
	req.AddCookie(&http.Cookie{Name: "token", Value: "cookie-token"})

	got := a.extractToken(req)
	if got != "header-token" {
		t.Fatalf("expected header token, got %q", got)
	}
}

func TestExtractToken_UsesCookieFallback(t *testing.T) {
	a := Authorization{TokenCookieName: "token"}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: "cookie-token"})

	got := a.extractToken(req)
	if got != "cookie-token" {
		t.Fatalf("expected cookie token, got %q", got)
	}
}

func TestGetContextWithUser_DebugOverrideInNonProduction(t *testing.T) {
	type ctxKey string
	const key ctxKey = "debug-user"

	h := &mockTokenHandler{
		createDebugContext: func(ctx context.Context, userID string) (context.Context, error) {
			if userID != "dev-user" {
				return ctx, errors.New("unexpected user")
			}
			return context.WithValue(ctx, key, userID), nil
		},
	}
	a := Authorization{TokenHandler: h, isProduction: false}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("AuthorizationOverwrite", "dev-user")

	ctx, ok := a.getContextWithUser(req)
	if !ok {
		t.Fatal("expected debug override to authorize user")
	}
	if got, _ := ctx.Value(key).(string); got != "dev-user" {
		t.Fatalf("expected debug user in context, got %q", got)
	}
}

func TestGetContextWithUser_DebugOverrideDisabledInProduction(t *testing.T) {
	a := Authorization{TokenHandler: &mockTokenHandler{}, isProduction: true}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("AuthorizationOverwrite", "dev-user")

	_, ok := a.getContextWithUser(req)
	if ok {
		t.Fatal("expected unauthorized without token in production")
	}
}

func TestValidateToken_RejectsUnexpectedSigningMethod(t *testing.T) {
	a := Authorization{jwtSecret: []byte("secret"), TokenHandler: &mockTokenHandler{}}
	tokenString := signedToken(t, jwt.SigningMethodHS384, []byte("secret"), jwt.MapClaims{"sub": "u1"})

	_, err := a.validateToken(tokenString)
	if err == nil {
		t.Fatal("expected validation error for unexpected signing method")
	}
}

func TestHandler_ReturnsUnauthorizedWhenNoUser(t *testing.T) {
	a := Authorization{TokenHandler: &mockTokenHandler{}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	a.Handler(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
	if called {
		t.Fatal("expected next handler not to be called")
	}
}

func TestHandler_PassesThroughWithValidJWT(t *testing.T) {
	type ctxKey string
	const key ctxKey = "authorized"

	h := &mockTokenHandler{
		validateToken: func(claims jwt.MapClaims) error {
			if claims["sub"] != "u1" {
				return errors.New("missing sub")
			}
			return nil
		},
		createContext: func(ctx context.Context, claims jwt.MapClaims) (context.Context, error) {
			return context.WithValue(ctx, key, true), nil
		},
	}
	a := Authorization{
		TokenHandler: h,
		jwtSecret:    []byte("secret"),
	}

	tokenString := signedToken(t, jwt.SigningMethodHS256, []byte("secret"), jwt.MapClaims{"sub": "u1"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rr := httptest.NewRecorder()

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if ok, _ := r.Context().Value(key).(bool); !ok {
			t.Fatal("expected authorization context value")
		}
		w.WriteHeader(http.StatusNoContent)
	})

	a.Handler(next).ServeHTTP(rr, req)

	if !called {
		t.Fatal("expected next handler to be called")
	}
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, rr.Code)
	}
}
