package authorization

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func (a *Authorization) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, gotUser := a.getContextWithUser(r)
		if !gotUser {
			// getContextWithUser has already logged the failure, with the underlying
			// error attached. Logging again here only duplicates it, minus the detail.
			http.Error(w, "Authorization Failed", http.StatusUnauthorized)
			return
		}

		// Continue to next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *Authorization) getContextWithUser(r *http.Request) (context.Context, bool) {
	ctx, err := a.contextFromRequest(r)
	if err != nil {
		slog.Error("Authorization failed", "status", http.StatusUnauthorized, "path", r.URL.Path, "error", err)
		return r.Context(), false
	}

	return ctx, true
}

// IdentityFromRequest validates the request's token and returns the identity it
// carries. It is the entry point for public endpoints that want to know whether a
// caller is signed in without rejecting the request: a missing or expired token is
// reported as (zero identity, false) and is neither logged nor written to the
// response, because for a logged-out visitor it is a normal state and not an error.
func (a *Authorization) IdentityFromRequest(r *http.Request) (ContextIdentity, bool) {
	ctx, err := a.contextFromRequest(r)
	if err != nil {
		return ContextIdentity{}, false
	}

	identity, err := a.TokenHandler.GetIdentityFromContext(ctx)
	if err != nil {
		return ContextIdentity{}, false
	}

	return identity, true
}

// contextFromRequest resolves the caller from the request and returns a context
// carrying the identity. It never logs or writes a response — callers decide
// whether a failure is an error worth reporting.
func (a *Authorization) contextFromRequest(r *http.Request) (context.Context, error) {
	ctx := r.Context()

	if !a.isProduction {
		user := r.Header.Get("AuthorizationOverwrite")
		if user != "" {
			userID, err := uuid.Parse(user)
			if err != nil {
				return ctx, fmt.Errorf("failed to parse overwrite user ID: %w", err)
			}
			debugCtx, err := a.TokenHandler.CreateDebugContext(ctx, userID)
			if err != nil {
				return ctx, fmt.Errorf("failed to create debug context: %w", err)
			}

			return debugCtx, nil
		}
	}

	token := a.extractToken(r)
	if token == "" {
		return ctx, errors.New("no authorization token found")
	}

	claims, err := a.validateToken(token)
	if err != nil {
		return ctx, fmt.Errorf("token validation failed: %w", err)
	}

	nextCtx, err := a.TokenHandler.CreateContext(ctx, claims)
	if err != nil {
		return ctx, fmt.Errorf("failed to create request context: %w", err)
	}

	return nextCtx, nil
}

func (a *Authorization) validateToken(tokenString string) (jwt.MapClaims, error) {
	validMethods := make([]string, 0, 2)
	if len(a.jwtSecret) > 0 {
		validMethods = append(validMethods, "HS256")
	}
	if a.jwks != nil {
		validMethods = append(validMethods, "ES256")
	}

	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		switch t.Method.Alg() {
		case "HS256":
			return a.jwtSecret, nil
		case "ES256":
			return a.jwks.Keyfunc(t)
		default:
			return nil, errors.New("unexpected signing method")
		}
	}, jwt.WithValidMethods(validMethods))

	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	if err := a.TokenHandler.ValidateToken(claims); err != nil {
		return nil, err
	}

	return claims, nil
}
