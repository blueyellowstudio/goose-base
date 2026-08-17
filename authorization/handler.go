package authorization

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func (a *Authorization) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, gotUser := a.getContextWithUser(r)
		if !gotUser {

			slog.Error("Authorization failed", "status", http.StatusUnauthorized, "path", r.URL.Path)
			http.Error(w, "Authorization Failed", http.StatusUnauthorized)
			return
		}

		// Continue to next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *Authorization) getContextWithUser(r *http.Request) (context.Context, bool) {

	ctx := r.Context()

	if !a.isProduction {
		user := r.Header.Get("AuthorizationOverwrite")
		if user != "" {
			userID, err := uuid.Parse(user)
			if err != nil {
				slog.Error("Failed to parse user ID", "error", err)
				return ctx, false
			}
			ctx, err = a.TokenHandler.CreateDebugContext(ctx, userID)
			if err != nil {
				slog.Error("Failed to create debug context", "error", err)
				return ctx, false
			}

			return ctx, true
		}
	}

	token := a.extractToken(r)
	if token == "" {
		slog.Error("No authorization token found", "status", http.StatusUnauthorized, "path", r.URL.Path)
		return ctx, false
	}

	claims, err := a.validateToken(token)
	if err != nil {
		slog.Error("Token validation failed", "status", http.StatusUnauthorized, "path", r.URL.Path, "error", err)
		return ctx, false
	}

	nextCtx, err := a.TokenHandler.CreateContext(ctx, claims)
	if err != nil {
		slog.Error("Token validation failed", "status", http.StatusUnauthorized, "path", r.URL.Path, "error", err)
		return ctx, false
	}

	return nextCtx, true
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
