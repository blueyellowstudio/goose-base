package authorization

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

func (a *Authorization) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, gotUser := a.getContextWithUser(r)
		if !gotUser {

			slog.Info("Authorization failed")
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
			ctx, err := a.TokenHandler.CreateDebugContext(ctx, user)
			if err != nil {
				slog.Error("Failed to create debug context", "error", err)
				return ctx, false
			}

			return ctx, true
		}
	}

	token := a.extractToken(r)
	if token == "" {
		slog.Info("No authorization token found")
		return ctx, false
	}

	claims, err := a.validateToken(token)
	if err != nil {
		slog.Info("Token validation failed", "error", err)
		return ctx, false
	}

	nextCtx, err := a.TokenHandler.CreateContext(ctx, claims)
	if err != nil {
		slog.Info("Token validation failed", "error", err)
		return ctx, false
	}

	return nextCtx, true
}

func (a *Authorization) validateToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {

		// Enforce HS256
		if t.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected signing method")
		}

		return a.jwtSecret, nil
	})

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
