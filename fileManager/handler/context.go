package handler

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

type contextKey struct{}

// WithUserID stores the authenticated user's ID in the context.
func WithUserID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

func userIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(contextKey{}).(uuid.UUID)
	return id, ok
}

// InjectUserIDMiddleware creates middleware that extracts a user ID using the provided
// function and stores it in the request context for the handler methods to read.
func InjectUserIDMiddleware(extract func(*http.Request) (uuid.UUID, bool)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if id, ok := extract(r); ok {
				r = r.WithContext(WithUserID(r.Context(), id))
			}
			next.ServeHTTP(w, r)
		})
	}
}
