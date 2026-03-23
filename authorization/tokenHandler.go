package authorization

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type TokenHandler interface {
	CreateContext(ctx context.Context, claims jwt.MapClaims) (context.Context, error)
	CreateDebugContext(ctx context.Context, userID string) (context.Context, error)
	ValidateToken(claims jwt.MapClaims) error
	GetIdentityFromContext(ctx context.Context) (ContextIdentity, error)
}

type ContextIdentity struct {
	UserID    uuid.UUID
	UserEmail string
}
