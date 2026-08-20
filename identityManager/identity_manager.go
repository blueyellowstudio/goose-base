package identityManager

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// ErrUserNotFound is what a lookup reports when the identity provider knows no user
// matching the query. It is a normal answer, not a failure of the call — callers are
// expected to branch on it rather than treat it as an outage.
var ErrUserNotFound = errors.New("user not found")

// EmailOtpType represents the type of OTP used in email verification.
type EmailOtpType string

const (
	EmailOtpTypeSignup      EmailOtpType = "signup"
	EmailOtpTypeRecovery    EmailOtpType = "recovery"
	EmailOtpTypeMagicLink   EmailOtpType = "magiclink"
	EmailOtpTypeInvite      EmailOtpType = "invite"
	EmailOtpTypeEmailChange EmailOtpType = "email_change"
	// EmailOtpTypeEmail verifies the numeric code from a passwordless sign-in — the one
	// SendMagicLink's email carries as {{ .Token }}. Supabase treats it as a distinct type
	// from EmailOtpTypeMagicLink, which verifies a link's token_hash instead.
	EmailOtpTypeEmail EmailOtpType = "email"
)

type CreateUserRequest struct {
	Email        string                 `json:"email"`
	EmailConfirm bool                   `json:"email_confirm"`
	UserMetadata map[string]interface{} `json:"user_metadata,omitempty"`
}

type InviteUserRequest struct {
	Email string                 `json:"email"`
	Data  map[string]interface{} `json:"data,omitempty"`
}

type RegisterResponse struct {
	UserID string
}

// AuthResponse
type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type AdminUserResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type AdminErrorResponse struct {
	Message string `json:"message"`
}

// IdentityManager defines operations for managing user identities.
type IdentityManager interface {
	Register(ctx context.Context, name, email, password string) (*RegisterResponse, error)
	Authenticate(ctx context.Context, email, password string) (*AuthResponse, error)
	RefreshToken(ctx context.Context, refreshToken string) (*AuthResponse, error)
	VerifyEmailOtp(ctx context.Context, email, token string, otpType EmailOtpType) (*AuthResponse, error)
	VerifyTokenHash(ctx context.Context, tokenHash, linkType string) (*AuthResponse, error)
	// ExchangeOAuthCode trades an OAuth authorization code plus its PKCE verifier for a
	// session. It exists so the OAuth handlers never speak HTTP to the provider directly.
	ExchangeOAuthCode(ctx context.Context, code, verifier string) (*AuthResponse, error)
	SendMagicLink(ctx context.Context, email string) error
	SendPasswordResetEmail(ctx context.Context, email string) error
	ResendVerificationEmail(ctx context.Context, email string) error
	SendInvite(ctx context.Context, email string, metadata map[string]interface{}) (uuid.UUID, error)
	CreateManagedUser(ctx context.Context, email, displayName string, companyUUID uuid.UUID, username *string) (*AdminUserResponse, error)
	GetUserEmail(ctx context.Context, userID uuid.UUID) (string, error)
	// GetUserIdByEmail resolves an address to its user id, or reports ErrUserNotFound.
	// It exists so a caller can recover the id of an account that already exists —
	// signup returns no id for a duplicate address.
	GetUserIdByEmail(ctx context.Context, email string) (uuid.UUID, error)
	UpdateUserPassword(ctx context.Context, userID uuid.UUID, password string) error
	DisableUser(ctx context.Context, userID uuid.UUID) error
	DeleteUser(ctx context.Context, userID uuid.UUID) error
}
