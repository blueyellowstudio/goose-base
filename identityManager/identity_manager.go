package identityManager

import (
	"context"

	"github.com/google/uuid"
)

// EmailOtpType represents the type of OTP used in email verification.
type EmailOtpType string

const (
	EmailOtpTypeSignup       EmailOtpType = "signup"
	EmailOtpTypeRecovery     EmailOtpType = "recovery"
	EmailOtpTypeMagicLink    EmailOtpType = "magiclink"
	EmailOtpTypeInvite       EmailOtpType = "invite"
	EmailOtpTypeEmailChange  EmailOtpType = "email_change"
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
	SendMagicLink(ctx context.Context, email string) error
	SendPasswordResetEmail(ctx context.Context, email string) error
	ResendVerificationEmail(ctx context.Context, email string) error
	SendInvite(ctx context.Context, email string, metadata map[string]interface{}) (uuid.UUID, error)
	CreateManagedUser(ctx context.Context, email, displayName string, companyUUID uuid.UUID, username *string) (*AdminUserResponse, error)
	GetUserEmail(ctx context.Context, userID uuid.UUID) (string, error)
	UpdateUserPassword(ctx context.Context, userID uuid.UUID, password string) error
	DisableUser(ctx context.Context, userID uuid.UUID) error
	DeleteUser(ctx context.Context, userID uuid.UUID) error
}
