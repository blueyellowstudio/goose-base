package identityManager

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type SupabaseIdentityManager struct {
	supabaseURL        string
	supabaseServiceKey string
	supabaseAnonKey    string
	client             *http.Client
}

// NewSupabaseIdentityManager creates an IdentityManager backed by Supabase Auth.
// url is your Supabase project URL, serviceKey is the service_role key, anonKey is the anon/public key.
func NewSupabaseIdentityManager(url, serviceKey, anonKey string) *SupabaseIdentityManager {
	return &SupabaseIdentityManager{
		supabaseURL:        url,
		supabaseServiceKey: serviceKey,
		supabaseAnonKey:    anonKey,
		client:             &http.Client{Timeout: 10 * time.Second},
	}
}

// Compile-time check that SupabaseIdentityManager implements IdentityManager.
var _ IdentityManager = (*SupabaseIdentityManager)(nil)

func (s *SupabaseIdentityManager) newRequest(ctx context.Context, method, url string, payload interface{}) (*http.Request, error) {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		body = bytes.NewBuffer(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func (s *SupabaseIdentityManager) doServiceRequest(ctx context.Context, method, url string, payload interface{}) ([]byte, int, error) {
	req, err := s.newRequest(ctx, method, url, payload)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("apikey", s.supabaseServiceKey)
	req.Header.Set("Authorization", "Bearer "+s.supabaseServiceKey)
	return s.do(req)
}

func (s *SupabaseIdentityManager) doAnonRequest(ctx context.Context, method, url string, payload interface{}) ([]byte, int, error) {
	req, err := s.newRequest(ctx, method, url, payload)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("apikey", s.supabaseAnonKey)
	return s.do(req)
}

func (s *SupabaseIdentityManager) do(req *http.Request) ([]byte, int, error) {
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read response body: %w", err)
	}
	return body, resp.StatusCode, nil
}

// parseAdminError extracts a human-readable error from a Supabase admin error response body.
func parseAdminError(body []byte, status int, context string) error {
	var errResp AdminErrorResponse
	if json.Unmarshal(body, &errResp) == nil && errResp.Message != "" {
		return fmt.Errorf("%s: %s", context, errResp.Message)
	}
	return fmt.Errorf("%s: status %d: %s", context, status, string(body))
}

// parseAnonError extracts a human-readable error from a Supabase anon error response body.
func parseAnonError(body []byte, status int, context string) error {
	var errResp struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		Message          string `json:"message"`
	}
	if json.Unmarshal(body, &errResp) == nil {
		if errResp.ErrorDescription != "" {
			return fmt.Errorf("%s: %s", context, errResp.ErrorDescription)
		}
		if errResp.Message != "" {
			return fmt.Errorf("%s: %s", context, errResp.Message)
		}
	}
	return fmt.Errorf("%s: status %d: %s", context, status, string(body))
}

func (s *SupabaseIdentityManager) Register(ctx context.Context, name, email, password string) (*RegisterResponse, error) {
	body, status, err := s.doAnonRequest(ctx, http.MethodPost,
		s.supabaseURL+"/auth/v1/signup",
		map[string]interface{}{
			"email":    email,
			"password": password,
			"data":     map[string]string{"display_name": name},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("supabase signup: %w", err)
	}
	if status != http.StatusOK {
		return nil, parseAnonError(body, status, "supabase signup")
	}

	var resp struct {
		Identities []struct {
			UserID string `json:"user_id"`
		} `json:"identities"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("supabase signup: failed to parse response: %w", err)
	}
	if len(resp.Identities) == 0 {
		return nil, fmt.Errorf("supabase signup: no identity returned")
	}
	return &RegisterResponse{UserID: resp.Identities[0].UserID}, nil
}

func (s *SupabaseIdentityManager) Authenticate(ctx context.Context, email, password string) (*AuthResponse, error) {
	body, status, err := s.doAnonRequest(ctx, http.MethodPost,
		s.supabaseURL+"/auth/v1/token?grant_type=password",
		map[string]string{"email": email, "password": password},
	)
	if err != nil {
		return nil, fmt.Errorf("supabase authenticate: %w", err)
	}
	if status != http.StatusOK {
		return nil, parseAnonError(body, status, "supabase authenticate")
	}
	var resp AuthResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("supabase authenticate: failed to parse response: %w", err)
	}
	return &resp, nil
}

func (s *SupabaseIdentityManager) RefreshToken(ctx context.Context, refreshToken string) (*AuthResponse, error) {
	body, status, err := s.doAnonRequest(ctx, http.MethodPost,
		s.supabaseURL+"/auth/v1/token?grant_type=refresh_token",
		map[string]string{"refresh_token": refreshToken},
	)
	if err != nil {
		return nil, fmt.Errorf("supabase refresh token: %w", err)
	}
	if status != http.StatusOK {
		return nil, parseAnonError(body, status, "supabase refresh token")
	}
	var resp AuthResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("supabase refresh token: failed to parse response: %w", err)
	}
	return &resp, nil
}

func (s *SupabaseIdentityManager) VerifyEmailOtp(ctx context.Context, email, token string, otpType EmailOtpType) (*AuthResponse, error) {
	body, status, err := s.doAnonRequest(ctx, http.MethodPost,
		s.supabaseURL+"/auth/v1/verify",
		map[string]string{"email": email, "token": token, "type": string(otpType)},
	)
	if err != nil {
		return nil, fmt.Errorf("supabase verify email otp: %w", err)
	}
	if status != http.StatusOK {
		return nil, parseAnonError(body, status, "supabase verify email otp")
	}
	var resp AuthResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("supabase verify email otp: failed to parse response: %w", err)
	}
	return &resp, nil
}

func (s *SupabaseIdentityManager) VerifyTokenHash(ctx context.Context, tokenHash, linkType string) (*AuthResponse, error) {
	body, status, err := s.doAnonRequest(ctx, http.MethodPost,
		s.supabaseURL+"/auth/v1/verify",
		map[string]string{"token_hash": tokenHash, "type": linkType},
	)
	if err != nil {
		return nil, fmt.Errorf("supabase verify token hash: %w", err)
	}
	if status != http.StatusOK {
		return nil, parseAdminError(body, status, "supabase verify token hash")
	}
	var resp AuthResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("supabase verify token hash: failed to parse response: %w", err)
	}
	return &resp, nil
}

func (s *SupabaseIdentityManager) SendMagicLink(ctx context.Context, email string) error {
	body, status, err := s.doServiceRequest(ctx, http.MethodPost,
		s.supabaseURL+"/auth/v1/magiclink",
		map[string]string{"email": email},
	)
	if err != nil {
		return fmt.Errorf("supabase magic link: %w", err)
	}
	if status != http.StatusOK {
		return parseAdminError(body, status, "supabase magic link")
	}
	return nil
}

func (s *SupabaseIdentityManager) SendPasswordResetEmail(ctx context.Context, email string) error {
	body, status, err := s.doAnonRequest(ctx, http.MethodPost,
		s.supabaseURL+"/auth/v1/recover",
		map[string]string{"email": email},
	)
	if err != nil {
		return fmt.Errorf("supabase password reset: %w", err)
	}
	if status != http.StatusOK {
		return parseAnonError(body, status, "supabase password reset")
	}
	return nil
}

func (s *SupabaseIdentityManager) ResendVerificationEmail(ctx context.Context, email string) error {
	body, status, err := s.doAnonRequest(ctx, http.MethodPost,
		s.supabaseURL+"/auth/v1/resend",
		map[string]string{"type": "signup", "email": email},
	)
	if err != nil {
		return fmt.Errorf("supabase resend verification: %w", err)
	}
	if status != http.StatusOK {
		return parseAdminError(body, status, "supabase resend verification")
	}
	return nil
}

func (s *SupabaseIdentityManager) SendInvite(ctx context.Context, email string, metadata map[string]interface{}) (uuid.UUID, error) {
	body, status, err := s.doServiceRequest(ctx, http.MethodPost,
		s.supabaseURL+"/auth/v1/invite",
		InviteUserRequest{Email: email, Data: metadata},
	)
	if err != nil {
		return uuid.Nil, fmt.Errorf("supabase invite: %w", err)
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return uuid.Nil, parseAdminError(body, status, "supabase invite")
	}
	var resp AdminUserResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return uuid.Nil, fmt.Errorf("supabase invite: failed to parse response: %w", err)
	}
	userID, err := uuid.Parse(resp.ID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("supabase invite: failed to parse user ID: %w", err)
	}
	return userID, nil
}

func (s *SupabaseIdentityManager) CreateManagedUser(ctx context.Context, email, displayName string, companyUUID uuid.UUID, username *string) (*AdminUserResponse, error) {
	metadata := map[string]interface{}{
		"display_name": displayName,
		"company_uuid": companyUUID.String(),
	}
	if username != nil && *username != "" {
		metadata["username"] = *username
	}

	body, status, err := s.doServiceRequest(ctx, http.MethodPost,
		s.supabaseURL+"/auth/v1/admin/users",
		CreateUserRequest{Email: email, EmailConfirm: true, UserMetadata: metadata},
	)
	if err != nil {
		return nil, fmt.Errorf("supabase create managed user: %w", err)
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return nil, parseAdminError(body, status, "supabase create managed user")
	}
	var resp AdminUserResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("supabase create managed user: failed to parse response: %w", err)
	}
	return &resp, nil
}

func (s *SupabaseIdentityManager) GetUserEmail(ctx context.Context, userID uuid.UUID) (string, error) {
	body, status, err := s.doServiceRequest(ctx, http.MethodGet,
		fmt.Sprintf("%s/auth/v1/admin/users/%s", s.supabaseURL, userID),
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("supabase get user email: %w", err)
	}
	if status != http.StatusOK {
		return "", parseAdminError(body, status, "supabase get user email")
	}
	var resp AdminUserResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("supabase get user email: failed to parse response: %w", err)
	}
	return resp.Email, nil
}

func (s *SupabaseIdentityManager) UpdateUserPassword(ctx context.Context, userID uuid.UUID, password string) error {
	body, status, err := s.doServiceRequest(ctx, http.MethodPut,
		fmt.Sprintf("%s/auth/v1/admin/users/%s", s.supabaseURL, userID),
		map[string]string{"password": password},
	)
	if err != nil {
		return fmt.Errorf("supabase update password: %w", err)
	}
	if status != http.StatusOK {
		return parseAdminError(body, status, "supabase update password")
	}
	return nil
}

func (s *SupabaseIdentityManager) DisableUser(ctx context.Context, userID uuid.UUID) error {
	body, status, err := s.doServiceRequest(ctx, http.MethodPut,
		fmt.Sprintf("%s/auth/v1/admin/users/%s", s.supabaseURL, userID),
		map[string]interface{}{"ban_duration": "876600h"}, // ~100 years
	)
	if err != nil {
		return fmt.Errorf("supabase disable user: %w", err)
	}
	if status != http.StatusOK {
		return parseAdminError(body, status, "supabase disable user")
	}
	return nil
}

func (s *SupabaseIdentityManager) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	body, status, err := s.doServiceRequest(ctx, http.MethodDelete,
		fmt.Sprintf("%s/auth/v1/admin/users/%s", s.supabaseURL, userID),
		nil,
	)
	if err != nil {
		return fmt.Errorf("supabase delete user: %w", err)
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return parseAdminError(body, status, "supabase delete user")
	}
	return nil
}
