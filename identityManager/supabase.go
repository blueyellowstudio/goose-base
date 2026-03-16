package identityManager

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"eurodima/internal/domain/identityManager"

	"github.com/google/uuid"
)

type SupabaseIdentityManager struct {
	supabaseURL        string
	supabaseServiceKey string
	supabaseAnonKey    string
}

func NewSupabaseIdentityManager() *SupabaseIdentityManager {
	return &SupabaseIdentityManager{
		supabaseURL:        os.Getenv("SUPABASE_URL"),
		supabaseServiceKey: os.Getenv("SUPABASE_SERVICE_KEY"),
		supabaseAnonKey:    os.Getenv("SUPABASE_ANON_KEY"),
	}
}

func (s *SupabaseIdentityManager) CreateManagedUser(email, displayName string, companyUUID uuid.UUID, username *string) (*identityManager.AdminUserResponse, error) {
	if s.supabaseURL == "" || s.supabaseServiceKey == "" {
		return nil, fmt.Errorf("supabase configuration missing (SUPABASE_URL or SUPABASE_SERVICE_KEY)")
	}

	adminURL := fmt.Sprintf("%s/auth/v1/admin/users", s.supabaseURL)

	userMetadata := map[string]interface{}{
		"display_name": displayName,
		"company_uuid": companyUUID.String(),
	}
	if username != nil && *username != "" {
		userMetadata["username"] = *username
	}

	payload := identityManager.CreateUserRequest{
		Email:        email,
		EmailConfirm: true,
		UserMetadata: userMetadata,
	}

	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, adminURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", s.supabaseServiceKey)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.supabaseServiceKey))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call supabase admin API: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errResp identityManager.AdminErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Message != "" {
			return nil, fmt.Errorf("supabase admin error: %s", errResp.Message)
		}
		return nil, fmt.Errorf("supabase admin returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var userResp identityManager.AdminUserResponse
	if err := json.Unmarshal(respBody, &userResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &userResp, nil
}

type supabaseRegisterResponse struct {
	ID         string `json:"id"`
	Identities []struct {
		UserID string `json:"user_id"`
	} `json:"identities"`
}

type supabaseErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (s *SupabaseIdentityManager) Register(name, email, password string) (*identityManager.RegisterResponse, error) {
	if s.supabaseURL == "" || s.supabaseAnonKey == "" {
		return nil, fmt.Errorf("supabase configuration missing")
	}

	authURL := fmt.Sprintf("%s/auth/v1/signup", s.supabaseURL)

	payload := map[string]interface{}{
		"email":    email,
		"password": password,
		"data": map[string]string{
			"display_name": name,
		},
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, authURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", s.supabaseAnonKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call supabase: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp supabaseErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			return nil, fmt.Errorf("%s", errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("supabase returned status %d", resp.StatusCode)
	}

	var authResp supabaseRegisterResponse
	if err := json.Unmarshal(respBody, &authResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if len(authResp.Identities) == 0 {
		return nil, fmt.Errorf("no identity returned from supabase")
	}

	return &identityManager.RegisterResponse{
		UserID: authResp.Identities[0].UserID,
	}, nil
}

func (s *SupabaseIdentityManager) RefreshToken(refreshToken string) (*identityManager.AuthResponse, error) {
	if s.supabaseURL == "" || s.supabaseAnonKey == "" {
		return nil, fmt.Errorf("supabase configuration missing")
	}

	authURL := fmt.Sprintf("%s/auth/v1/token?grant_type=refresh_token", s.supabaseURL)

	payload := map[string]string{
		"refresh_token": refreshToken,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, authURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", s.supabaseAnonKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call supabase: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp supabaseErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			return nil, fmt.Errorf("supabase error: %s", errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("supabase returned status %d", resp.StatusCode)
	}

	var authResp identityManager.AuthResponse
	if err := json.Unmarshal(respBody, &authResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &authResp, nil
}

func (s *SupabaseIdentityManager) Authenticate(email, password string) (*identityManager.AuthResponse, error) {
	if s.supabaseURL == "" || s.supabaseAnonKey == "" {
		return nil, fmt.Errorf("supabase configuration missing")
	}

	authURL := fmt.Sprintf("%s/auth/v1/token?grant_type=password", s.supabaseURL)

	payload := map[string]string{
		"email":    email,
		"password": password,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, authURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", s.supabaseAnonKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call supabase: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp supabaseErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			return nil, fmt.Errorf("supabase error: %s", errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("supabase returned status %d", resp.StatusCode)
	}

	var authResp identityManager.AuthResponse
	if err := json.Unmarshal(respBody, &authResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &authResp, nil
}

func (s *SupabaseIdentityManager) VerifyEmailOtp(email, token string, otpType identityManager.EmailOtpType) (*identityManager.AuthResponse, error) {
	if s.supabaseURL == "" || s.supabaseAnonKey == "" {
		return nil, fmt.Errorf("supabase configuration missing")
	}

	authURL := fmt.Sprintf("%s/auth/v1/verify", s.supabaseURL)

	payload := map[string]string{
		"email": email,
		"token": token,
		"type":  string(otpType),
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, authURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", s.supabaseAnonKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call supabase: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp supabaseErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			return nil, fmt.Errorf("%s", errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("supabase returned status %d", resp.StatusCode)
	}

	var authResp identityManager.AuthResponse
	if err := json.Unmarshal(respBody, &authResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &authResp, nil
}

func (s *SupabaseIdentityManager) SendMagicLink(email string) error {
	if s.supabaseURL == "" || s.supabaseServiceKey == "" {
		return fmt.Errorf("supabase configuration missing")
	}

	magicLinkURL := fmt.Sprintf("%s/auth/v1/magiclink", s.supabaseURL)

	payload := map[string]string{
		"email": email,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, magicLinkURL, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", s.supabaseServiceKey)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.supabaseServiceKey))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call supabase magic link API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("supabase magic link returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (s *SupabaseIdentityManager) SendInvite(email string, metadata map[string]interface{}) (uuid.UUID, error) {
	if s.supabaseURL == "" || s.supabaseServiceKey == "" {
		return uuid.Nil, fmt.Errorf("supabase configuration missing (SUPABASE_URL or SUPABASE_SERVICE_KEY)")
	}

	inviteURL := fmt.Sprintf("%s/auth/v1/invite", s.supabaseURL)

	payload := identityManager.InviteUserRequest{
		Email: email,
		Data:  metadata,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, inviteURL, bytes.NewBuffer(body))
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", s.supabaseServiceKey)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.supabaseServiceKey))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to call supabase invite API: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errResp identityManager.AdminErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Message != "" {
			return uuid.Nil, fmt.Errorf("supabase invite error: %s", errResp.Message)
		}
		return uuid.Nil, fmt.Errorf("supabase invite returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var userResp identityManager.AdminUserResponse
	if err := json.Unmarshal(respBody, &userResp); err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse response: %w", err)
	}
	userId, err := uuid.Parse(userResp.ID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse user ID: %w", err)
	}

	return userId, nil
}

func (s *SupabaseIdentityManager) VerifyTokenHash(tokenHash string, linkType string) (*identityManager.AuthResponse, error) {
	if s.supabaseURL == "" || s.supabaseAnonKey == "" {
		return nil, fmt.Errorf("supabase configuration missing")
	}

	verifyURL := fmt.Sprintf("%s/auth/v1/verify", s.supabaseURL)

	payload := map[string]string{
		"token_hash": tokenHash,
		"type":       linkType,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, verifyURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", s.supabaseAnonKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call supabase verify API: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp identityManager.AdminErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Message != "" {
			return nil, fmt.Errorf("supabase verify error: %s", errResp.Message)
		}
		return nil, fmt.Errorf("supabase verify returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp identityManager.VerifyTokenHashResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &identityManager.AuthResponse{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
	}, nil
}

func (s *SupabaseIdentityManager) SendPasswordResetEmail(email string) error {
	if s.supabaseURL == "" || s.supabaseAnonKey == "" {
		return fmt.Errorf("supabase configuration missing")
	}

	resetURL := fmt.Sprintf("%s/auth/v1/recover", s.supabaseURL)

	payload := map[string]string{
		"email": email,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, resetURL, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", s.supabaseAnonKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call supabase recover API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("supabase recover returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (s *SupabaseIdentityManager) DeleteUser(userID uuid.UUID) error {
	if s.supabaseURL == "" || s.supabaseServiceKey == "" {
		return fmt.Errorf("supabase configuration missing (SUPABASE_URL or SUPABASE_SERVICE_KEY)")
	}

	adminURL := fmt.Sprintf("%s/auth/v1/admin/users/%s", s.supabaseURL, userID.String())

	req, err := http.NewRequest(http.MethodDelete, adminURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", s.supabaseServiceKey)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.supabaseServiceKey))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call supabase admin API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		var errResp identityManager.AdminErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Message != "" {
			return fmt.Errorf("supabase admin error: %s", errResp.Message)
		}
		return fmt.Errorf("supabase admin returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (s *SupabaseIdentityManager) DisableUser(userID uuid.UUID) error {
	if s.supabaseURL == "" || s.supabaseServiceKey == "" {
		return fmt.Errorf("supabase configuration missing (SUPABASE_URL or SUPABASE_SERVICE_KEY)")
	}

	adminURL := fmt.Sprintf("%s/auth/v1/admin/users/%s", s.supabaseURL, userID.String())

	payload := map[string]interface{}{
		"ban_duration": "876600h", // ~100 years
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPut, adminURL, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", s.supabaseServiceKey)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.supabaseServiceKey))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call supabase admin API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		var errResp identityManager.AdminErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Message != "" {
			return fmt.Errorf("supabase admin error: %s", errResp.Message)
		}
		return fmt.Errorf("supabase admin returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (s *SupabaseIdentityManager) UpdateUserPassword(userID uuid.UUID, password string) error {
	if s.supabaseURL == "" || s.supabaseServiceKey == "" {
		return fmt.Errorf("supabase configuration missing (SUPABASE_URL or SUPABASE_SERVICE_KEY)")
	}

	adminURL := fmt.Sprintf("%s/auth/v1/admin/users/%s", s.supabaseURL, userID.String())

	payload := map[string]string{
		"password": password,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPut, adminURL, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", s.supabaseServiceKey)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.supabaseServiceKey))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call supabase admin API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		var errResp identityManager.AdminErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Message != "" {
			return fmt.Errorf("supabase admin error: %s", errResp.Message)
		}
		return fmt.Errorf("supabase admin returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (s *SupabaseIdentityManager) GetUserEmail(ctx context.Context, userID uuid.UUID) (string, error) {
	if s.supabaseURL == "" || s.supabaseServiceKey == "" {
		return "", fmt.Errorf("supabase configuration missing (SUPABASE_URL or SUPABASE_SERVICE_KEY)")
	}

	adminURL := fmt.Sprintf("%s/auth/v1/admin/users/%s", s.supabaseURL, userID.String())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, adminURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", s.supabaseServiceKey)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.supabaseServiceKey))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call supabase admin API: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp identityManager.AdminErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Message != "" {
			return "", fmt.Errorf("supabase admin error: %s", errResp.Message)
		}
		return "", fmt.Errorf("supabase admin returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var userResp identityManager.AdminUserResponse
	if err := json.Unmarshal(respBody, &userResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	return userResp.Email, nil
}

func (s *SupabaseIdentityManager) ResendVerificationEmail(email string) error {
	if s.supabaseURL == "" || s.supabaseAnonKey == "" {
		return fmt.Errorf("supabase configuration missing")
	}

	resendURL := fmt.Sprintf("%s/auth/v1/resend", s.supabaseURL)

	payload := map[string]string{
		"type":  "signup",
		"email": email,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, resendURL, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", s.supabaseAnonKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call supabase resend API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		var errResp identityManager.AdminErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Message != "" {
			return fmt.Errorf("supabase resend error: %s", errResp.Message)
		}
		return fmt.Errorf("supabase resend returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
