package authentication

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
)

const (
	CookieMaxAge = 7 * 24 * 60 * 60 // 7 days in seconds
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	FirstName   string `json:"firstName"`
	LastName    string `json:"lastName"`
	PhoneNumber string `json:"phoneNumber"`
	Role        *int   `json:"role"`
}

type VerifyEmailRequest struct {
	Email string `json:"email"`
	Token string `json:"token"`
}

type SupabaseAuthResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	User         struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
}

type SupabaseErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type LoginResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

func (a *Authentication) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		a.respondWithError(w, http.StatusBadRequest, "Email and password are required")
		return
	}

	authResponse, err := a.identities.Authenticate(r.Context(), req.Email, req.Password)
	if err != nil {
		slog.Error("Supabase authentication failed", "error", err)
		a.respondWithError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	a.setAuthCookie(w, authResponse)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(LoginResponse{
		Success: true,
		Message: "Login successful",
	})
}

func (a *Authentication) AuthenticateWithSupabase(email, password string) (string, string, error) {
	authResp, err := a.identities.Authenticate(context.Background(), email, password)
	if err != nil {
		return "", "", err
	}

	return authResp.AccessToken, authResp.RefreshToken, nil
}

func (a *Authentication) refreshToken(w http.ResponseWriter, ctx context.Context, refreshToken string) (*string, error) {
	authResp, err := a.identities.RefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	a.setAuthCookie(w, authResp)
	return &authResp.AccessToken, nil
}

type RefreshAuthRequest struct {
	RefreshToken *string `json:"refresh_token"`
}

func (a *Authentication) RefreshAuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req RefreshAuthRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	if req.RefreshToken == nil {
		req.RefreshToken = a.getRefreshTokenFromCookies(r)
	}

	if req.RefreshToken == nil || *req.RefreshToken == "" {
		a.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	_, err := a.refreshToken(w, r.Context(), *req.RefreshToken)
	if err != nil {
		slog.Error("Supabase token refresh failed", "error", err)
		a.respondWithError(w, http.StatusUnauthorized, "Invalid or expired refresh token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(LoginResponse{
		Success: true,
		Message: "Token refreshed successfully",
	})
}

func (a *Authentication) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	a.clearAuthCookie(w)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

func (a *Authentication) getRefreshTokenFromCookies(r *http.Request) *string {
	cookie, err := r.Cookie(a.refreshTokenCookieName)
	if err != nil {
		return nil
	}
	return &cookie.Value
}

// DisableAccountHandler disables the user's account in the identity manager and clears authentication cookies
func (a *Authentication) DisableAccountHandler(w http.ResponseWriter, r *http.Request) {
	userClaims, err := a.tokenHandler.GetIdentityFromContext(r.Context())
	if err != nil {
		a.respondWithError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	err = a.identities.DisableUser(r.Context(), userClaims.UserID)
	if err != nil {
		slog.Error("Failed to disable user account", "error", err, "userID", userClaims.UserID)
		a.respondWithError(w, http.StatusInternalServerError, "Failed to disable account")
		return
	}

	a.clearAuthCookie(w)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(LoginResponse{
		Success: true,
		Message: "Account disabled successfully",
	})
}

// DeleteAccountHandler deletes the user's account from the identity manager and clears authentication cookies, this can also be used in combination of a handler that deletes internal user data, not only from the identity manager
func (a *Authentication) DeleteAccountHandler(w http.ResponseWriter, r *http.Request) {
	userClaims, err := a.tokenHandler.GetIdentityFromContext(r.Context())
	if err != nil {
		a.respondWithError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	err = a.identities.DeleteUser(r.Context(), userClaims.UserID)
	if err != nil {
		slog.Error("Failed to delete user from Supabase", "error", err, "userID", userClaims.UserID)
		a.respondWithError(w, http.StatusInternalServerError, "Failed to delete account")
		return
	}

	a.clearAuthCookie(w)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(LoginResponse{
		Success: true,
		Message: "Account deleted successfully",
	})
}
