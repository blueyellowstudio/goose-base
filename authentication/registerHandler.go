package authentication

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"

	"github.com/blueyellowstudio/goose-base/identityManager"
)

var ErrWeakPassword = errors.New("password is too weak")

func (a *Authentication) RegisterUser(ctx context.Context, username, email, password string) (*identityManager.RegisterResponse, error) {
	if !isRegisterInputValid(email, password) {
		return nil, ErrWeakPassword
	}

	return a.identities.Register(ctx, username, email, password)
}

func (a *Authentication) VerifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req VerifyEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate input
	if req.Email == "" || req.Token == "" {
		a.respondWithError(w, http.StatusBadRequest, "Email and token are required")
		return
	}

	// Verify the OTP
	authResponse, err := a.identities.VerifyEmailOtp(r.Context(), req.Email, req.Token, identityManager.EmailOtpTypeSignup)
	if err != nil {
		slog.Error("Supabase OTP verification failed", "error", err)
		a.respondWithError(w, http.StatusUnauthorized, "Invalid or expired OTP")
		return
	}

	// Set the auth cookie
	a.setAuthCookie(w, &identityManager.AuthResponse{
		AccessToken:  authResponse.AccessToken,
		RefreshToken: authResponse.RefreshToken,
	})

	// Respond to the user
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(LoginResponse{
		Success: true,
		Message: "Email verified successfully",
	})
}

func (a *Authentication) ResendVerificationEmailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req ResendVerificationEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate input
	if req.Email == "" {
		a.respondWithError(w, http.StatusBadRequest, "Email is required")
		return
	}

	// Resend the verification email
	err := a.identities.ResendVerificationEmail(r.Context(), req.Email)
	if err != nil {
		slog.Error("Failed to resend verification email", "error", err)
		a.respondWithError(w, http.StatusInternalServerError, "Failed to resend verification email")
		return
	}

	// Respond to the user
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(LoginResponse{
		Success: true,
		Message: "Verification email sent",
	})
}

// isRegisterInputValid validates the user registration input fields such as Username, Email, and Password.
// Returns true if the input is valid, otherwise returns false.
func isRegisterInputValid(email, password string) bool {
	if email == "" || password == "" {
		slog.Warn("Invalid registration input", "email", email)
		return false
	}

	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		slog.Warn("Invalid registration input", "email", email)
		return false
	}

	if !isPasswordAcceptable(password) {
		slog.Warn("Invalid registration input")
		return false
	}

	return true
}

// isPasswordAcceptable validates the user registration input fields such as Username, Email, and Password.
// Returns true if the input is valid, otherwise returns false.
func isPasswordAcceptable(password string) bool {
	if len(password) < 8 {
		slog.Warn("Invalid registration input password is too short")
		return false
	}

	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)

	if !hasLower || !hasUpper || !hasNumber {
		slog.Warn("Invalid registration input, password is too weak")
		return false
	}
	return true
}

type ResendVerificationEmailRequest struct {
	Email string `json:"email"`
}
