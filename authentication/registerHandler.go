package authentication

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/blueyellowstudio/goose-base/identityManager"
)

var ErrWeakPassword = errors.New("password is too weak")

// registerRejectedMessage is the single message every rejected registration gets.
// Naming the rule that failed would tell an attacker which half of the credentials
// to keep and which to vary.
const registerRejectedMessage = "Invalid email or password"

// registerAcceptedMessage is the single message every accepted registration gets,
// whether or not an account was actually created. See RegisterHandler.
const registerAcceptedMessage = "Registration received, check your email to confirm the address"

func (a *Authentication) RegisterUser(ctx context.Context, username, email, password string) (*identityManager.RegisterResponse, error) {
	if !isRegisterInputValid(email, password) {
		return nil, ErrWeakPassword
	}

	return a.identities.Register(ctx, username, email, password)
}

// RegisterHandler creates an account from an anonymous request.
//
// It deliberately writes no auth cookie. With Supabase email confirmation enabled
// signup returns no session — the account is unconfirmed until the user enters the
// emailed OTP, and GetVerifyTokenHandler(identityManager.EmailOtpTypeSignup) is what
// calls setAuthCookie once it does.
//
// Every accepted request gets the same 201 and the same body, including one for an
// address that is already registered. Anything that distinguishes the two — a 409, a
// different message, a user id present in one case and absent in the other — turns
// this endpoint into an oracle that an unauthenticated caller can walk an email list
// through. The user id therefore stays server-side, in the log line below.
func (a *Authentication) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		slog.Error("Registration rejected", "status", http.StatusMethodNotAllowed, "path", r.URL.Path, "method", r.Method)
		a.respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Error("Registration rejected", "status", http.StatusBadRequest, "path", r.URL.Path, "err", err)
		a.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if !isRegisterInputValid(req.Email, req.Password) {
		slog.Error("Registration rejected", "status", http.StatusBadRequest, "path", r.URL.Path, "err", ErrWeakPassword)
		a.respondWithError(w, http.StatusBadRequest, registerRejectedMessage)
		return
	}

	registered, err := a.identities.Register(r.Context(), req.Username, req.Email, req.Password)
	switch {
	case err == nil:
		slog.Info("Registered new user", "userID", registered.UserID)
	case isEmailAlreadyRegistered(err):
		// Not an error for the caller: the address is taken, which is the account
		// owner's business and nobody else's.
		slog.Info("Signup for an already registered address", "err", err)
	default:
		slog.Error("Registration failed", "status", http.StatusInternalServerError, "path", r.URL.Path, "err", err)
		a.respondWithError(w, http.StatusInternalServerError, "Registration failed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(LoginResponse{
		Success: true,
		Message: registerAcceptedMessage,
	})
}

// alreadyRegisteredMarkers are the error texts identityManager.Register produces for
// an address Supabase already knows.
//
// With email confirmation enabled Supabase answers a duplicate signup with 200 and an
// empty "identities" array — its own anti-enumeration behaviour — which Register
// reports as "no identity returned". With confirmation disabled it answers 422 "User
// already registered" instead. Both mean the same thing here.
var alreadyRegisteredMarkers = []string{
	"no identity returned",
	"user already registered",
	"email address is already registered",
}

// isEmailAlreadyRegistered reports whether err is Supabase saying the address is taken
// rather than a genuine failure, which must still surface as a 500.
func isEmailAlreadyRegistered(err error) bool {
	if err == nil {
		return false
	}

	message := strings.ToLower(err.Error())
	for _, marker := range alreadyRegisteredMarkers {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func (a *Authentication) GetVerifyTokenHandler(otpType identityManager.EmailOtpType) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
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
		authResponse, err := a.identities.VerifyEmailOtp(r.Context(), req.Email, req.Token, otpType)
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
