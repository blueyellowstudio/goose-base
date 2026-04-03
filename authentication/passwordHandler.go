package authentication

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

func (a *Authentication) RequestPasswordResetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req RequestPasswordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Email != "" {
		go func(email string) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			if err := a.identities.SendPasswordResetEmail(ctx, email); err != nil {
				slog.Error("Failed to send password reset email", "error", err, "email", email)
			}
		}(req.Email)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(LoginResponse{
		Success: true,
		Message: "",
	})
}

func (a *Authentication) ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	identity, err := a.tokenHandler.GetIdentityFromContext(r.Context())
	if err != nil {
		a.respondWithError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Password == "" {
		a.respondWithError(w, http.StatusBadRequest, "Password is required")
		return
	}

	if !isPasswordAcceptable(req.Password) {
		a.respondWithError(w, http.StatusBadRequest, "Weak password")
		return
	}

	err = a.identities.UpdateUserPassword(r.Context(), identity.UserID, req.Password)
	if err != nil {
		slog.Error("Failed to update user password in Supabase", "error", err, "userID", identity.UserID)
		a.respondWithError(w, http.StatusInternalServerError, "Failed to reset password")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(LoginResponse{
		Success: true,
		Message: "Password reset successfully",
	})
}

func (a *Authentication) ChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	identity, err := a.tokenHandler.GetIdentityFromContext(r.Context())
	if err != nil {
		a.respondWithError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.CurrentPassword == "" || req.NewPassword == "" {
		a.respondWithError(w, http.StatusBadRequest, "Current password and new password are required")
		return
	}

	if !isPasswordAcceptable(req.NewPassword) {
		a.respondWithError(w, http.StatusBadRequest, "Weak password")
		return
	}

	// Verify current password by attempting to authenticate
	_, err = a.identities.Authenticate(r.Context(), identity.UserEmail, req.CurrentPassword)
	if err != nil {
		slog.Error("Current password verification failed", "error", err)
		a.respondWithError(w, http.StatusUnauthorized, "Current password is incorrect")
		return
	}

	// Update password in Supabase
	err = a.identities.UpdateUserPassword(r.Context(), identity.UserID, req.NewPassword)
	if err != nil {
		slog.Error("Failed to update password", "error", err)
		a.respondWithError(w, http.StatusInternalServerError, "Failed to update password")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(LoginResponse{
		Success: true,
		Message: "Password changed successfully",
	})
}

type ResetPasswordRequest struct {
	Password string `json:"password"`
}
type ChangePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}
type RequestPasswordResetRequest struct {
	Email string `json:"email"`
}
