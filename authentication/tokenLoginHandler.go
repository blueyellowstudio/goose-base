package authentication

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

type StartLoginRequest struct {
	Email string `json:"email"`
}

func (a *Authentication) StartLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req StartLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Email == "" {
		a.respondWithError(w, http.StatusBadRequest, "Email is required")
		return
	}

	err := a.identities.SendMagicLink(r.Context(), req.Email)
	if err != nil {
		slog.Error("Failed to send magic link", "error", err, "email", req.Email)
		a.respondWithError(w, http.StatusInternalServerError, "Failed to send login link")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(LoginResponse{
		Success: true,
		Message: "Login link sent",
	})
}
