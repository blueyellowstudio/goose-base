package identityManager

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

type contractBackend struct {
	name                 string
	newManager           func(t *testing.T) IdentityManager
	validAuthEmail       string
	validAuthPassword    string
	supportsSuccessfulAuth bool
}

func selectedIdentityManagerBackends(t *testing.T) []string {
	t.Helper()
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("IDENTITYMANAGER_TEST_BACKEND")))
	switch mode {
	case "", "mock":
		return []string{"mock"}
	case "integration":
		return []string{"integration"}
	case "both":
		return []string{"mock", "integration"}
	default:
		t.Fatalf("invalid IDENTITYMANAGER_TEST_BACKEND=%q (allowed: mock|integration|both)", mode)
		return nil
	}
}

func newMockContractBackend() contractBackend {
	return contractBackend{
		name: "mock",
		newManager: func(t *testing.T) IdentityManager {
			t.Helper()
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodPost && r.URL.Path == "/auth/v1/token" && r.URL.Query().Get("grant_type") == "password":
					var req map[string]string
					_ = json.NewDecoder(r.Body).Decode(&req)
					if req["email"] == "valid@example.com" && req["password"] == "Password1" {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(`{"access_token":"access-token","refresh_token":"refresh-token"}`))
						return
					}
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error_description":"Invalid login credentials"}`))
				case r.Method == http.MethodPost && r.URL.Path == "/auth/v1/token" && r.URL.Query().Get("grant_type") == "refresh_token":
					var req map[string]string
					_ = json.NewDecoder(r.Body).Decode(&req)
					if req["refresh_token"] == "refresh-token" {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(`{"access_token":"new-access","refresh_token":"new-refresh"}`))
						return
					}
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(`{"message":"invalid refresh token"}`))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			t.Cleanup(ts.Close)
			return NewSupabaseIdentityManager(ts.URL, "service-key", "anon-key")
		},
		validAuthEmail:       "valid@example.com",
		validAuthPassword:    "Password1",
		supportsSuccessfulAuth: true,
	}
}

func newIntegrationContractBackend(t *testing.T) contractBackend {
	t.Helper()
	url := strings.TrimSpace(os.Getenv("SUPABASE_URL"))
	anonKey := strings.TrimSpace(os.Getenv("SUPABASE_ANON_KEY"))
	serviceKey := strings.TrimSpace(os.Getenv("SUPABASE_SERVICE_KEY"))

	if url == "" || anonKey == "" {
		t.Skip("integration backend skipped: set SUPABASE_URL and SUPABASE_ANON_KEY")
	}

	email := strings.TrimSpace(os.Getenv("SUPABASE_TEST_EMAIL"))
	password := strings.TrimSpace(os.Getenv("SUPABASE_TEST_PASSWORD"))

	return contractBackend{
		name: "integration",
		newManager: func(t *testing.T) IdentityManager {
			t.Helper()
			return NewSupabaseIdentityManager(url, serviceKey, anonKey)
		},
		validAuthEmail:       email,
		validAuthPassword:    password,
		supportsSuccessfulAuth: email != "" && password != "",
	}
}

func runIdentityManagerContractSuite(t *testing.T, backend contractBackend) {
	t.Helper()

	t.Run("Authenticate_InvalidCredentials_ReturnsError", func(t *testing.T) {
		m := backend.newManager(t)
		_, err := m.Authenticate(context.Background(), "invalid@example.com", "WrongPassword1")
		if err == nil {
			t.Fatalf("%s backend: expected authenticate error for invalid credentials", backend.name)
		}
	})

	t.Run("RefreshToken_InvalidToken_ReturnsError", func(t *testing.T) {
		m := backend.newManager(t)
		_, err := m.RefreshToken(context.Background(), "invalid-refresh-token")
		if err == nil {
			t.Fatalf("%s backend: expected refresh-token error for invalid token", backend.name)
		}
	})

	t.Run("Authenticate_Success_ReturnsTokens", func(t *testing.T) {
		if !backend.supportsSuccessfulAuth {
			t.Skip("successful auth contract skipped: set SUPABASE_TEST_EMAIL and SUPABASE_TEST_PASSWORD for integration backend")
		}
		m := backend.newManager(t)
		resp, err := m.Authenticate(context.Background(), backend.validAuthEmail, backend.validAuthPassword)
		if err != nil {
			t.Fatalf("%s backend: expected successful authenticate, got error: %v", backend.name, err)
		}
		if resp == nil || resp.AccessToken == "" {
			t.Fatalf("%s backend: expected non-empty access token", backend.name)
		}
		if resp.RefreshToken == "" {
			t.Fatalf("%s backend: expected non-empty refresh token", backend.name)
		}
	})
}

func TestSupabaseIdentityManager_Contract(t *testing.T) {
	for _, backendName := range selectedIdentityManagerBackends(t) {
		backendName := backendName
		t.Run(backendName, func(t *testing.T) {
			var backend contractBackend
			switch backendName {
			case "mock":
				backend = newMockContractBackend()
			case "integration":
				backend = newIntegrationContractBackend(t)
			default:
				t.Fatalf("unexpected backend: %s", backendName)
			}
			runIdentityManagerContractSuite(t, backend)
		})
	}
}
