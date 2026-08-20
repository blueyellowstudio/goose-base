package identityManager

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

type contractBackend struct {
	name                   string
	newManager             func(t *testing.T) IdentityManager
	validAuthEmail         string
	validAuthPassword      string
	supportsSuccessfulAuth bool
	// validOAuthCode and validOAuthVerifier are only meaningful when the backend can be
	// driven through a successful PKCE exchange, which a live Supabase project cannot be
	// from a test.
	validOAuthCode        string
	validOAuthVerifier    string
	supportsOAuthExchange bool
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
				case r.Method == http.MethodPost && r.URL.Path == "/auth/v1/token" && r.URL.Query().Get("grant_type") == "pkce":
					// The field names below are the wire contract with GoTrue. Getting
					// them wrong fails only against a real project, so pin them here.
					var req map[string]string
					_ = json.NewDecoder(r.Body).Decode(&req)
					if req["auth_code"] == "valid-auth-code" && req["code_verifier"] == "valid-verifier" {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(`{"access_token":"oauth-access","refresh_token":"oauth-refresh"}`))
						return
					}
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error_description":"invalid request: both auth code and code verifier should be non-empty"}`))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			t.Cleanup(ts.Close)
			return NewSupabaseIdentityManager(ts.URL, "service-key", "anon-key")
		},
		validAuthEmail:         "valid@example.com",
		validAuthPassword:      "Password1",
		supportsSuccessfulAuth: true,
		validOAuthCode:         "valid-auth-code",
		validOAuthVerifier:     "valid-verifier",
		supportsOAuthExchange:  true,
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
		validAuthEmail:         email,
		validAuthPassword:      password,
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

	t.Run("ExchangeOAuthCode_InvalidCode_ReturnsError", func(t *testing.T) {
		m := backend.newManager(t)
		_, err := m.ExchangeOAuthCode(context.Background(), "invalid-auth-code", "invalid-verifier")
		if err == nil {
			t.Fatalf("%s backend: expected an error for an invalid authorization code", backend.name)
		}
	})

	t.Run("ExchangeOAuthCode_Success_ReturnsTokens", func(t *testing.T) {
		if !backend.supportsOAuthExchange {
			t.Skip("successful PKCE exchange contract skipped: no usable authorization code for this backend")
		}
		m := backend.newManager(t)
		resp, err := m.ExchangeOAuthCode(context.Background(), backend.validOAuthCode, backend.validOAuthVerifier)
		if err != nil {
			t.Fatalf("%s backend: expected a successful exchange, got error: %v", backend.name, err)
		}
		if resp == nil || resp.AccessToken == "" || resp.RefreshToken == "" {
			t.Fatalf("%s backend: expected both tokens from the exchange, got %+v", backend.name, resp)
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

// newUsersListServer stands in for GoTrue's admin list-users endpoint, answering with
// the supplied JSON and recording the query it was called with.
func newUsersListServer(t *testing.T, body string, gotQuery *url.Values) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/v1/admin/users" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if gotQuery != nil {
			*gotQuery = r.URL.Query()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
}

func TestGetUserIdByEmail(t *testing.T) {
	const wantID = "7353c17e-c3d9-4baf-9b1f-9d7c97f71e93"

	t.Run("returns the id for a known address", func(t *testing.T) {
		var query url.Values
		server := newUsersListServer(t,
			`{"users":[{"id":"`+wantID+`","email":"known@example.com"}]}`, &query)
		defer server.Close()

		got, err := NewSupabaseIdentityManager(server.URL, "service", "anon").
			GetUserIdByEmail(context.Background(), "known@example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.String() != wantID {
			t.Fatalf("got %s, want %s", got, wantID)
		}

		// GoTrue ignores an unrecognised "email" parameter and answers with page 1 of
		// every user, so the parameter name is part of the contract, not a detail.
		if query.Get("filter") != "known@example.com" {
			t.Errorf("expected the address in filter=, got query %v", query)
		}
	})

	t.Run("matches the address case-insensitively", func(t *testing.T) {
		server := newUsersListServer(t,
			`{"users":[{"id":"`+wantID+`","email":"Known@Example.com"}]}`, nil)
		defer server.Close()

		if _, err := NewSupabaseIdentityManager(server.URL, "service", "anon").
			GetUserIdByEmail(context.Background(), "known@example.com"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("reports ErrUserNotFound for an empty result", func(t *testing.T) {
		server := newUsersListServer(t, `{"users":[]}`, nil)
		defer server.Close()

		_, err := NewSupabaseIdentityManager(server.URL, "service", "anon").
			GetUserIdByEmail(context.Background(), "nobody@example.com")
		if !errors.Is(err, ErrUserNotFound) {
			t.Fatalf("got %v, want ErrUserNotFound", err)
		}
	})

	// The filter matches loosely and this id decides which account a caller writes
	// against, so a non-matching result must not be trusted. Observed against a real
	// project: an unrecognised parameter returned three unrelated accounts.
	t.Run("rejects results whose address does not match", func(t *testing.T) {
		server := newUsersListServer(t, `{"users":[
			{"id":"`+wantID+`","email":"someone.else@example.com"},
			{"id":"618837e2-46e6-4ddd-b2ca-a2fdbfeab949","email":"third.party@example.com"}
		]}`, nil)
		defer server.Close()

		_, err := NewSupabaseIdentityManager(server.URL, "service", "anon").
			GetUserIdByEmail(context.Background(), "known@example.com")
		if !errors.Is(err, ErrUserNotFound) {
			t.Fatalf("got %v, want ErrUserNotFound for a non-matching address", err)
		}
	})

	t.Run("surfaces a non-200 as an error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"invalid service key"}`))
		}))
		defer server.Close()

		_, err := NewSupabaseIdentityManager(server.URL, "service", "anon").
			GetUserIdByEmail(context.Background(), "known@example.com")
		if err == nil {
			t.Fatal("expected an error")
		}
		if errors.Is(err, ErrUserNotFound) {
			t.Fatal("a failed call must not be reported as user-not-found")
		}
	})
}
