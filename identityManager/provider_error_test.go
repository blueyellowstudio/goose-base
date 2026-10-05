package identityManager

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newAnswerServer(status int, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestErrorAnswerKeepsProviderStatus(t *testing.T) {
	cases := map[string]struct {
		status        int
		body          string
		wantMessage   string
		isUnavailable bool
	}{
		"refused refresh token": {
			status:      http.StatusBadRequest,
			body:        `{"error":"invalid_grant","error_description":"Invalid Refresh Token: Already Used"}`,
			wantMessage: "supabase refresh token: Invalid Refresh Token: Already Used",
		},
		"server error": {
			status:        http.StatusInternalServerError,
			body:          `{"message":"database unavailable"}`,
			wantMessage:   "supabase refresh token: database unavailable",
			isUnavailable: true,
		},
		"rate limit without a JSON body": {
			status:        http.StatusTooManyRequests,
			body:          "slow down",
			wantMessage:   "supabase refresh token: status 429: slow down",
			isUnavailable: true,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			server := newAnswerServer(tc.status, tc.body)
			defer server.Close()

			_, err := NewSupabaseIdentityManager(server.URL, "service", "anon").
				RefreshToken(context.Background(), "refresh-token")

			var providerErr *ProviderError
			if !errors.As(err, &providerErr) {
				t.Fatalf("got %v, want a *ProviderError", err)
			}
			if providerErr.StatusCode != tc.status {
				t.Errorf("got status %d, want %d", providerErr.StatusCode, tc.status)
			}
			if err.Error() != tc.wantMessage {
				t.Errorf("got message %q, want %q", err.Error(), tc.wantMessage)
			}
			if got := IsUnavailable(err); got != tc.isUnavailable {
				t.Errorf("got IsUnavailable %v, want %v", got, tc.isUnavailable)
			}
		})
	}
}

func TestAdminErrorAnswerKeepsProviderStatus(t *testing.T) {
	server := newAnswerServer(http.StatusServiceUnavailable, `{"message":"maintenance"}`)
	defer server.Close()

	_, err := NewSupabaseIdentityManager(server.URL, "service", "anon").
		GetUserIdByEmail(context.Background(), "someone@example.com")

	var providerErr *ProviderError
	if !errors.As(err, &providerErr) || providerErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("got %v, want a *ProviderError with status 503", err)
	}
	if !IsUnavailable(err) {
		t.Error("got IsUnavailable false for a 503")
	}
}

func TestUnreachableProviderIsUnavailable(t *testing.T) {
	server := newAnswerServer(http.StatusOK, "{}")
	server.Close()

	_, err := NewSupabaseIdentityManager(server.URL, "service", "anon").
		RefreshToken(context.Background(), "refresh-token")

	if err == nil || !IsUnavailable(err) {
		t.Fatalf("got %v, want an unavailable provider", err)
	}
}

func TestOtherErrorsAreNotUnavailable(t *testing.T) {
	if IsUnavailable(errors.New("token has no user id")) {
		t.Error("got IsUnavailable true for an error that never reached the provider")
	}
	if IsUnavailable(nil) {
		t.Error("got IsUnavailable true for nil")
	}
}
