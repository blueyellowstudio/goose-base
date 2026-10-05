package identityManager

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// ProviderError is an error answer of the identity provider. It keeps the HTTP status, so
// a caller can tell a refused request (4xx) from an outage of the provider (5xx, 429).
type ProviderError struct {
	Operation  string
	StatusCode int
	Message    string
}

func (e *ProviderError) Error() string {
	return fmt.Sprintf("%s: %s", e.Operation, e.Message)
}

// IsUnavailable reports a failure that says nothing about the caller's input: the provider
// was not reachable, failed itself, or limited the rate. A caller must not treat such a
// failure as refused credentials.
func IsUnavailable(err error) bool {
	var transportErr *url.Error
	if errors.As(err, &transportErr) {
		return true
	}

	var providerErr *ProviderError
	if errors.As(err, &providerErr) {
		return providerErr.StatusCode >= http.StatusInternalServerError || providerErr.StatusCode == http.StatusTooManyRequests
	}
	return false
}
