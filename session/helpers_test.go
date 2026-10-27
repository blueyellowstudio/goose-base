package session

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var sessionTestT0 = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

func sessionTestClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// sessionTestKey is the store key computed independently of the code under test.
func sessionTestKey(cookieValue string) string {
	sum := sha256.Sum256([]byte(cookieValue))
	return hex.EncodeToString(sum[:])
}

// sessionTestCount reads the store size where no key is known to Get.
func sessionTestCount(s *MemoryStore) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

func sessionTestLockCount(m *Manager) int {
	m.locksMu.Lock()
	defer m.locksMu.Unlock()
	return len(m.locks)
}

// sessionTestTokens are issued at T0 with the access token valid for five minutes.
func sessionTestTokens(refreshExpiresAt time.Time) Tokens {
	return Tokens{
		AccessToken:      "access-1",
		RefreshToken:     "refresh-1",
		IssuedAt:         sessionTestT0,
		AccessExpiresAt:  sessionTestT0.Add(5 * time.Minute),
		RefreshExpiresAt: refreshExpiresAt,
	}
}

// sessionTestManager returns a Manager and its MemoryStore on the fixed clock with a nil Refresher.
func sessionTestManager(t *testing.T) (*Manager, *MemoryStore) {
	t.Helper()
	cfg := Config{Now: sessionTestClock(sessionTestT0)}
	store := NewMemoryStore(MemoryStoreConfig{Now: cfg.Now})
	return NewManager(store, nil, cfg), store
}

func sessionTestSetCookies(t *testing.T, rec *httptest.ResponseRecorder) []*http.Cookie {
	t.Helper()
	var cookies []*http.Cookie
	for _, header := range rec.Header().Values("Set-Cookie") {
		cookie, err := http.ParseSetCookie(header)
		if err != nil {
			t.Fatalf("parse Set-Cookie %q: %v", header, err)
		}
		cookies = append(cookies, cookie)
	}
	return cookies
}

// sessionTestRequest builds a GET / and adds c by name and value when c is not nil.
func sessionTestRequest(t *testing.T, c *http.Cookie) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	if c != nil {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	return req
}
