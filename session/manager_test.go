package session

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCreateSetsSessionCookie(t *testing.T) {
	m, store := sessionTestManager(t)
	tokens := sessionTestTokens(sessionTestT0.Add(30 * time.Minute))
	rec := httptest.NewRecorder()

	if err := m.Create(t.Context(), rec, "user-1", tokens); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if got := len(rec.Header().Values("Set-Cookie")); got != 1 {
		t.Fatalf("Set-Cookie headers = %d, want 1", got)
	}
	cookie := sessionTestSetCookies(t, rec)[0]
	if cookie.Name != "session" {
		t.Errorf("Name = %q, want session", cookie.Name)
	}
	if cookie.Path != "/" {
		t.Errorf("Path = %q, want /", cookie.Path)
	}
	if !cookie.HttpOnly {
		t.Error("HttpOnly = false, want true")
	}
	if !cookie.Secure {
		t.Error("Secure = false, want true")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", cookie.SameSite)
	}
	if cookie.MaxAge != 1800 {
		t.Errorf("MaxAge = %d, want 1800", cookie.MaxAge)
	}
	raw, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		t.Fatalf("cookie value is not raw base64url: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("decoded cookie value = %d bytes, want 32", len(raw))
	}

	key := sessionTestKey(cookie.Value)
	got, err := store.Get(t.Context(), key)
	if err != nil {
		t.Fatalf("store.Get(key): %v", err)
	}
	if got.ID != key {
		t.Errorf("ID = %q, want %q", got.ID, key)
	}
	if got.ID == cookie.Value {
		t.Error("ID equals the cookie value, want its hash")
	}
	if got.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", got.Subject)
	}
	if got.Tokens != tokens {
		t.Errorf("Tokens = %+v, want %+v", got.Tokens, tokens)
	}
	if !got.CreatedAt.Equal(sessionTestT0) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, sessionTestT0)
	}
}

func TestCreateUsesConfiguredCookieName(t *testing.T) {
	store := NewMemoryStore(MemoryStoreConfig{Now: sessionTestClock(sessionTestT0)})
	m := NewManager(store, nil, Config{CookieName: "sid", Now: sessionTestClock(sessionTestT0)})
	rec := httptest.NewRecorder()

	if err := m.Create(t.Context(), rec, "user-1", sessionTestTokens(sessionTestT0.Add(time.Hour))); err != nil {
		t.Fatalf("Create: %v", err)
	}

	cookies := sessionTestSetCookies(t, rec)
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie headers = %d, want 1", len(cookies))
	}
	if cookies[0].Name != "sid" {
		t.Errorf("Name = %q, want sid", cookies[0].Name)
	}
}

func TestCreateTwiceGivesDistinctSessions(t *testing.T) {
	m, store := sessionTestManager(t)
	tokens := sessionTestTokens(sessionTestT0.Add(time.Hour))
	rec1 := httptest.NewRecorder()
	rec2 := httptest.NewRecorder()

	if err := m.Create(t.Context(), rec1, "user-1", tokens); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if err := m.Create(t.Context(), rec2, "user-1", tokens); err != nil {
		t.Fatalf("second Create: %v", err)
	}

	first := sessionTestSetCookies(t, rec1)[0]
	second := sessionTestSetCookies(t, rec2)[0]
	if first.Value == second.Value {
		t.Error("two Creates returned the same cookie value")
	}
	if got := sessionTestCount(store); got != 2 {
		t.Errorf("store count = %d, want 2", got)
	}
	for _, c := range []*http.Cookie{first, second} {
		if _, err := store.Get(t.Context(), sessionTestKey(c.Value)); err != nil {
			t.Errorf("store.Get(key of %q): %v", c.Value, err)
		}
	}
}

func TestCreateRefusesExpiredRefreshToken(t *testing.T) {
	tests := []struct {
		name             string
		refreshExpiresAt time.Time
		wantExpired      bool
		wantMaxAge       int
	}{
		{name: "equal to now", refreshExpiresAt: sessionTestT0, wantExpired: true},
		{name: "before now", refreshExpiresAt: sessionTestT0.Add(-time.Second), wantExpired: true},
		{name: "control: 1 s left", refreshExpiresAt: sessionTestT0.Add(time.Second), wantMaxAge: 1},
		{name: "control: 500 ms left", refreshExpiresAt: sessionTestT0.Add(500 * time.Millisecond), wantMaxAge: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, store := sessionTestManager(t)
			rec := httptest.NewRecorder()

			err := m.Create(t.Context(), rec, "user-1", sessionTestTokens(tt.refreshExpiresAt))

			if tt.wantExpired {
				if !errors.Is(err, ErrRefreshExpired) {
					t.Fatalf("err = %v, want ErrRefreshExpired", err)
				}
				if got := len(rec.Header().Values("Set-Cookie")); got != 0 {
					t.Errorf("Set-Cookie headers = %d, want 0", got)
				}
				if got := sessionTestCount(store); got != 0 {
					t.Errorf("store count = %d, want 0", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			cookies := sessionTestSetCookies(t, rec)
			if len(cookies) != 1 {
				t.Fatalf("Set-Cookie headers = %d, want 1", len(cookies))
			}
			if got := sessionTestCount(store); got != 1 {
				t.Errorf("store count = %d, want 1", got)
			}
			if cookies[0].MaxAge != tt.wantMaxAge {
				t.Errorf("MaxAge = %d, want %d", cookies[0].MaxAge, tt.wantMaxAge)
			}
		})
	}
}

func TestDestroyDeletesAndClearsCookie(t *testing.T) {
	m, store := sessionTestManager(t)
	rec1 := httptest.NewRecorder()
	if err := m.Create(t.Context(), rec1, "user-1", sessionTestTokens(sessionTestT0.Add(time.Hour))); err != nil {
		t.Fatalf("Create: %v", err)
	}
	created := sessionTestSetCookies(t, rec1)[0]
	req := sessionTestRequest(t, created)
	rec2 := httptest.NewRecorder()

	got, err := m.Destroy(t.Context(), rec2, req)

	if err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	key := sessionTestKey(created.Value)
	if got == nil {
		t.Fatal("Destroy returned a nil session")
	}
	if got.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", got.Subject)
	}
	if got.Tokens.RefreshToken != "refresh-1" {
		t.Errorf("RefreshToken = %q, want refresh-1", got.Tokens.RefreshToken)
	}
	if got.ID != key {
		t.Errorf("ID = %q, want %q", got.ID, key)
	}
	if _, err := store.Get(t.Context(), key); !errors.Is(err, ErrNotFound) {
		t.Errorf("store.Get after Destroy: err = %v, want ErrNotFound", err)
	}

	cookies := sessionTestSetCookies(t, rec2)
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie headers on Destroy = %d, want 1", len(cookies))
	}
	cleared := cookies[0]
	if cleared.Name != created.Name {
		t.Errorf("cleared Name = %q, want %q", cleared.Name, created.Name)
	}
	if cleared.Path != created.Path {
		t.Errorf("cleared Path = %q, want %q", cleared.Path, created.Path)
	}
	if cleared.Secure != created.Secure {
		t.Errorf("cleared Secure = %v, want %v", cleared.Secure, created.Secure)
	}
	if cleared.SameSite != created.SameSite {
		t.Errorf("cleared SameSite = %v, want %v", cleared.SameSite, created.SameSite)
	}
	if cleared.HttpOnly != created.HttpOnly {
		t.Errorf("cleared HttpOnly = %v, want %v", cleared.HttpOnly, created.HttpOnly)
	}
	if cleared.Value != "" {
		t.Errorf("cleared Value = %q, want empty", cleared.Value)
	}
	if cleared.MaxAge != -1 {
		t.Errorf("cleared MaxAge = %d, want -1", cleared.MaxAge)
	}
}

func TestDestroyWithoutSession(t *testing.T) {
	t.Run("no cookie", func(t *testing.T) {
		m, _ := sessionTestManager(t)
		rec := httptest.NewRecorder()

		got, err := m.Destroy(t.Context(), rec, sessionTestRequest(t, nil))

		if got != nil || err != nil {
			t.Errorf("Destroy = (%+v, %v), want (nil, nil)", got, err)
		}
		if n := len(rec.Header().Values("Set-Cookie")); n != 0 {
			t.Errorf("Set-Cookie headers = %d, want 0", n)
		}
	})

	t.Run("unknown cookie", func(t *testing.T) {
		m, _ := sessionTestManager(t)
		rec := httptest.NewRecorder()
		req := sessionTestRequest(t, &http.Cookie{Name: "session", Value: "not-a-known-session"})

		got, err := m.Destroy(t.Context(), rec, req)

		if got != nil || err != nil {
			t.Errorf("Destroy = (%+v, %v), want (nil, nil)", got, err)
		}
		cookies := sessionTestSetCookies(t, rec)
		if len(cookies) != 1 {
			t.Fatalf("Set-Cookie headers = %d, want 1", len(cookies))
		}
		if cookies[0].Name != "session" {
			t.Errorf("Name = %q, want session", cookies[0].Name)
		}
		if cookies[0].MaxAge != -1 {
			t.Errorf("MaxAge = %d, want -1", cookies[0].MaxAge)
		}
	})

	t.Run("other cookie name", func(t *testing.T) {
		m, store := sessionTestManager(t)
		createRec := httptest.NewRecorder()
		if err := m.Create(t.Context(), createRec, "user-1", sessionTestTokens(sessionTestT0.Add(time.Hour))); err != nil {
			t.Fatalf("Create: %v", err)
		}
		created := sessionTestSetCookies(t, createRec)[0]
		req := sessionTestRequest(t, &http.Cookie{Name: "other", Value: created.Value})

		got, err := m.Destroy(t.Context(), httptest.NewRecorder(), req)

		if got != nil || err != nil {
			t.Errorf("Destroy = (%+v, %v), want (nil, nil)", got, err)
		}
		if _, err := store.Get(t.Context(), sessionTestKey(created.Value)); err != nil {
			t.Errorf("session gone after Destroy under another name: %v", err)
		}
	})
}

func TestDestroyWaitsForSameKeyLock(t *testing.T) {
	m, store := sessionTestManager(t)
	created := sessionTestCreate(t, m)
	key := sessionTestKey(created.Value)
	unlock := m.lockKey(key)
	done := make(chan struct{})
	destroyErr := make(chan error, 1)
	go func() {
		_, err := m.Destroy(t.Context(), httptest.NewRecorder(), sessionTestRequest(t, created))
		destroyErr <- err
		close(done)
	}()

	select {
	case <-done:
		unlock()
		t.Fatal("Destroy finished while the same key was locked")
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := store.Get(t.Context(), key); err != nil {
		t.Errorf("session gone while the key was locked: %v", err)
	}

	unlock()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Destroy did not finish within 2s of unlock")
	}
	if _, err := store.Get(t.Context(), key); !errors.Is(err, ErrNotFound) {
		t.Errorf("store.Get after Destroy: err = %v, want ErrNotFound", err)
	}
	if err := <-destroyErr; err != nil {
		t.Errorf("Destroy err = %v, want nil", err)
	}
}

func TestDestroyDoesNotWaitForOtherKeyLock(t *testing.T) {
	m, store := sessionTestManager(t)
	createdA := sessionTestCreate(t, m)
	createdB := sessionTestCreate(t, m)
	unlockA := m.lockKey(sessionTestKey(createdA.Value))
	defer unlockA()
	done := make(chan struct{})
	go func() {
		_, _ = m.Destroy(t.Context(), httptest.NewRecorder(), sessionTestRequest(t, createdB))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Destroy of B blocked on the lock of A")
	}
	if _, err := store.Get(t.Context(), sessionTestKey(createdB.Value)); !errors.Is(err, ErrNotFound) {
		t.Errorf("store.Get(B) after Destroy: err = %v, want ErrNotFound", err)
	}
}

func TestDestroyReleasesLockEntry(t *testing.T) {
	m, _ := sessionTestManager(t)
	for range 2 {
		created := sessionTestCreate(t, m)
		if _, err := m.Destroy(t.Context(), httptest.NewRecorder(), sessionTestRequest(t, created)); err != nil {
			t.Fatalf("Destroy: %v", err)
		}
	}
	unknown := &http.Cookie{Name: "session", Value: "not-a-known-session"}
	if _, err := m.Destroy(t.Context(), httptest.NewRecorder(), sessionTestRequest(t, unknown)); err != nil {
		t.Fatalf("Destroy unknown: %v", err)
	}

	if got := sessionTestLockCount(m); got != 0 {
		t.Errorf("lock entries = %d, want 0", got)
	}
}

func TestFromContext(t *testing.T) {
	got, ok := FromContext(t.Context())
	if got != nil || ok {
		t.Errorf("FromContext(empty) = (%+v, %v), want (nil, false)", got, ok)
	}

	s := &Session{ID: "k", Subject: "user-1"}
	got, ok = FromContext(withSession(t.Context(), s))
	if !ok {
		t.Fatal("FromContext(withSession) ok = false, want true")
	}
	if got.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", got.Subject)
	}
	if got.ID != "k" {
		t.Errorf("ID = %q, want k", got.ID)
	}
}

// sessionTestCreate creates a session for user-1 and returns its Set-Cookie.
func sessionTestCreate(t *testing.T, m *Manager) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := m.Create(t.Context(), rec, "user-1", sessionTestTokens(sessionTestT0.Add(time.Hour))); err != nil {
		t.Fatalf("Create: %v", err)
	}
	return sessionTestSetCookies(t, rec)[0]
}
