package session

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryStorePutThenGet(t *testing.T) {
	store := NewMemoryStore(MemoryStoreConfig{Now: sessionTestClock(sessionTestT0)})
	refreshExpiresAt := sessionTestT0.Add(time.Hour)
	s := &Session{ID: "k1", Subject: "user-1", Tokens: sessionTestTokens(refreshExpiresAt), CreatedAt: sessionTestT0}

	if err := store.Put(t.Context(), s); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := store.Get(t.Context(), "k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if got.ID != "k1" {
		t.Errorf("ID = %q, want k1", got.ID)
	}
	if got.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", got.Subject)
	}
	if got.Tokens.RefreshToken != "refresh-1" {
		t.Errorf("RefreshToken = %q, want refresh-1", got.Tokens.RefreshToken)
	}
	if !got.Tokens.RefreshExpiresAt.Equal(refreshExpiresAt) {
		t.Errorf("RefreshExpiresAt = %v, want %v", got.Tokens.RefreshExpiresAt, refreshExpiresAt)
	}
	if !got.CreatedAt.Equal(sessionTestT0) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, sessionTestT0)
	}
}

func TestMemoryStoreGetUnknownAndDeleted(t *testing.T) {
	store := NewMemoryStore(MemoryStoreConfig{Now: sessionTestClock(sessionTestT0)})

	got, err := store.Get(t.Context(), "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing: err = %v, want ErrNotFound", err)
	}
	if got != nil {
		t.Errorf("Get missing: session = %+v, want nil", got)
	}

	s := &Session{ID: "k1", Subject: "user-1", Tokens: sessionTestTokens(sessionTestT0.Add(time.Hour)), CreatedAt: sessionTestT0}
	if err := store.Put(t.Context(), s); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := store.Delete(t.Context(), "k1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(t.Context(), "k1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after Delete: err = %v, want ErrNotFound", err)
	}
	if err := store.Delete(t.Context(), "k1"); err != nil {
		t.Errorf("second Delete: err = %v, want nil", err)
	}
}

func TestMemoryStorePutKeepsCopy(t *testing.T) {
	store := NewMemoryStore(MemoryStoreConfig{Now: sessionTestClock(sessionTestT0)})
	s := &Session{ID: "k1", Subject: "user-1", Tokens: sessionTestTokens(sessionTestT0.Add(time.Hour)), CreatedAt: sessionTestT0}
	if err := store.Put(t.Context(), s); err != nil {
		t.Fatalf("Put: %v", err)
	}

	s.Subject = "changed"
	s.Tokens.AccessToken = "changed"
	got, err := store.Get(t.Context(), "k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if got.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", got.Subject)
	}
	if got.Tokens.AccessToken != "access-1" {
		t.Errorf("AccessToken = %q, want access-1", got.Tokens.AccessToken)
	}
}

func TestMemoryStoreGetReturnsCopy(t *testing.T) {
	store := NewMemoryStore(MemoryStoreConfig{Now: sessionTestClock(sessionTestT0)})
	s := &Session{ID: "k1", Subject: "user-1", Tokens: sessionTestTokens(sessionTestT0.Add(time.Hour)), CreatedAt: sessionTestT0}
	if err := store.Put(t.Context(), s); err != nil {
		t.Fatalf("Put: %v", err)
	}
	first, err := store.Get(t.Context(), "k1")
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}

	first.Subject = "changed"
	first.Tokens.RefreshToken = "changed"
	second, err := store.Get(t.Context(), "k1")
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}

	if second.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", second.Subject)
	}
	if second.Tokens.RefreshToken != "refresh-1" {
		t.Errorf("RefreshToken = %q, want refresh-1", second.Tokens.RefreshToken)
	}
}

func TestMemoryStoreSweepRemovesExpired(t *testing.T) {
	store := NewMemoryStore(MemoryStoreConfig{Now: sessionTestClock(sessionTestT0)})
	sessionTestPutExpiringAt(t, store, "expired", sessionTestT0.Add(-time.Second))
	sessionTestPutExpiringAt(t, store, "boundary", sessionTestT0)
	sessionTestPutExpiringAt(t, store, "live", sessionTestT0.Add(time.Hour))

	store.sweep(t.Context())

	for _, id := range []string{"expired", "boundary"} {
		if _, err := store.Get(t.Context(), id); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get %q after sweep: err = %v, want ErrNotFound", id, err)
		}
	}
	live, err := store.Get(t.Context(), "live")
	if err != nil {
		t.Fatalf("Get live after sweep: %v", err)
	}
	if live.Subject != "user-live" {
		t.Errorf("live Subject = %q, want user-live", live.Subject)
	}
}

func TestMemoryStoreSweepUsesInjectedClock(t *testing.T) {
	injectedNow := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore(MemoryStoreConfig{Now: sessionTestClock(injectedNow)})
	sessionTestPutExpiringAt(t, store, "future", time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC))

	store.sweep(t.Context())

	if _, err := store.Get(t.Context(), "future"); err != nil {
		t.Errorf("Get future after sweep: err = %v, want found", err)
	}
}

func TestMemoryStoreRunSweepsOnTick(t *testing.T) {
	store := NewMemoryStore(MemoryStoreConfig{Now: sessionTestClock(sessionTestT0)})
	sessionTestPutExpiringAt(t, store, "expired", sessionTestT0.Add(-time.Second))
	sessionTestPutExpiringAt(t, store, "live", sessionTestT0.Add(time.Hour))
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	go store.Run(ctx, 10*time.Millisecond)

	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := store.Get(t.Context(), "expired")
		if errors.Is(err, ErrNotFound) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expired session still present after 2s, last Get err = %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := store.Get(t.Context(), "live"); err != nil {
		t.Errorf("Get live after Run sweep: err = %v, want found", err)
	}
}

func TestMemoryStoreRunStopsOnCancel(t *testing.T) {
	store := NewMemoryStore(MemoryStoreConfig{Now: sessionTestClock(sessionTestT0)})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		store.Run(ctx, time.Hour)
		close(done)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of cancel")
	}
}

func sessionTestPutExpiringAt(t *testing.T, store *MemoryStore, id string, refreshExpiresAt time.Time) {
	t.Helper()
	s := &Session{ID: id, Subject: "user-" + id, Tokens: sessionTestTokens(refreshExpiresAt), CreatedAt: sessionTestT0}
	if err := store.Put(t.Context(), s); err != nil {
		t.Fatalf("Put %q: %v", id, err)
	}
}
