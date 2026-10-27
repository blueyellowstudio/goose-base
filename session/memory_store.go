package session

import (
	"context"
	"errors"
	"sync"
	"time"
)

var _ Store = (*MemoryStore)(nil)

// NewMemoryStore returns an empty store. Start Run to drop expired sessions.
func NewMemoryStore(cfg MemoryStoreConfig) *MemoryStore {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &MemoryStore{sessions: make(map[string]Session), now: now}
}

// Get returns a copy, so callers cannot change the stored session.
func (s *MemoryStore) Get(_ context.Context, id string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stored, found := s.sessions[id]
	if !found {
		return nil, ErrNotFound
	}
	return &stored, nil
}

// Put stores a copy of sess.
func (s *MemoryStore) Put(_ context.Context, sess *Session) error {
	if sess == nil {
		return errors.New("session: nil session")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[sess.ID] = *sess
	return nil
}

// Delete removes the session; an absent id is not an error.
func (s *MemoryStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, id)
	return nil
}

// Run removes expired sessions every interval until ctx is done. The caller starts it in a goroutine.
func (s *MemoryStore) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweep(ctx)
		}
	}
}

func (s *MemoryStore) sweep(context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	for id, sess := range s.sessions {
		if expired(sess.Tokens, now) {
			delete(s.sessions, id)
		}
	}
}

// MemoryStoreConfig configures NewMemoryStore.
type MemoryStoreConfig struct {
	Now func() time.Time // nil = time.Now
}

// MemoryStore is an in-process Store. Sessions are lost on restart and not shared between instances.
type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]Session
	now      func() time.Time
}
