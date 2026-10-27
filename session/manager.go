package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	DefaultCookieName   = "session"
	DefaultRefreshAhead = 30 * time.Second
	// DefaultRefreshTimeout bounds one refresh, which runs detached from the request that started it.
	DefaultRefreshTimeout = 15 * time.Second
)

// NewManager applies the Config defaults. refresher may be nil while nothing refreshes tokens.
func NewManager(store Store, refresher Refresher, cfg Config) *Manager {
	m := &Manager{
		store:          store,
		refresher:      refresher,
		cookieName:     cfg.CookieName,
		refreshAhead:   cfg.RefreshAhead,
		refreshTimeout: cfg.RefreshTimeout,
		logger:         cfg.Logger,
		now:            cfg.Now,
		locks:          make(map[string]*keyLock),
	}
	if m.cookieName == "" {
		m.cookieName = DefaultCookieName
	}
	if m.refreshAhead == 0 {
		m.refreshAhead = DefaultRefreshAhead
	}
	if m.refreshTimeout == 0 {
		m.refreshTimeout = DefaultRefreshTimeout
	}
	if m.logger == nil {
		m.logger = slog.Default()
	}
	if m.now == nil {
		m.now = time.Now
	}
	return m
}

// Create stores a new session under a fresh cookie value and sets the cookie on w.
// It returns ErrRefreshExpired, without side effects, when the refresh token is already expired.
func (m *Manager) Create(ctx context.Context, w http.ResponseWriter, subject string, t Tokens) error {
	now := m.now()
	if expired(t, now) {
		return ErrRefreshExpired
	}

	value, err := newCookieValue()
	if err != nil {
		return fmt.Errorf("session: create cookie value: %w", err)
	}
	key := storeKey(value)
	if err := m.store.Put(ctx, &Session{ID: key, Subject: subject, Tokens: t, CreatedAt: now}); err != nil {
		return fmt.Errorf("session: store put: %w", err)
	}

	m.setCookie(w, value, maxAgeUntil(t.RefreshExpiresAt, now))
	return nil
}

// Destroy deletes the session of the request cookie and clears the cookie on w.
// It returns the deleted session, or (nil, nil) when the request has none. A cookie
// whose session is unknown is still cleared, so a stale browser cookie goes away.
func (m *Manager) Destroy(ctx context.Context, w http.ResponseWriter, r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(m.cookieName)
	if err != nil || cookie.Value == "" {
		return nil, nil
	}

	key := storeKey(cookie.Value)
	unlock := m.lockKey(key)
	defer unlock()

	s, err := m.store.Get(ctx, key)
	if errors.Is(err, ErrNotFound) {
		m.clearCookie(w)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("session: store get: %w", err)
	}
	if err := m.store.Delete(ctx, key); err != nil {
		return nil, fmt.Errorf("session: store delete: %w", err)
	}

	m.clearCookie(w)
	return s, nil
}

// FromContext returns the session that the middleware put into ctx.
func FromContext(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(contextKey{}).(*Session)
	return s, ok
}

// lockKey serializes work on one session. The entry is reference counted and removed with the
// last unlock, so memory stays bounded by the keys locked right now (DA4).
func (m *Manager) lockKey(key string) (unlock func()) {
	m.locksMu.Lock()
	lock, found := m.locks[key]
	if !found {
		lock = &keyLock{}
		m.locks[key] = lock
	}
	lock.refs++
	m.locksMu.Unlock()

	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()

		m.locksMu.Lock()
		defer m.locksMu.Unlock()
		lock.refs--
		if lock.refs == 0 {
			delete(m.locks, key)
		}
	}
}

func withSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, contextKey{}, s)
}

func newCookieValue() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func storeKey(cookieValue string) string {
	sum := sha256.Sum256([]byte(cookieValue))
	return hex.EncodeToString(sum[:])
}

// Config configures NewManager.
type Config struct {
	CookieName     string           // "" = DefaultCookieName
	RefreshAhead   time.Duration    // 0 = DefaultRefreshAhead
	RefreshTimeout time.Duration    // 0 = DefaultRefreshTimeout
	Logger         *slog.Logger     // nil = slog.Default()
	Now            func() time.Time // nil = time.Now
}

// Manager creates and destroys sessions and sets their cookie.
type Manager struct {
	store          Store
	refresher      Refresher
	cookieName     string
	refreshAhead   time.Duration
	refreshTimeout time.Duration
	logger         *slog.Logger
	now            func() time.Time
	locksMu        sync.Mutex
	locks          map[string]*keyLock
	group          singleflight.Group
}

type keyLock struct {
	mu   sync.Mutex
	refs int
}

type contextKey struct{}
