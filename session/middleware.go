package session

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"time"
)

const refreshUnavailableMessage = "session refresh unavailable"

// refreshResult is what one caller learns from a refresh. ran is true only for the caller whose
// own flight called the Refresher, so only that caller's response carries the new cookie.
type refreshResult struct {
	session *Session
	ran     bool
	err     error
}

// Middleware resolves the session for every request and refreshes its tokens when needed (D4).
// It never rejects a request for lacking a session, so the application's own auth middleware
// decides; its only own answer is the 503 of a refresh that failed while the access token is
// already unusable.
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(m.cookieName)
		if err != nil || cookie.Value == "" {
			next.ServeHTTP(w, r)
			return
		}

		key := storeKey(cookie.Value)
		s, err := m.store.Get(r.Context(), key)
		if errors.Is(err, ErrNotFound) {
			next.ServeHTTP(w, r)
			return
		}
		if err != nil {
			m.logger.Error("session lookup failed", "session", key[:8], "err", err)
			next.ServeHTTP(w, r)
			return
		}

		if !m.needsRefresh(s.Tokens, m.now()) {
			next.ServeHTTP(w, r.WithContext(withSession(r.Context(), s)))
			return
		}
		m.serveRefreshed(w, r, next, cookie.Value, s)
	})
}

// needsRefresh caps the window at half the access token's lifetime, so a provider that issues
// short-lived tokens does not get a refresh on every request (DA3). A zero IssuedAt means the
// lifetime is unknown and the window stays RefreshAhead.
func (m *Manager) needsRefresh(t Tokens, now time.Time) bool {
	window := m.refreshAhead
	if !t.IssuedAt.IsZero() {
		window = min(window, t.AccessExpiresAt.Sub(t.IssuedAt)/2)
	}
	return t.AccessExpiresAt.Sub(now) <= window
}

func (m *Manager) serveRefreshed(w http.ResponseWriter, r *http.Request, next http.Handler, cookieValue string, own *Session) {
	key := storeKey(cookieValue)
	res := m.refresh(r.Context(), key)
	now := m.now()

	switch {
	case errors.Is(res.err, ErrRefreshRejected):
		// Every caller that shares the flight clears the cookie on its own response.
		m.logger.Info("session refresh rejected, session ended", "session", key[:8])
		m.clearCookie(w)
		next.ServeHTTP(w, r)
	case res.err != nil:
		m.serveAfterFailedRefresh(w, r, next, key, cmp.Or(res.session, own), now)
	case res.session == nil:
		next.ServeHTTP(w, r)
	default:
		if res.ran {
			m.setCookie(w, cookieValue, maxAgeUntil(res.session.Tokens.RefreshExpiresAt, now))
		}
		next.ServeHTTP(w, r.WithContext(withSession(r.Context(), res.session)))
	}
}

// serveAfterFailedRefresh keeps the request alive while the access token still works. The
// provider error is never logged: it can echo a token.
func (m *Manager) serveAfterFailedRefresh(w http.ResponseWriter, r *http.Request, next http.Handler, key string, s *Session, now time.Time) {
	if s.Tokens.AccessExpiresAt.After(now) {
		m.logger.Warn("session refresh failed, continuing with the current access token", "session", key[:8])
		next.ServeHTTP(w, r.WithContext(withSession(r.Context(), s)))
		return
	}

	m.logger.Error(refreshUnavailableMessage, "session", key[:8], "status", http.StatusServiceUnavailable, "path", r.URL.Path)
	http.Error(w, refreshUnavailableMessage, http.StatusServiceUnavailable)
}

// refresh runs at most one flight per session at a time. Each caller passes its own closure so
// ran stays local to the caller that executed it; singleflight's shared flag would also be true
// for the caller that ran the flight when others joined it.
func (m *Manager) refresh(reqCtx context.Context, key string) refreshResult {
	ran := false
	value, err, _ := m.group.Do(key, func() (any, error) {
		s, called, err := m.refreshLocked(reqCtx, key)
		ran = called
		return s, err
	})
	s, _ := value.(*Session)
	return refreshResult{session: s, ran: ran, err: err}
}

// refreshLocked detaches from the request context: the provider may rotate the refresh token,
// so abandoning the call when the first caller disconnects would lose the new token. The key
// lock is held from Get through Put so that Destroy waits for the refresh (DA4).
//
// The returned session is nil when the session no longer exists or the provider rejected the
// refresh token; otherwise it is the stored copy or the new session. called reports whether
// the Refresher was called.
func (m *Manager) refreshLocked(reqCtx context.Context, key string) (s *Session, called bool, err error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), m.refreshTimeout)
	defer cancel()

	unlock := m.lockKey(key)
	defer unlock()

	cur, err := m.store.Get(ctx, key)
	if errors.Is(err, ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		m.logger.Error("session lookup failed", "session", key[:8], "err", err)
		return nil, false, err
	}
	// A request that arrived before another flight finished sees the already refreshed tokens.
	if !m.needsRefresh(cur.Tokens, m.now()) {
		return cur, false, nil
	}
	if m.refresher == nil {
		return cur, false, errNoRefresher
	}

	tokens, err := m.refresher.Refresh(ctx, cur.Tokens.RefreshToken)
	if errors.Is(err, ErrRefreshRejected) {
		if deleteErr := m.store.Delete(ctx, key); deleteErr != nil {
			m.logger.Error("session delete after rejected refresh failed", "session", key[:8], "err", deleteErr)
		}
		return nil, true, ErrRefreshRejected
	}
	if err != nil {
		return cur, true, err
	}

	// Without rotation the provider returns no refresh token, and its RefreshExpiresAt then
	// describes no token: keep both of the stored one, or the cookie would outlive the token.
	if tokens.RefreshToken == "" {
		tokens.RefreshToken = cur.Tokens.RefreshToken
		tokens.RefreshExpiresAt = cur.Tokens.RefreshExpiresAt
	}
	// A new value: concurrent readers may still hold cur.
	refreshed := &Session{ID: cur.ID, Subject: cur.Subject, Tokens: tokens, CreatedAt: cur.CreatedAt}
	if err := m.store.Put(ctx, refreshed); err != nil {
		m.logger.Error("session store after refresh failed", "session", key[:8], "err", err)
		return cur, true, err
	}
	return refreshed, true, nil
}
