package session

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMiddlewareWithoutSession(t *testing.T) {
	cases := map[string]*http.Cookie{
		"no cookie":      nil,
		"unknown cookie": {Name: "session", Value: "not-a-known-session"},
	}
	for name, cookie := range cases {
		t.Run(name, func(t *testing.T) {
			env := sessionMwSetup(t, nil, sessionTestTokens(sessionTestT0.Add(30*time.Minute)))
			env.clock.Set(sessionMwExpired)
			seen := &sessionMwSeen{}

			rec := env.serveRequest(sessionTestRequest(t, cookie), seen)

			sessionMwRequireStatus(t, rec, http.StatusOK)
			sessionMwRequireAccess(t, seen, "")
			sessionMwRequireSetCookieCount(t, rec, 0)
			sessionMwRequireCalls(t, env.refresher, 0)
		})
	}
}

func TestMiddlewareValidTokenNoRefresh(t *testing.T) {
	env := sessionMwSetup(t, nil, sessionTestTokens(sessionTestT0.Add(30*time.Minute)))
	env.clock.Set(sessionMwValid)
	seen := &sessionMwSeen{}

	rec := env.serve(t.Context(), t, seen)

	sessionMwRequireAccess(t, seen, "access-1")
	sessionMwRequireCalls(t, env.refresher, 0)
	sessionMwRequireSetCookieCount(t, rec, 0)
}

func TestMiddlewareRefreshesInsideWindow(t *testing.T) {
	env := sessionMwSetup(t, nil, sessionTestTokens(sessionTestT0.Add(30*time.Minute)))
	env.clock.Set(sessionMwInsideWindow)
	now := sessionMwInsideWindow
	seen := &sessionMwSeen{}

	rec := env.serve(t.Context(), t, seen)

	sessionMwRequireCalls(t, env.refresher, 1)
	if got := env.refresher.Received(); !slices.Equal(got, []string{"refresh-1"}) {
		t.Errorf("Received = %q, want [refresh-1]", got)
	}
	stored := env.stored(t)
	if stored.Tokens.AccessToken != "access-2" {
		t.Errorf("AccessToken = %q, want access-2", stored.Tokens.AccessToken)
	}
	if stored.Tokens.RefreshToken != "refresh-2" {
		t.Errorf("RefreshToken = %q, want refresh-2", stored.Tokens.RefreshToken)
	}
	if want := now.Add(5 * time.Minute); !stored.Tokens.AccessExpiresAt.Equal(want) {
		t.Errorf("AccessExpiresAt = %v, want %v", stored.Tokens.AccessExpiresAt, want)
	}
	if want := now.Add(30 * time.Minute); !stored.Tokens.RefreshExpiresAt.Equal(want) {
		t.Errorf("RefreshExpiresAt = %v, want %v", stored.Tokens.RefreshExpiresAt, want)
	}
	if stored.ID != env.key {
		t.Errorf("ID = %q, want %q", stored.ID, env.key)
	}
	if stored.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", stored.Subject)
	}
	if !stored.CreatedAt.Equal(sessionTestT0) {
		t.Errorf("CreatedAt = %v, want %v", stored.CreatedAt, sessionTestT0)
	}

	sessionMwRequireSetCookieCount(t, rec, 1)
	cookie := sessionTestSetCookies(t, rec)[0]
	if cookie.Name != "session" {
		t.Errorf("Name = %q, want session", cookie.Name)
	}
	if cookie.Value != env.cookie.Value {
		t.Errorf("Value = %q, want the original cookie value", cookie.Value)
	}
	if cookie.MaxAge != 1800 {
		t.Errorf("MaxAge = %d, want 1800", cookie.MaxAge)
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
	sessionMwRequireAccess(t, seen, "access-2")
}

func TestMiddlewareConcurrentRequestsRefreshOnce(t *testing.T) {
	const requests = 50
	env := sessionMwSetup(t, nil, sessionTestTokens(sessionTestT0.Add(30*time.Minute)))
	env.clock.Set(sessionMwExpired)
	env.hooks.barrier = requests
	env.hooks.released = make(chan struct{})
	seen := &sessionMwSeen{}
	recorders := make([]*httptest.ResponseRecorder, requests)

	var wg sync.WaitGroup
	for i := range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			recorders[i] = env.serve(t.Context(), t, seen)
		}()
	}
	allDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(allDone)
	}()
	select {
	case <-allDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the 50 requests")
	}

	sessionMwRequireCalls(t, env.refresher, 1)
	got := seen.Access()
	if len(got) != requests {
		t.Fatalf("next ran %d times, want %d", len(got), requests)
	}
	for _, access := range got {
		if access != "access-2" {
			t.Fatalf("next saw access token %q, want access-2 in every request", access)
		}
	}
	withCookie := 0
	for _, rec := range recorders {
		headers := len(rec.Header().Values("Set-Cookie"))
		if headers > 1 {
			t.Errorf("a response has %d Set-Cookie headers, want at most 1", headers)
		}
		if headers == 1 {
			withCookie++
		}
	}
	if withCookie != 1 {
		t.Errorf("responses with Set-Cookie = %d, want exactly 1", withCookie)
	}
}

func TestMiddlewareLateArrivalDoesNotRefreshAgain(t *testing.T) {
	env := sessionMwSetup(t, nil, sessionTestTokens(sessionTestT0.Add(30*time.Minute)))
	env.clock.Set(sessionMwExpired)
	env.serve(t.Context(), t, &sessionMwSeen{})
	sessionMwRequireCalls(t, env.refresher, 1)
	env.hooks.staleNext = &env.original
	seen2 := &sessionMwSeen{}

	rec2 := env.serve(t.Context(), t, seen2)

	sessionMwRequireCalls(t, env.refresher, 1)
	sessionMwRequireAccess(t, seen2, "access-2")
	sessionMwRequireSetCookieCount(t, rec2, 0)
}

func TestMiddlewareCancelledExecutorStillRefreshes(t *testing.T) {
	env := sessionMwSetup(t, nil, sessionTestTokens(sessionTestT0.Add(30*time.Minute)))
	release := sessionMwBlockRefresher(t, env.refresher)
	env.refresher.entered = make(chan struct{}, 1)
	env.clock.Set(sessionMwExpired)
	ctxA, cancelA := context.WithCancel(t.Context())
	defer cancelA()
	seenB := &sessionMwSeen{}

	doneA := sessionMwGo(func() { env.serve(ctxA, t, &sessionMwSeen{}) })
	sessionMwRequireSignal(t, env.refresher.entered, "the refresh to start")
	doneB := sessionMwGo(func() { env.serve(t.Context(), t, seenB) })
	time.Sleep(50 * time.Millisecond)
	cancelA()
	time.Sleep(50 * time.Millisecond)
	release()
	sessionMwRequireSignal(t, doneA, "request A to finish")
	sessionMwRequireSignal(t, doneB, "request B to finish")

	sessionMwRequireCalls(t, env.refresher, 1)
	if got := env.stored(t).Tokens.AccessToken; got != "access-2" {
		t.Errorf("stored AccessToken = %q, want access-2", got)
	}
	sessionMwRequireAccess(t, seenB, "access-2")
}

func TestMiddlewareRotationUsesNewestRefreshToken(t *testing.T) {
	env := sessionMwSetup(t, nil, sessionTestTokens(sessionTestT0.Add(30*time.Minute)))
	env.clock.Set(sessionMwExpired)
	env.serve(t.Context(), t, &sessionMwSeen{})
	env.clock.Set(sessionTestT0.Add(10 * time.Minute))
	seen2 := &sessionMwSeen{}

	env.serve(t.Context(), t, seen2)

	if got := env.refresher.Received(); !slices.Equal(got, []string{"refresh-1", "refresh-2"}) {
		t.Errorf("Received = %q, want [refresh-1 refresh-2]", got)
	}
	if got := env.stored(t).Tokens.RefreshToken; got != "refresh-3" {
		t.Errorf("stored RefreshToken = %q, want refresh-3", got)
	}
	sessionMwRequireAccess(t, seen2, "access-3")
}

func TestMiddlewareKeepsRefreshTokenWithoutRotation(t *testing.T) {
	env := sessionMwSetup(t, nil, sessionTestTokens(sessionTestT0.Add(30*time.Minute)))
	env.refresher.noRotate = true
	env.clock.Set(sessionMwExpired)

	rec := env.serve(t.Context(), t, &sessionMwSeen{})

	stored := env.stored(t)
	if stored.Tokens.AccessToken != "access-2" {
		t.Errorf("AccessToken = %q, want access-2", stored.Tokens.AccessToken)
	}
	if stored.Tokens.RefreshToken != "refresh-1" {
		t.Errorf("RefreshToken = %q, want refresh-1", stored.Tokens.RefreshToken)
	}
	if want := sessionTestT0.Add(30 * time.Minute); !stored.Tokens.RefreshExpiresAt.Equal(want) {
		t.Errorf("RefreshExpiresAt = %v, want %v", stored.Tokens.RefreshExpiresAt, want)
	}
	sessionMwRequireSetCookieCount(t, rec, 1)
	if got := sessionTestSetCookies(t, rec)[0].MaxAge; got != 1500 {
		t.Errorf("MaxAge = %d, want 1500", got)
	}
}

func TestMiddlewareRejectedRefreshEndsSession(t *testing.T) {
	env := sessionMwSetup(t, nil, sessionTestTokens(sessionTestT0.Add(30*time.Minute)))
	env.refresher.valid = "other"
	env.clock.Set(sessionMwExpired)
	seen := &sessionMwSeen{}

	rec := env.serve(t.Context(), t, seen)

	sessionMwRequireCalls(t, env.refresher, 1)
	sessionMwRequireAccess(t, seen, "")
	sessionMwRequireStatus(t, rec, http.StatusOK)
	env.requireSessionGone(t)
	sessionMwRequireClearedCookie(t, rec)
}

func TestMiddlewareLostRefreshResponse(t *testing.T) {
	env := sessionMwSetup(t, nil, sessionTestTokens(sessionTestT0.Add(30*time.Minute)))
	env.refresher.lostNext = true
	env.clock.Set(sessionMwExpired)
	seen := &sessionMwSeen{}

	rec := env.serve(t.Context(), t, seen)

	sessionMwRequireStatus(t, rec, http.StatusServiceUnavailable)
	sessionMwRequireAccess(t, seen)
	sessionMwRequireSetCookieCount(t, rec, 0)
	sessionMwRequireCalls(t, env.refresher, 1)
	if got := env.stored(t).Tokens.RefreshToken; got != "refresh-1" {
		t.Errorf("stored RefreshToken = %q, want refresh-1", got)
	}

	seen2 := &sessionMwSeen{}
	rec2 := env.serve(t.Context(), t, seen2)

	sessionMwRequireStatus(t, rec2, http.StatusOK)
	sessionMwRequireAccess(t, seen2, "")
	sessionMwRequireCalls(t, env.refresher, 2)
	if got := env.refresher.Received(); !slices.Equal(got, []string{"refresh-1", "refresh-1"}) {
		t.Errorf("Received = %q, want [refresh-1 refresh-1]", got)
	}
	env.requireSessionGone(t)
	sessionMwRequireClearedCookie(t, rec2)
}

func TestMiddlewareTransientRefreshError(t *testing.T) {
	t.Run("access still valid", func(t *testing.T) {
		env := sessionMwSetup(t, nil, sessionTestTokens(sessionTestT0.Add(30*time.Minute)))
		env.refresher.failNext = errSessionMwTransient
		env.clock.Set(sessionMwInsideWindow)
		seen := &sessionMwSeen{}

		rec := env.serve(t.Context(), t, seen)

		sessionMwRequireStatus(t, rec, http.StatusOK)
		sessionMwRequireAccess(t, seen, "access-1")
		sessionMwRequireSetCookieCount(t, rec, 0)
		if got := env.stored(t).Tokens.AccessToken; got != "access-1" {
			t.Errorf("stored AccessToken = %q, want access-1", got)
		}
	})

	t.Run("access expired", func(t *testing.T) {
		env := sessionMwSetup(t, nil, sessionTestTokens(sessionTestT0.Add(30*time.Minute)))
		env.refresher.failNext = errSessionMwTransient
		env.clock.Set(sessionMwExpired)
		seen := &sessionMwSeen{}

		rec := env.serve(t.Context(), t, seen)

		sessionMwRequireStatus(t, rec, http.StatusServiceUnavailable)
		sessionMwRequireAccess(t, seen)
		sessionMwRequireSetCookieCount(t, rec, 0)
		if got := env.stored(t).Tokens.RefreshToken; got != "refresh-1" {
			t.Errorf("stored RefreshToken = %q, want refresh-1", got)
		}
		if logs := env.logs.String(); !strings.Contains(logs, env.key[:8]) {
			t.Errorf("log does not contain the key prefix %q:\n%s", env.key[:8], logs)
		}
	})
}

func TestMiddlewareWindowCappedAtHalfLifetime(t *testing.T) {
	refreshAhead := func(c *Config) { c.RefreshAhead = 10 * time.Minute }
	tokens := sessionTestTokens(sessionTestT0.Add(30 * time.Minute))

	t.Run("three minutes left", func(t *testing.T) {
		env := sessionMwSetup(t, refreshAhead, tokens)
		env.clock.Set(sessionTestT0.Add(2 * time.Minute))
		seen := &sessionMwSeen{}

		env.serve(t.Context(), t, seen)

		sessionMwRequireCalls(t, env.refresher, 0)
		sessionMwRequireAccess(t, seen, "access-1")
	})

	t.Run("two minutes left", func(t *testing.T) {
		env := sessionMwSetup(t, refreshAhead, tokens)
		env.clock.Set(sessionTestT0.Add(3 * time.Minute))

		env.serve(t.Context(), t, &sessionMwSeen{})

		sessionMwRequireCalls(t, env.refresher, 1)
	})
}

func TestMiddlewareZeroIssuedAtUsesFullWindow(t *testing.T) {
	tokens := sessionTestTokens(sessionTestT0.Add(30 * time.Minute))
	tokens.IssuedAt = time.Time{}
	env := sessionMwSetup(t, func(c *Config) { c.RefreshAhead = 10 * time.Minute }, tokens)
	env.clock.Set(sessionMwValid)

	env.serve(t.Context(), t, &sessionMwSeen{})

	sessionMwRequireCalls(t, env.refresher, 1)
}

func TestMiddlewareLogoutWaitsForRefresh(t *testing.T) {
	type destroyResult struct {
		session *Session
		err     error
	}
	env := sessionMwSetup(t, nil, sessionTestTokens(sessionTestT0.Add(30*time.Minute)))
	release := sessionMwBlockRefresher(t, env.refresher)
	env.refresher.entered = make(chan struct{}, 1)
	env.clock.Set(sessionMwExpired)
	destroyed := make(chan destroyResult, 1)

	doneServe := sessionMwGo(func() { env.serve(t.Context(), t, &sessionMwSeen{}) })
	sessionMwRequireSignal(t, env.refresher.entered, "the refresh to start")
	go func() {
		s, err := env.m.Destroy(t.Context(), httptest.NewRecorder(), sessionTestRequest(t, env.cookie))
		destroyed <- destroyResult{session: s, err: err}
	}()
	select {
	case <-destroyed:
		t.Fatal("Destroy returned while the refresh was in flight")
	case <-time.After(100 * time.Millisecond):
	}
	release()
	sessionMwRequireSignal(t, doneServe, "the request to finish")
	var result destroyResult
	select {
	case result = <-destroyed:
	case <-time.After(sessionMwWaitBound):
		t.Fatal("timed out waiting for Destroy")
	}

	if result.err != nil {
		t.Fatalf("Destroy error = %v, want nil", result.err)
	}
	if result.session == nil || result.session.Tokens.RefreshToken != "refresh-2" {
		t.Errorf("Destroy returned session %+v, want one with RefreshToken refresh-2", result.session)
	}
	env.requireSessionGone(t)
	sessionMwRequireCalls(t, env.refresher, 1)
}

func TestMiddlewareLogoutBeforeFlight(t *testing.T) {
	env := sessionMwSetup(t, nil, sessionTestTokens(sessionTestT0.Add(30*time.Minute)))
	env.clock.Set(sessionMwExpired)
	var destroyErr error
	env.hooks.afterNextGet = func() {
		_, err := env.m.Destroy(t.Context(), httptest.NewRecorder(), sessionTestRequest(t, env.cookie))
		destroyErr = err
	}
	seen := &sessionMwSeen{}

	rec := env.serve(t.Context(), t, seen)

	if destroyErr != nil {
		t.Fatalf("Destroy error = %v, want nil", destroyErr)
	}
	sessionMwRequireStatus(t, rec, http.StatusOK)
	sessionMwRequireAccess(t, seen, "")
	sessionMwRequireCalls(t, env.refresher, 0)
	sessionMwRequireSetCookieCount(t, rec, 0)
	env.requireSessionGone(t)
}

func TestMiddlewareRefreshTimeout(t *testing.T) {
	env := sessionMwSetup(t, func(c *Config) { c.RefreshTimeout = 50 * time.Millisecond }, sessionTestTokens(sessionTestT0.Add(30*time.Minute)))
	sessionMwBlockRefresher(t, env.refresher)
	env.clock.Set(sessionMwExpired)
	recorded := make(chan *httptest.ResponseRecorder, 1)

	go func() { recorded <- env.serve(t.Context(), t, &sessionMwSeen{}) }()

	select {
	case rec := <-recorded:
		sessionMwRequireStatus(t, rec, http.StatusServiceUnavailable)
	case <-time.After(sessionMwWaitBound):
		t.Fatal("request still running after 2s, want the refresh timeout to end it")
	}
	sessionMwRequireCalls(t, env.refresher, 1)
}

func TestMiddlewareLogsNoCredentials(t *testing.T) {
	env := sessionMwSetup(t, nil, sessionTestTokens(sessionTestT0.Add(30*time.Minute)))
	env.clock.Set(sessionMwExpired)
	env.refresher.failNext = errors.New("provider answered 400 for refresh-1")
	rec1 := env.serve(t.Context(), t, &sessionMwSeen{})
	sessionMwRequireStatus(t, rec1, http.StatusServiceUnavailable)
	env.refresher.valid = "other"

	env.serve(t.Context(), t, &sessionMwSeen{})

	logs := env.logs.String()
	if lines := strings.Count(strings.TrimSpace(logs), "\n") + 1; lines < 2 {
		t.Errorf("log has %d lines, want at least 2:\n%s", lines, logs)
	}
	if !strings.Contains(logs, env.key[:8]) {
		t.Errorf("log does not contain the key prefix %q:\n%s", env.key[:8], logs)
	}
	secrets := []string{env.cookie.Value, env.key, "access-1", "refresh-1", "access-2", "refresh-2"}
	for _, secret := range secrets {
		if strings.Contains(logs, secret) {
			t.Errorf("log contains %q:\n%s", secret, logs)
		}
	}
}

func TestMiddlewareWithoutRefresher(t *testing.T) {
	t.Run("inside window", func(t *testing.T) {
		env := sessionMwSetupWithoutRefresher(t)
		env.clock.Set(sessionMwInsideWindow)
		seen := &sessionMwSeen{}

		rec := env.serve(t.Context(), t, seen)

		sessionMwRequireStatus(t, rec, http.StatusOK)
		sessionMwRequireAccess(t, seen, "access-1")
		sessionMwRequireSetCookieCount(t, rec, 0)
	})

	t.Run("expired", func(t *testing.T) {
		env := sessionMwSetupWithoutRefresher(t)
		env.clock.Set(sessionMwExpired)
		seen := &sessionMwSeen{}

		rec := env.serve(t.Context(), t, seen)

		sessionMwRequireStatus(t, rec, http.StatusServiceUnavailable)
		sessionMwRequireAccess(t, seen)
		env.stored(t)
	})
}

func TestNewManagerDefaultRefreshTimeout(t *testing.T) {
	store := NewMemoryStore(MemoryStoreConfig{})

	if got := NewManager(store, nil, Config{}).refreshTimeout; got != 15*time.Second {
		t.Errorf("default refreshTimeout = %v, want 15s", got)
	}
	if got := NewManager(store, nil, Config{RefreshTimeout: time.Second}).refreshTimeout; got != time.Second {
		t.Errorf("configured refreshTimeout = %v, want 1s", got)
	}
}
