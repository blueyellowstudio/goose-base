package session

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"
)

var (
	sessionMwValid        = sessionTestT0
	sessionMwInsideWindow = sessionTestT0.Add(4*time.Minute + 50*time.Second)
	sessionMwExpired      = sessionTestT0.Add(5 * time.Minute)
)

var errSessionMwTransient = errors.New("provider unavailable")

const sessionMwWaitBound = 2 * time.Second

// sessionMwSetup builds a manager on a settable clock (at T0) and logs in "user-1" with tokens.
func sessionMwSetup(t *testing.T, cfg func(*Config), tokens Tokens) *sessionMwEnv {
	t.Helper()
	return sessionMwBuild(t, cfg, tokens, true)
}

// sessionMwSetupWithoutRefresher is sessionMwSetup with default tokens and a nil Refresher.
func sessionMwSetupWithoutRefresher(t *testing.T) *sessionMwEnv {
	t.Helper()
	return sessionMwBuild(t, nil, sessionTestTokens(sessionTestT0.Add(30*time.Minute)), false)
}

func sessionMwBuild(t *testing.T, cfg func(*Config), tokens Tokens, withRefresher bool) *sessionMwEnv {
	t.Helper()
	clock := &sessionMwClock{t: sessionTestT0}
	store := NewMemoryStore(MemoryStoreConfig{Now: clock.Now})
	hooks := &sessionMwHookStore{MemoryStore: store}
	refresher := &sessionMwRefresher{now: clock.Now, valid: "refresh-1", issued: 1}
	logs := &sessionMwLog{}
	config := Config{Now: clock.Now, Logger: slog.New(slog.NewTextHandler(logs, nil))}
	if cfg != nil {
		cfg(&config)
	}

	var manager *Manager
	if withRefresher {
		manager = NewManager(hooks, refresher, config)
	} else {
		manager = NewManager(hooks, nil, config)
		refresher = nil
	}

	rec := httptest.NewRecorder()
	if err := manager.Create(t.Context(), rec, "user-1", tokens); err != nil {
		t.Fatalf("Create: %v", err)
	}
	cookie := sessionTestSetCookies(t, rec)[0]
	key := sessionTestKey(cookie.Value)
	original, err := store.Get(t.Context(), key)
	if err != nil {
		t.Fatalf("store.Get after Create: %v", err)
	}
	return &sessionMwEnv{
		m:         manager,
		store:     store,
		hooks:     hooks,
		clock:     clock,
		refresher: refresher,
		logs:      logs,
		cookie:    cookie,
		key:       key,
		original:  *original,
	}
}

// serve runs one request with the session cookie through the middleware.
func (e *sessionMwEnv) serve(ctx context.Context, t *testing.T, seen *sessionMwSeen) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	req.AddCookie(e.cookie)
	return e.serveRequest(req, seen)
}

func (e *sessionMwEnv) serveRequest(req *http.Request, seen *sessionMwSeen) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.m.Middleware(seen.handler()).ServeHTTP(rec, req)
	return rec
}

// stored returns the session currently in the store, failing the test when it is gone.
func (e *sessionMwEnv) stored(t *testing.T) *Session {
	t.Helper()
	got, err := e.store.Get(t.Context(), e.key)
	if err != nil {
		t.Fatalf("store.Get(key): %v", err)
	}
	return got
}

func (e *sessionMwEnv) requireSessionGone(t *testing.T) {
	t.Helper()
	if _, err := e.store.Get(t.Context(), e.key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("store.Get(key) error = %v, want ErrNotFound", err)
	}
}

// sessionMwBlockRefresher makes Refresh wait until the returned release is called. The
// channel is also released on cleanup, so no goroutine outlives the test.
func sessionMwBlockRefresher(t *testing.T, f *sessionMwRefresher) (release func()) {
	t.Helper()
	block := make(chan struct{})
	f.block = block
	var once sync.Once
	release = func() { once.Do(func() { close(block) }) }
	t.Cleanup(release)
	return release
}

// sessionMwRequireSignal fails the test unless ch signals within the wait bound.
func sessionMwRequireSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(sessionMwWaitBound):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// sessionMwGo runs fn in a goroutine and returns a channel that is closed when fn returns.
func sessionMwGo(fn func()) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	return done
}

func sessionMwRequireSetCookieCount(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if got := len(rec.Header().Values("Set-Cookie")); got != want {
		t.Fatalf("Set-Cookie headers = %d, want %d", got, want)
	}
}

// sessionMwRequireClearedCookie expects exactly one Set-Cookie that clears the session cookie.
func sessionMwRequireClearedCookie(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	sessionMwRequireSetCookieCount(t, rec, 1)
	cookie := sessionTestSetCookies(t, rec)[0]
	if cookie.Name != "session" {
		t.Errorf("Name = %q, want session", cookie.Name)
	}
	if cookie.MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1", cookie.MaxAge)
	}
	if cookie.Path != "/" {
		t.Errorf("Path = %q, want /", cookie.Path)
	}
	if !cookie.Secure {
		t.Error("Secure = false, want true")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", cookie.SameSite)
	}
}

func sessionMwRequireStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d", rec.Code, want)
	}
}

func sessionMwRequireAccess(t *testing.T, seen *sessionMwSeen, want ...string) {
	t.Helper()
	got := seen.Access()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !slices.Equal(got, want) {
		t.Fatalf("next saw access tokens %q, want %q", got, want)
	}
}

func sessionMwRequireCalls(t *testing.T, f *sessionMwRefresher, want int) {
	t.Helper()
	if got := f.Calls(); got != want {
		t.Fatalf("refresher calls = %d, want %d", got, want)
	}
}

// sessionMwClock is a settable clock shared by the manager, the store and the fake refresher.
type sessionMwClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *sessionMwClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *sessionMwClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// sessionMwRefresher behaves like a provider with refresh-token rotation on (Q2): only valid
// is accepted; each success returns access-N / refresh-N and makes refresh-N the only valid token.
type sessionMwRefresher struct {
	mu       sync.Mutex
	now      func() time.Time
	valid    string
	issued   int
	noRotate bool          // success returns RefreshToken "" and zero RefreshExpiresAt; valid unchanged
	failNext error         // returned once, before any rotation
	lostNext bool          // once: rotate internally, then return errSessionMwTransient
	block    chan struct{} // when non-nil: wait for close(block) or ctx.Done()
	entered  chan struct{} // when non-nil: a non-blocking send on every call, before blocking
	calls    int
	received []string
}

func (f *sessionMwRefresher) Refresh(ctx context.Context, refreshToken string) (Tokens, error) {
	f.mu.Lock()
	f.calls++
	f.received = append(f.received, refreshToken)
	entered, block := f.entered, f.block
	f.mu.Unlock()

	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return Tokens{}, ctx.Err()
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return Tokens{}, err
	}
	if refreshToken != f.valid {
		return Tokens{}, ErrRefreshRejected
	}
	f.issued++
	n := f.issued
	now := f.now()
	if f.lostNext {
		f.lostNext = false
		f.valid = sessionMwToken("refresh", n)
		return Tokens{}, errSessionMwTransient
	}
	if f.noRotate {
		return Tokens{
			AccessToken:     sessionMwToken("access", n),
			IssuedAt:        now,
			AccessExpiresAt: now.Add(5 * time.Minute),
		}, nil
	}
	f.valid = sessionMwToken("refresh", n)
	return Tokens{
		AccessToken:      sessionMwToken("access", n),
		RefreshToken:     f.valid,
		IssuedAt:         now,
		AccessExpiresAt:  now.Add(5 * time.Minute),
		RefreshExpiresAt: now.Add(30 * time.Minute),
	}, nil
}

func (f *sessionMwRefresher) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *sessionMwRefresher) Received() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.received)
}

func sessionMwToken(kind string, n int) string {
	return kind + "-" + strconv.Itoa(n)
}

// sessionMwHookStore wraps the real MemoryStore; each hook fires once on the next Get.
type sessionMwHookStore struct {
	*MemoryStore
	mu           sync.Mutex
	staleNext    *Session // next Get returns a copy of this instead of the stored session
	afterNextGet func()   // runs after the next Get, before it returns
	barrier      int      // when > 0: the first barrier Gets each wait until all of them arrived
	arrived      int
	released     chan struct{} // closed when arrived reaches barrier; created by the test with barrier
}

func (s *sessionMwHookStore) Get(ctx context.Context, id string) (*Session, error) {
	s.mu.Lock()
	stale, after := s.staleNext, s.afterNextGet
	s.staleNext, s.afterNextGet = nil, nil
	s.mu.Unlock()

	got, err := s.MemoryStore.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if stale != nil {
		staleCopy := *stale
		got = &staleCopy
	}
	if after != nil {
		after()
	}
	if err := s.waitAtBarrier(); err != nil {
		return nil, err
	}
	return got, nil
}

func (s *sessionMwHookStore) waitAtBarrier() error {
	s.mu.Lock()
	waiting := s.arrived < s.barrier
	if waiting {
		s.arrived++
		if s.arrived == s.barrier {
			close(s.released)
		}
	}
	released := s.released
	s.mu.Unlock()

	if !waiting {
		return nil
	}
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	select {
	case <-released:
		return nil
	case <-timeout.C:
		return errors.New("barrier timeout")
	}
}

// sessionMwLog is a goroutine-safe io.Writer for the manager's slog logger.
type sessionMwLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *sessionMwLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *sessionMwLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// sessionMwSeen records what next saw: the access token in FromContext, or "" for no session.
type sessionMwSeen struct {
	mu     sync.Mutex
	access []string
}

func (s *sessionMwSeen) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		access := ""
		if sess, ok := FromContext(r.Context()); ok {
			access = sess.Tokens.AccessToken
		}
		s.mu.Lock()
		s.access = append(s.access, access)
		s.mu.Unlock()

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func (s *sessionMwSeen) Access() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.access)
}

type sessionMwEnv struct {
	m         *Manager
	store     *MemoryStore
	hooks     *sessionMwHookStore
	clock     *sessionMwClock
	refresher *sessionMwRefresher
	logs      *sessionMwLog
	cookie    *http.Cookie // from Create
	key       string       // sessionTestKey(cookie.Value)
	original  Session      // the stored session right after Create
}
