# goose-base

Shared Go library for BlueYellow services. Provides reusable subpackages for common service infrastructure.

## Install

```bash
go get github.com/blueyellowstudio/goose-base
```

Import individual packages as needed:

```go
import "github.com/blueyellowstudio/goose-base/identityManager"
import "github.com/blueyellowstudio/goose-base/authorization"
import "github.com/blueyellowstudio/goose-base/authentication"
import "github.com/blueyellowstudio/goose-base/medialib"
import "github.com/blueyellowstudio/goose-base/outbox"
import "github.com/blueyellowstudio/goose-base/storage"
import "github.com/blueyellowstudio/goose-base/utils"
import "github.com/blueyellowstudio/goose-base/ping"
```

---

## Packages

### `identityManager`

Supabase Auth wrapper with a provider-agnostic `IdentityManager` interface.

```go
im := identityManager.NewSupabaseIdentityManager(
    os.Getenv("SUPABASE_URL"),
    os.Getenv("SUPABASE_SERVICE_KEY"),
    os.Getenv("SUPABASE_ANON_KEY"),
)

// Register
resp, err := im.Register(ctx, "John Doe", "john@example.com", "password")

// Authenticate
auth, err := im.Authenticate(ctx, "john@example.com", "password")

// Refresh token
auth, err = im.RefreshToken(ctx, auth.RefreshToken)
```

**Interface:** `Register`, `Authenticate`, `RefreshToken`, `ExchangeOAuthCode`, `VerifyEmailOtp`, `VerifyTokenHash`, `SendMagicLink`, `SendPasswordResetEmail`, `ResendVerificationEmail`, `SendInvite`, `CreateManagedUser`, `GetUserEmail`, `UpdateUserPassword`, `DisableUser`, `DeleteUser`

---

### `authorization`

JWT validation middleware. Populates the request context with the caller's identity so handlers never touch tokens. Reads the `Authorization: Bearer` header first, then the named cookie — so a native client and a cookie-session browser can share the same routes.

```go
// ES256 via the project's JWKS, with HS256 still accepted while a legacy
// secret is configured. Pass an empty jwtSecret to accept ES256 only.
authz, err := authorization.NewAuthorizationWithJWKS(
    ctx,
    "token",                 // access token cookie name
    os.Getenv("JWT_SECRET"), // "" disables the HS256 fallback
    os.Getenv("JWKS_URL"),
    tokenHandler,            // your per-service TokenHandler
    isProduction,
)

// Protect a route group
r.Route("/api", func(api chi.Router) {
    api.Use(authz.Handler)
    api.Get("/orders", ordersHandler)
})

// Inside a handler
identity, err := tokenHandler.GetIdentityFromContext(r.Context())
// identity.UserID, .UserEmail, .Username, .Role

// For PUBLIC endpoints that want to know whether a caller is signed in
// without rejecting them — reports instead of 401, and logs nothing.
identity, ok := authz.IdentityFromRequest(r)
```

`NewAuthorization(cookieName, secret, tokenHandler, isProduction)` is the HS256-only constructor. Which algorithms are accepted follows from what you configure — secret only ⇒ `HS256`, secret + JWKS ⇒ both, JWKS with an empty secret ⇒ `ES256` only. **Neither configured accepts nothing**, so guard for that at startup.

You implement `TokenHandler` once per service: `CreateContext`, `CreateDebugContext`, `ValidateToken`, `GetIdentityFromContext`. Full example in [`docu/basics.md`](docu/basics.md).

---

### `authentication`

HTTP handlers for the session lifecycle. Every handler that produces a session writes it into `HttpOnly` cookies rather than returning tokens, so a browser client never holds a token in JavaScript.

```go
authn := authentication.NewAuthentication(
    identities,   // IdentityManager
    tokenHandler, // TokenHandler
    authz,        // *authorization.Authorization
    os.Getenv("APP_URL"), // FRONTEND origin — redirect paths are appended to it
    "token", "rToken",    // access / refresh cookie names
    isProduction,
    authentication.LoginRedirectConfig{
        RedirectToTokenLoginAfterMagicLinkFailed: true,
        TokenLoginPath:   "/token-login",   // all four are FRONTEND routes
        LoginErrorPath:   "/",
        AcceptInvitePath: "/register",
        SetPasswordPath:  "/reset-password/new",
    },
    authentication.OAuthConfig{
        SupabaseURL: os.Getenv("SUPABASE_URL"),
        CallbackURL: os.Getenv("API_BASE_URL") + "/do-auth/oauth/callback",
    },
)

// Keep the refresh cookie off every request but the one that spends it.
// This path must equal the route RefreshAuthHandler is mounted on.
authn.SetRefreshPath("/do-auth/refresh")
```

**Public routes** — the credential arrives in the body, a cookie, or a query parameter:

```go
r.Post("/do-auth/login", authn.LoginHandler)
r.Post("/do-auth/register", authn.RegisterHandler)
r.Post("/do-auth/refresh", authn.RefreshAuthHandler)
r.Post("/do-auth/logout", authn.LogoutHandler)
r.Get("/do-auth/session", authn.SessionHandler)

// Passwordless: the email carries both a link and a numeric code
r.Post("/do-auth/token-login", authn.StartLoginHandler)
r.Get("/do-auth/link", authn.AuthLinkHandler)
r.Post("/do-auth/verify-otp", authn.GetVerifyTokenHandler(identityManager.EmailOtpTypeEmail))

// Email confirmation after registration
r.Post("/do-auth/verify-email", authn.GetVerifyTokenHandler(identityManager.EmailOtpTypeSignup))
r.Post("/do-auth/resend-verification", authn.ResendVerificationEmailHandler)

r.Post("/do-auth/password/request-reset", authn.RequestPasswordResetHandler)

// Server-side PKCE OAuth — no provider token ever reaches JavaScript
r.Get("/do-auth/oauth/callback", authn.OAuthCallbackHandler)
r.Get("/do-auth/oauth/{provider}", authn.OAuthStartHandler)
```

**Authenticated routes** — these read the caller from context, so mounted publicly they return `401` unconditionally:

```go
r.Group(func(protected chi.Router) {
    protected.Use(authz.Handler)
    protected.Post("/do-auth/password/reset", authn.ResetPasswordHandler)
    protected.Post("/do-auth/password/change", authn.ChangePasswordHandler)
    protected.Post("/do-auth/account/disable", authn.DisableAccountHandler)
    protected.Post("/do-auth/account/delete", authn.DeleteAccountHandler)
})
```

`SessionHandler` is how a cookie-session client learns who it is — it always answers `200`, because being signed out is a normal state, not an error:

```jsonc
{ "authenticated": false }
{ "authenticated": true, "userId": "…", "email": "…", "username": "…", "role": "admin" }
```

Gotchas worth knowing up front:

- `GetVerifyTokenHandler` is a **factory** — mount one route per `EmailOtpType`. `EmailOtpTypeEmail` verifies a numeric code, `EmailOtpTypeMagicLink` verifies a link's `token_hash`; they are not interchangeable.
- `RegisterHandler` sets **no** cookie (there is no session until the email is confirmed) and answers a duplicate address identically to a new signup, so it cannot be used to enumerate accounts.
- `SendMagicLink` does **not** create users — it posts to `/auth/v1/otp` with `create_user=false`.
- The OAuth CSRF `state` travels in `redirect_to`, so the provider's redirect allow-list entry must tolerate a query string: `https://api.example.com/do-auth/oauth/callback*`.
- `SameSite=Strict` in production means the browser and the API must be same-site, or no request carries its cookie.

Full walkthrough, including the request flow and a `TokenHandler` implementation: [`docu/basics.md`](docu/basics.md).

---

### `medialib`

Entity-agnostic media asset library: one active object per asset, presigned uploads, soft/hard deletion and a deletion trail for client cache invalidation. Assets are **semi-public** — any logged-in user may read any object, gated by a single Supabase RLS policy.

```go
media := medialib.NewService(
    pgxrunner.NewRunner(pool),
    mlpg.NewMediaRepository(pool, tables),
    mlpg.NewMediaObjectRepository(pool, tables),
    mlpg.NewDeletionRepository(pool, tables),
    store,                                            // storage.Storage
    medialib.NewURLBuilder(storageBase, bucket, nil), // nil ⇒ {"image"} are image types
    bucket,
    nil,                                              // logger, defaults to slog.Default()
)

// Upload: create the slot, open an upload, activate once the client has PUT the bytes
m, _ := media.CreateMedia(ctx, "", "image")
uploadURL, obj, _ := media.CreateMediaObject(ctx, m.ID, "image/jpeg", "jpg", nil)
_ = media.ActivateMediaObject(ctx, obj.ID, sizeBytes)
```

Reads come in two shapes, differing only in **where the credential lives**:

```go
// 1. The caller attaches its own JWT as an Authorization header.
//    Supports on-the-fly image resizing (append ?width=<n>).
url, err := media.GetActiveURL(ctx, mediaID)

// Batched: one query for many assets, no per-id round-trips.
resolved, err := media.ResolveActiveURLs(ctx, mediaIDs) // map[uuid.UUID]ResolvedMedia

// 2. A signed URL carrying its own short-lived token in the query string.
//    For clients that CANNOT set that header — a browser holding its session in
//    an HttpOnly cookie. Usable directly as an <img>/<video> src, and supports
//    range requests, so video seeking works. Returns the original, no transform.
signed, err := media.GetActiveSignedURL(ctx, mediaID)
// signed.URL, signed.Type, signed.ExpiresAt
```

Signing uses the service role key, which bypasses RLS — not an escalation, since it grants exactly what the authenticated-read policy already grants every logged-in user. Callers must still have a session of their own.

**Sentinel errors:** `ErrMediaNotFound`, `ErrMediaObjectNotFound`, `ErrNoActiveObject`.

Concept and bucket/RLS setup: [`docu/medialib.md`](docu/medialib.md) and [`medialib/README.md`](medialib/README.md).

---

### `outbox`

Transactional outbox pattern for reliable event processing over PostgreSQL.

Events are written in the same database transaction as domain changes, then processed asynchronously by a background worker with at-least-once delivery and dead-letter support.

**Database setup** — run `outbox/setup.sql` to create the required tables.

**Writing events:**

```go
// Your domain event must implement the DomainEvent interface
type UserCreated struct { ... }
func (e *UserCreated) EventName() string       { return "user.created" }
func (e *UserCreated) OccurredAt() time.Time   { return e.occurredAt }

// Write within a transaction
writer := outbox.NewWriter()

tx, _ := pool.Begin(ctx)
defer tx.Rollback(ctx)

_, _ = tx.Exec(ctx, "INSERT INTO users ...")
_ = writer.Add(ctx, tx, &UserCreated{...})

tx.Commit(ctx) // both succeed or both fail
```

**Processing events:**

```go
// Implement a handler
type UserCreatedHandler struct{ emailSvc EmailService }

func (h *UserCreatedHandler) Handles(eventType string) bool {
    return eventType == "user.created"
}
func (h *UserCreatedHandler) Handle(ctx context.Context, event outbox.DomainEvent) error {
    e := event.(*UserCreated)
    return h.emailSvc.SendWelcome(ctx, e.Email)
}

// Wire up and start worker
repo := outbox.NewRepository(pool)
registry := outbox.NewEventRegistry()
registry.Register("user.created", func() outbox.DomainEvent { return &UserCreated{} })

worker := outbox.NewWorker(pool, repo, registry, []outbox.Handler{
    &UserCreatedHandler{emailSvc},
}, outbox.DefaultWorkerConfig(), slog.Default())

go worker.Run(ctx)
```

**Default config:** batch size 100, max retries 5, poll interval 1s.

> Handlers must be **idempotent** — events may be delivered more than once.

---

### `storage`

File storage abstraction with two implementations: local filesystem and Supabase Storage. Both generate signed upload/download URLs.

**Supabase Storage:**

```go
s, err := storage.NewSupabaseStorage(&storage.SupabaseStorageConfig{
    StorageURL:       os.Getenv("SUPABASE_STORAGE_URL"),
    StoragePublicURL: os.Getenv("SUPABASE_STORAGE_PUBLIC_URL"),
    ServiceKey:       os.Getenv("SUPABASE_SERVICE_KEY"),
    UploadExpiry:     15 * time.Minute,
    DownloadExpiry:   time.Hour,
})

mimeType := "image/jpeg"
upload, err := s.GenerateUploadURL("avatars", "user-123/photo.jpg", &mimeType)

// filename + download=true force a Content-Disposition attachment;
// pass "", false for a URL meant to be rendered inline.
download, err := s.GenerateDownloadURL("avatars", "user-123/photo.jpg", "photo.jpg", true)
```

**Local filesystem** (dev/self-hosted):

```go
s, err := storage.NewFileStorage(&storage.StorageConfig{
    BaseDir:        "/var/data/uploads",
    SecretKey:      os.Getenv("STORAGE_SECRET_KEY"),
    BaseURL:        "https://api.example.com",
    UploadExpiry:   15 * time.Minute,
    DownloadExpiry: time.Hour,
})

// Mount the upload/download handlers with chi
r.Put("/file/upload", s.UploadHandler)
r.Get("/file/download", s.DownloadHandler)
```

**Interface:** `GenerateUploadURL`, `GenerateDownloadURL`, `DeleteObject`, `DeleteObjects`, `ListObjects`, `GetObjectInfo`, `FileExists`

---

### `utils`

Environment variable helpers with defaults.

```go
addr := utils.GetEnv("SERVER_ADDR", ":8080")
debug := utils.GetEnvBool("DEBUG", false)
timeout := utils.GetEnvInt("TIMEOUT_SECONDS", 30)
```

---

### `ping`

HTTP handler that returns `Pong`. Useful as a liveness probe.

```go
r := chi.NewRouter()
r.Get("/ping", ping.Handler)
```
