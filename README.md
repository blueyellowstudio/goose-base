# goservice-basics

Shared Go library for BlueYellow services. Provides reusable subpackages for common service infrastructure.

## Install

```bash
go get github.com/blueyellowstudio/goservice-basics
```

Import individual packages as needed:

```go
import "github.com/blueyellowstudio/goservice-basics/identityManager"
import "github.com/blueyellowstudio/goservice-basics/outbox"
import "github.com/blueyellowstudio/goservice-basics/storage"
import "github.com/blueyellowstudio/goservice-basics/utils"
import "github.com/blueyellowstudio/goservice-basics/ping"
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

**Interface:** `Register`, `Authenticate`, `RefreshToken`, `VerifyEmailOtp`, `VerifyTokenHash`, `SendMagicLink`, `SendPasswordResetEmail`, `ResendVerificationEmail`, `SendInvite`, `CreateManagedUser`, `GetUserEmail`, `UpdateUserPassword`, `DisableUser`, `DeleteUser`

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

upload, err := s.GenerateUploadURL("avatars", "user-123/photo.jpg")
download, err := s.GenerateDownloadURL("avatars", "user-123/photo.jpg", "photo.jpg")
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

**Interface:** `GenerateUploadURL`, `GenerateDownloadURL`, `DeleteObject`, `ListObjects`, `GetObjectInfo`, `FileExists`

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
