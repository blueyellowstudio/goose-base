# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Module

`github.com/blueyellowstudio/goose-base` — a shared Go library published to GitHub and imported by other services.

## Commands

```bash
go build ./...         # Build all packages
go test ./...          # Run all tests
go test ./outbox/...   # Run tests for a single package
go vet ./...           # Static analysis
```

## Architecture

This repo is a collection of independent subpackages. Each package is self-contained and consumed individually by downstream services via `go get github.com/blueyellowstudio/goose-base/<package>`.

### `identityManager`
Supabase Auth wrapper. `identity_manager.go` defines the `IdentityManager` interface and all shared types (`AuthResponse`, `AdminUserResponse`, etc.). `supabase.go` provides the concrete `SupabaseIdentityManager` implementation.

Constructor takes explicit config params — callers pass `os.Getenv(...)` themselves:
```go
im := identityManager.NewSupabaseIdentityManager(url, serviceKey, anonKey)
```

### `outbox`
Transactional outbox pattern over PostgreSQL (pgx). Flow:
1. `Writer.Add(ctx, tx, event)` — writes event inside caller's transaction
2. `Worker.Run(ctx)` — polls `outbox_events`, routes to `Handler` via `EventRegistry`
3. Failed events retry up to `MaxRetries`, then move to `outbox_dead_letter_events`

`DomainEvent` interface is defined locally in `outbox.go`. Consuming services implement it on their domain event types. Requires DB schema from `outbox/setup.sql`.

### `storage`
File storage abstraction. `storageInterface.go` defines the `Storage` interface and config structs. Two implementations: `FileStorage` (local filesystem with HMAC-signed URLs) and `SupabaseStorage` (Supabase Storage API).

### `utils`
Env helpers: `GetEnv`, `GetEnvBool`, `GetEnvInt` — all accept a default value.

### `ping`
Single handler `ping.Handler` — returns `"Pong"`. Mount with chi: `r.Get("/ping", ping.Handler)`.

## Key conventions

- All methods accept `context.Context` as first argument
- Interfaces are defined in the same package as their types (not in a separate `interfaces` package)
- Each package with a Supabase implementation has a compile-time interface check: `var _ Interface = (*Impl)(nil)`
- The `outbox/handler.go` `Handler` interface currently references `events.DomainEvent` — this must stay aligned with the local `DomainEvent` definition in `outbox/outbox.go`
