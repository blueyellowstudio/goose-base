# Usage Examples: Outbox

## 1. When To Use This Module

- Domain operations and their events must succeed or fail atomically
- Publishing events to external systems (email, notifications, integrations) after database writes
- Decoupling synchronous request handling from asynchronous event processing
- Building event-driven architectures with at-least-once delivery guarantees

## 2. When NOT To Use This Module

- Synchronous request-response patterns where immediate confirmation is required
- Events that don't need transactional consistency with domain operations
- Exactly-once delivery requirements (handlers must be idempotent)
- High-frequency events where polling latency is unacceptable (consider direct message broker)

## 3. Minimal Example

Write an event within a database transaction:

```go
tx, _ := pool.Begin(ctx)
defer tx.Rollback(ctx)

// Domain operation
_, _ = tx.Exec(ctx, "INSERT INTO users (id, email) VALUES ($1, $2)", userID, email)

// Add event in same transaction
writer := outbox.NewWriter()
event := events.NewUserCreated(userID, email)
_ = writer.Add(ctx, tx, event)

tx.Commit(ctx) // Both succeed or both fail
```

## 4. Standard Integration Example

Complete setup with worker processing events:

```go
func main() {
    pool, _ := pgxpool.New(ctx, connString)
    
    // Setup components
    repo := outbox.NewRepository(pool)
    registry := outbox.NewEventRegistry()
    
    // Register handlers
    handlers := []outbox.Handler{
        notifications.NewJoinRequestHandler(notificationService),
        email.NewInviteHandler(emailService),
    }
    
    // Configure and start worker
    config := outbox.DefaultWorkerConfig()
    config.BatchSize = 50
    config.MaxRetries = 3
    
    worker := outbox.NewWorker(pool, repo, registry, handlers, config, slog.Default())
    
    // Run in background (blocks until context cancelled)
    go worker.Run(ctx)
}
```

## 5. Advanced Example

Implementing a custom handler:

```go
type JoinRequestHandler struct {
    notifier NotificationService
}

func (h *JoinRequestHandler) Handles(eventType string) bool {
    return eventType == events.JoinCompanyRequestEventName ||
           eventType == events.JoinRequestAcceptedEventName
}

func (h *JoinRequestHandler) Handle(ctx context.Context, event events.DomainEvent) error {
    switch e := event.(type) {
    case *events.JoinRequestCreated:
        return h.notifier.NotifyCompanyAdmins(ctx, e.CompanyID, e.RequestID)
    case *events.JoinRequestAccepted:
        return h.notifier.NotifyUser(ctx, e.UserID, "Your request was accepted")
    }
    return nil
}
```

Registering a new event type:

```go
registry := outbox.NewEventRegistry()
registry.Register("order.created", func() events.DomainEvent {
    return &OrderCreated{}
})
```

## 6. Anti-Patterns

```go
// ❌ Writing event outside transaction
writer.Add(ctx, tx, event)
tx.Commit(ctx)
writer.Add(ctx, anotherTx, anotherEvent) // This defeats the purpose!

// ❌ Non-idempotent handler (will cause duplicates on retry)
func (h *Handler) Handle(ctx context.Context, event events.DomainEvent) error {
    // BAD: No idempotency check
    return h.emailService.Send(event.UserID, "Welcome!")
}

// ❌ Blocking operations in handler without timeout
func (h *Handler) Handle(ctx context.Context, event events.DomainEvent) error {
    // BAD: No context timeout, can block worker indefinitely
    return h.externalAPI.Call(event.Data)
}

// ❌ Returning nil for unknown events in handler
func (h *Handler) Handles(eventType string) bool {
    return true // BAD: Claims to handle everything
}
```

## 7. Integration Notes

- **Domain Events**: Must implement `events.DomainEvent` interface with `EventName()` and `OccurredAt()` methods
- **Database Schema**: Requires `outbox_events` and `outbox_dead_letter_events` tables (see `setup.sql`)
- **Transaction Scope**: `Writer.Add()` requires an active `pgx.Tx` — never pass a pool connection
- **Handler Registration**: Handlers are checked in order; first matching handler processes the event
- **Dead Letter**: Events exceeding `MaxRetries` are moved to `outbox_dead_letter_events` for manual inspection

## 8. Performance Considerations

- **Polling Interval**: Default 1 second; reduce for lower latency, increase to reduce database load
- **Batch Size**: Default 100; larger batches improve throughput but increase transaction duration
- **Row Locking**: `FOR UPDATE SKIP LOCKED` enables multiple workers without conflicts
- **Index**: Partial index on `occurred_at WHERE processed_at IS NULL` optimizes fetch queries
- **Dead Letter Monitoring**: Monitor `outbox_dead_letter_events` table for failed events requiring attention

## 9. Testing Guidance

**Unit Testing Handlers:**
```go
func TestJoinRequestHandler(t *testing.T) {
    mockNotifier := &MockNotificationService{}
    handler := NewJoinRequestHandler(mockNotifier)
    
    event := &events.JoinRequestCreated{RequestID: uuid.New(), CompanyID: uuid.New()}
    err := handler.Handle(ctx, event)
    
    assert.NoError(t, err)
    assert.True(t, mockNotifier.NotifyCompanyAdminsCalled)
}
```

**Integration Testing Writer:**
```go
func TestOutboxWriter(t *testing.T) {
    tx, _ := pool.Begin(ctx)
    defer tx.Rollback(ctx)
    
    writer := outbox.NewWriter()
    event := events.NewJoinRequestCreated(requestID, companyID)
    
    err := writer.Add(ctx, tx, event)
    assert.NoError(t, err)
    
    // Verify event in database
    var count int
    tx.QueryRow(ctx, "SELECT COUNT(*) FROM outbox_events WHERE id = $1", event.ID).Scan(&count)
    assert.Equal(t, 1, count)
}
```

**Testing Idempotency:**
- Process the same event twice and verify side effects occur only once
- Use unique constraint checks or idempotency keys in handlers
