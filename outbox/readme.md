# Outbox Pattern

The outbox package implements the **transactional outbox pattern** for reliable event processing.

## Why?

When a domain action and its corresponding event must succeed or fail together, publishing directly to a message broker creates a race condition. The outbox pattern solves this by:

1. Writing events to a database table **within the same transaction** as domain changes
2. A separate worker polls and processes these events asynchronously

## Components

| File | Purpose |
|------|---------|
| `writer.go` | Writes events to outbox table (requires `pgx.Tx`) |
| `repository.go` | Fetches/updates outbox events with row locking |
| `worker.go` | Polls and dispatches events to handlers |
| `handler.go` | Interface for event processors |
| `registry.go` | Maps event type strings to Go types |


## Setup

```sql
outboxWriter := outbox.NewWriter()

// Initialize outbox worker
outboxRepo := outbox.NewRepository(database.Pool())
outboxRegistry := outbox.NewEventRegistry()

// Register the model and event type, the handler processing it is defined in the handler
outboxRegistry.Register(events.JoinCompanyRequestEventName, func() events.DomainEvent {
		return &events.JoinRequestCreated{}
	})

// define the handlers the events are linked by EventName to the handler
handlers := []outbox.Handler{
    handler.NewJoinRequestResolvedHandler(notificationService, slog.Default()),
    handler.NewJoinRequestHandler(notificationService, slog.Default()),
}

outboxWorker := outbox.NewWorker(
    database.Pool(),
    outboxRepo,
    outboxRegistry,
    handlers, // Handlers can be added as needed
    outbox.DefaultWorkerConfig(),
    nil, // Uses default logger
)

```

## Usage

```go
tx, _ := pool.Begin(ctx)
defer tx.Rollback(ctx)

// Domain writes...
_, _ = tx.Exec(ctx, "INSERT INTO join_requests ...")

// Add event in same transaction
event := events.NewJoinRequestCreated(requestID, companyID)
_ = outboxWriter.Add(ctx, tx, event)

tx.Commit(ctx)  // Both succeed or both fail
```

## Guarantees

- **At-least-once delivery** via retry mechanism
- **Horizontal scaling** via `FOR UPDATE SKIP LOCKED`
- **Idempotent processing** must be ensured by handlers
- **Dead letter** for events exceeding max retries

## Future

Designed for drop-in replacement with Kafka/RabbitMQ without changing domain events or handlers.
