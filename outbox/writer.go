package outbox

import (
	"context"
	"encoding/json"
	"eurodima/internal/domain/events"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Writer provides transactional outbox event writing.
// Events MUST be written within a database transaction to ensure
// atomicity with domain operations.
type Writer struct{}

// NewWriter creates a new outbox writer.
func NewWriter() *Writer {
	return &Writer{}
}

// Add inserts a domain event into the outbox table within the given transaction.
// This method requires a transaction to enforce transactional safety.
// The event will be processed asynchronously by the outbox worker.
func (w *Writer) Add(ctx context.Context, tx pgx.Tx, event events.DomainEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}

	const query = `
		INSERT INTO outbox_events (id, event_type, payload, occurred_at, created_at)
		VALUES ($1, $2, $3, $4, now())
	`

	_, err = tx.Exec(ctx, query,
		uuid.New(),
		event.EventName(),
		payload,
		event.OccurredAt(),
	)

	return err
}
