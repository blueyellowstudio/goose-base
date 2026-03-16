package outbox

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OutboxEvent represents an event stored in the outbox table.
type OutboxEvent struct {
	ID          uuid.UUID
	EventType   string
	Payload     []byte
	OccurredAt  time.Time
	ProcessedAt *time.Time
	RetryCount  int
	LastError   *string
	CreatedAt   time.Time
}

// Repository provides database operations for the outbox.
type Repository struct {
	pool *pgxpool.Pool
}

// NewRepository creates a new outbox repository.
func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

// FetchBatch retrieves a batch of unprocessed events using FOR UPDATE SKIP LOCKED
// to enable concurrent workers without conflicts.
func (r *Repository) FetchBatch(ctx context.Context, limit int) ([]OutboxEvent, error) {
	const query = `
		SELECT id, event_type, payload, occurred_at, processed_at, retry_count, last_error, created_at
		FROM outbox_events
		WHERE processed_at IS NULL
		ORDER BY occurred_at
		LIMIT $1
		FOR UPDATE SKIP LOCKED
	`

	rows, err := r.pool.Query(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []OutboxEvent
	for rows.Next() {
		var e OutboxEvent
		err := rows.Scan(
			&e.ID,
			&e.EventType,
			&e.Payload,
			&e.OccurredAt,
			&e.ProcessedAt,
			&e.RetryCount,
			&e.LastError,
			&e.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		events = append(events, e)
	}

	return events, rows.Err()
}

// FetchBatchTx retrieves a batch of unprocessed events within a transaction.
func (r *Repository) FetchBatchTx(ctx context.Context, tx pgx.Tx, limit int) ([]OutboxEvent, error) {
	const query = `
		SELECT id, event_type, payload, occurred_at, processed_at, retry_count, last_error, created_at
		FROM outbox_events
		WHERE processed_at IS NULL
		ORDER BY occurred_at
		LIMIT $1
		FOR UPDATE SKIP LOCKED
	`

	rows, err := tx.Query(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []OutboxEvent
	for rows.Next() {
		var e OutboxEvent
		err := rows.Scan(
			&e.ID,
			&e.EventType,
			&e.Payload,
			&e.OccurredAt,
			&e.ProcessedAt,
			&e.RetryCount,
			&e.LastError,
			&e.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		events = append(events, e)
	}

	return events, rows.Err()
}

// MarkProcessed marks an event as successfully processed.
func (r *Repository) MarkProcessed(ctx context.Context, id uuid.UUID) error {
	const query = `
		UPDATE outbox_events
		SET processed_at = now()
		WHERE id = $1
	`
	_, err := r.pool.Exec(ctx, query, id)
	return err
}

// MarkProcessedTx marks an event as successfully processed within a transaction.
func (r *Repository) MarkProcessedTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	const query = `
		UPDATE outbox_events
		SET processed_at = now()
		WHERE id = $1
	`
	_, err := tx.Exec(ctx, query, id)
	return err
}

// MarkFailed increments the retry count and stores the error message.
func (r *Repository) MarkFailed(ctx context.Context, id uuid.UUID, errMsg string) error {
	const query = `
		UPDATE outbox_events
		SET retry_count = retry_count + 1,
		    last_error = $2
		WHERE id = $1
	`
	_, err := r.pool.Exec(ctx, query, id, errMsg)
	return err
}

// MarkFailedTx increments the retry count and stores the error message within a transaction.
func (r *Repository) MarkFailedTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, errMsg string) error {
	const query = `
		UPDATE outbox_events
		SET retry_count = retry_count + 1,
		    last_error = $2
		WHERE id = $1
	`
	_, err := tx.Exec(ctx, query, id, errMsg)
	return err
}

// MoveToDeadLetter moves a failed event to the dead letter table and marks it processed.
func (r *Repository) MoveToDeadLetter(ctx context.Context, tx pgx.Tx, event OutboxEvent, errMsg string) error {

	const insertQuery = `
		INSERT INTO outbox_dead_letter_events 
			(id, original_event_id, event_type, payload, occurred_at, failed_at, retry_count, last_error)
		VALUES ($1, $2, $3, $4, $5, now(), $6, $7)
	`
	_, err := tx.Exec(ctx, insertQuery,
		uuid.New(),
		event.ID,
		event.EventType,
		event.Payload,
		event.OccurredAt,
		event.RetryCount,
		errMsg,
	)
	if err != nil {
		return err
	}

	const updateQuery = `
		UPDATE outbox_events
		SET processed_at = now(),
		    last_error = $2
		WHERE id = $1
	`
	_, err = tx.Exec(ctx, updateQuery, event.ID, errMsg)
	if err != nil {
		return err
	}

	return nil
}

