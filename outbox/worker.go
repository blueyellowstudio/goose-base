package outbox

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WorkerConfig holds configuration for the outbox worker.
type WorkerConfig struct {
	BatchSize    int
	MaxRetries   int
	PollInterval time.Duration
}

// DefaultWorkerConfig returns sensible default configuration.
func DefaultWorkerConfig() WorkerConfig {
	return WorkerConfig{
		BatchSize:    100,
		MaxRetries:   5,
		PollInterval: time.Second,
	}
}

// Worker processes events from the outbox table.
// It supports multiple concurrent instances through database row locking.
type Worker struct {
	pool     *pgxpool.Pool
	repo     *Repository
	registry *EventRegistry
	handlers []Handler
	config   WorkerConfig
	logger   *slog.Logger
}

// NewWorker creates a new outbox worker.
func NewWorker(
	pool *pgxpool.Pool,
	repo *Repository,
	registry *EventRegistry,
	handlers []Handler,
	config WorkerConfig,
	logger *slog.Logger,
) *Worker {
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{
		pool:     pool,
		repo:     repo,
		registry: registry,
		handlers: handlers,
		config:   config,
		logger:   logger,
	}
}

// Run starts the worker loop. It blocks until the context is cancelled.
func (w *Worker) Run(ctx context.Context) error {

	w.logger.Info("outbox worker started",
		"batch_size", w.config.BatchSize,
		"max_retries", w.config.MaxRetries,
		"poll_interval", w.config.PollInterval,
	)

	ticker := time.NewTicker(w.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("outbox worker stopping")
			return ctx.Err()
		case <-ticker.C:
			if err := w.processBatch(ctx); err != nil {
				w.logger.Error("failed to process batch", "error", err)
			}
		}
	}
}

// processBatch fetches and processes a batch of events within a transaction.
func (w *Worker) processBatch(ctx context.Context) error {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	events, err := w.repo.FetchBatchTx(ctx, tx, w.config.BatchSize)
	if err != nil {
		return err
	}

	if len(events) == 0 {
		return nil
	}

	w.logger.Debug("processing batch", "count", len(events))

	for _, outboxEvent := range events {
		if err := w.processEvent(ctx, outboxEvent); err != nil {
			w.logger.Error("failed to process event",
				"event_id", outboxEvent.ID,
				"event_type", outboxEvent.EventType,
				"error", err,
			)

			err := w.handleFailure(ctx, tx, outboxEvent, err)
			if err != nil {
				w.logger.Error("failed to handle failure",
					"event_id", outboxEvent.ID,
					"event_type", outboxEvent.EventType,
					"error", err,
				)
			}
		} else {
			err := w.repo.MarkProcessedTx(ctx, tx, outboxEvent.ID)
			if err != nil {
				w.logger.Error("failed to mark processed",
					"event_id", outboxEvent.ID,
					"event_type", outboxEvent.EventType,
					"error", err,
				)
			}
		}
	}

	return tx.Commit(ctx)
}

// processEvent handles a single event, routing it to the appropriate handler.
func (w *Worker) processEvent(ctx context.Context, outboxEvent OutboxEvent) error {
	domainEvent, err := w.registry.Deserialize(outboxEvent.EventType, outboxEvent.Payload)
	if err != nil {
		w.logger.Error("failed to deserialize event",
			"event_id", outboxEvent.ID,
			"event_type", outboxEvent.EventType,
			"error", err,
		)
		return err
	}

	handler := w.findHandler(outboxEvent.EventType)
	if handler == nil {
		w.logger.Warn("no handler for event type", "event_type", outboxEvent.EventType)
		return nil
	}

	if err := handler.Handle(ctx, domainEvent); err != nil {
		w.logger.Error("handler failed",
			"event_id", outboxEvent.ID,
			"event_type", outboxEvent.EventType,
			"error", err,
		)
		return err
	}

	return nil
}

// findHandler returns the first handler that can process the given event type.
func (w *Worker) findHandler(eventType string) Handler {
	for _, h := range w.handlers {
		if h.Handles(eventType) {
			return h
		}
	}
	return nil
}

// handleFailure decides whether to retry or move to dead letter.
func (w *Worker) handleFailure(ctx context.Context, tx pgx.Tx, event OutboxEvent, err error) error {
	newRetryCount := event.RetryCount + 1

	if newRetryCount >= w.config.MaxRetries {
		w.logger.Warn("moving event to dead letter",
			"event_id", event.ID,
			"event_type", event.EventType,
			"retry_count", newRetryCount,
		)
		return w.repo.MoveToDeadLetter(ctx, tx, event, err.Error())
	}

	return w.repo.MarkFailedTx(ctx, tx, event.ID, err.Error())
}
