package outbox

import (
	"context"
	"eurodima/internal/domain/events"
)

// Handler processes domain events from the outbox.
// Handlers must be stateless and idempotent.
type Handler interface {
	// Handles returns true if this handler can process the given event type.
	Handles(eventType string) bool

	// Handle processes the domain event.
	// Implementations must be idempotent to handle at-least-once delivery.
	Handle(ctx context.Context, event events.DomainEvent) error
}
