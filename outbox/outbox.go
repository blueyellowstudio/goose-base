package outbox

import "time"

// DomainEvent represents a domain event that can be stored in and processed from the outbox.
type DomainEvent interface {
	EventName() string
	OccurredAt() time.Time
}
