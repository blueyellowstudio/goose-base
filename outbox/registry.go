package outbox

import (
	"encoding/json"
	"errors"
	"eurodima/internal/domain/events"
)

// ErrUnknownEventType is returned when an event type is not registered.
var ErrUnknownEventType = errors.New("unknown event type")

// EventRegistry provides explicit mapping from event type names to their concrete types.
// No reflection or dynamic typing is used.
type EventRegistry struct {
	factories map[string]func() events.DomainEvent
}

// NewEventRegistry creates a new event registry with all known event types registered.
func NewEventRegistry() *EventRegistry {
	r := &EventRegistry{
		factories: make(map[string]func() events.DomainEvent),
	}

	return r
}

// Register adds a new event type to the registry.
func (r *EventRegistry) Register(eventType string, factory func() events.DomainEvent) {
	r.factories[eventType] = factory
}

// Deserialize converts raw JSON payload into a concrete DomainEvent based on the event type.
func (r *EventRegistry) Deserialize(eventType string, payload []byte) (events.DomainEvent, error) {
	factory, ok := r.factories[eventType]
	if !ok {
		return nil, ErrUnknownEventType
	}

	event := factory()
	if err := json.Unmarshal(payload, event); err != nil {
		return nil, err
	}

	return event, nil
}

// IsRegistered checks if an event type is registered in the registry.
func (r *EventRegistry) IsRegistered(eventType string) bool {
	_, ok := r.factories[eventType]
	return ok
}
