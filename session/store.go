package session

import "context"

// Store persists sessions by id. Ids are hex SHA-256 store keys, never raw cookie values.
type Store interface {
	// Get returns a copy of the session, or ErrNotFound.
	Get(ctx context.Context, id string) (*Session, error)
	Put(ctx context.Context, s *Session) error
	// Delete of an absent id is not an error.
	Delete(ctx context.Context, id string) error
}
