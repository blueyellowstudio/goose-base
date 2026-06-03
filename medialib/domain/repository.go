package domain

import (
	"context"
	"time"

	txpkg "github.com/blueyellowstudio/goose-base/tx"

	"github.com/google/uuid"
)

// MediaRepository persists the logical asset slot.
type MediaRepository interface {
	Create(ctx context.Context, tx txpkg.Transaction, media Media) (*Media, error)
	Update(ctx context.Context, tx txpkg.Transaction, media Media) error
	GetByID(ctx context.Context, id uuid.UUID) (*Media, error)
	// GetByIDTx loads a media row within a transaction, locking it with
	// FOR UPDATE to serialize concurrent object activations on the same media.
	GetByIDTx(ctx context.Context, tx txpkg.Transaction, id uuid.UUID) (*Media, error)
	// ListWithActiveObjectByIDs loads many media by id, each paired with its
	// active object (nil when none), in a single LEFT JOIN query. Used to
	// resolve read URLs for a whole page of media without per-id round-trips.
	ListWithActiveObjectByIDs(ctx context.Context, ids []uuid.UUID) ([]MediaWithActiveObject, error)
	SoftDelete(ctx context.Context, tx txpkg.Transaction, id uuid.UUID, deletedAt time.Time) error
	HardDelete(ctx context.Context, tx txpkg.Transaction, id uuid.UUID) error
}

// MediaObjectRepository persists physical uploads.
type MediaObjectRepository interface {
	Create(ctx context.Context, tx txpkg.Transaction, obj MediaObject) (*MediaObject, error)
	Update(ctx context.Context, tx txpkg.Transaction, obj MediaObject) error
	GetByID(ctx context.Context, id uuid.UUID) (*MediaObject, error)
	GetActiveByMediaID(ctx context.Context, mediaID uuid.UUID) (*MediaObject, error)
	ListByMediaID(ctx context.Context, mediaID uuid.UUID) ([]MediaObject, error)
	// SupersedeActiveByMediaID marks the currently active, non-deleted object of
	// a media as deleted (status=deleted, deleted_at=now). Returns whether a row
	// was affected. Must be called inside the media-row lock during activation.
	SupersedeActiveByMediaID(ctx context.Context, tx txpkg.Transaction, mediaID uuid.UUID) (bool, error)
	HardDelete(ctx context.Context, tx txpkg.Transaction, id uuid.UUID) error
}

// DeletionRepository persists the hard-deletion trail.
type DeletionRepository interface {
	Create(ctx context.Context, tx txpkg.Transaction, deletion MediaObjectDeletion) (*MediaObjectDeletion, error)
	ListSince(ctx context.Context, since time.Time) ([]MediaObjectDeletion, error)
}
