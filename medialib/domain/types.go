package domain

import (
	"time"

	"github.com/google/uuid"
)

// Media is the logical asset slot. It carries no application meaning (name,
// description, …) — those live on app-side link tables. A media groups one or
// more MediaObjects, of which at most one is active at a time.
type Media struct {
	ID         uuid.UUID  `json:"id"`
	StorageKey string     `json:"storageKey"`
	Type       string     `json:"type"`
	CreatedAt  time.Time  `json:"createdAt"`
	UpdatedAt  time.Time  `json:"updatedAt"`
	DeletedAt  *time.Time `json:"deletedAt,omitempty"`
}

// MediaObjectStatus is the lifecycle of a physical upload.
type MediaObjectStatus string

const (
	MediaObjectStatusPending MediaObjectStatus = "pending"
	MediaObjectStatusActive  MediaObjectStatus = "active"
	MediaObjectStatusDeleted MediaObjectStatus = "deleted"
)

// ProcessingStatus tracks optional server-side processing (e.g. video poster
// extraction). Images need no processing — Supabase resolves sizes on the fly.
type ProcessingStatus string

const (
	ProcessingStatusPending    ProcessingStatus = "pending"
	ProcessingStatusProcessing ProcessingStatus = "processing"
	ProcessingStatusDone       ProcessingStatus = "done"
	ProcessingStatusFailed     ProcessingStatus = "failed"
)

// MediaObject is a single physical upload against a Media. The storage object
// URL is derived from its id at runtime. Each re-upload creates a new row;
// exactly one object per media may be active.
type MediaObject struct {
	ID               uuid.UUID         `json:"id"`
	MediaID          uuid.UUID         `json:"mediaId"`
	Status           MediaObjectStatus `json:"status"`
	ProcessingStatus ProcessingStatus  `json:"processingStatus"`
	SizeBytes        *int64            `json:"sizeBytes,omitempty"`
	MimeType         *string           `json:"mimeType,omitempty"`
	Extension        *string           `json:"extension,omitempty"`
	CreatedAt        time.Time         `json:"createdAt"`
	UpdatedAt        time.Time         `json:"updatedAt"`
	DeletedAt        *time.Time        `json:"deletedAt,omitempty"`
}

// MediaWithActiveObject is a media row paired with its single active object,
// if any (Object is nil when no object is active yet). It is the row shape of
// the batched media⋈active-object read used to resolve many media at once.
type MediaWithActiveObject struct {
	Media  Media
	Object *MediaObject
}

// MediaObjectDeletion is a deletion-trail entry written when a MediaObject is
// hard deleted. Clients pull entries after a timestamp to purge stale caches.
type MediaObjectDeletion struct {
	ID            uuid.UUID `json:"id"`
	MediaObjectID uuid.UUID `json:"mediaObjectId"`
	StoragePath   string    `json:"storagePath"`
	DeletedAt     time.Time `json:"deletedAt"`
}
