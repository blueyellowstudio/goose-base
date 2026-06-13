package domain

import (
	"time"

	"github.com/google/uuid"
)

type DeletedItemType string

const (
	DeletedItemTypeFile       DeletedItemType = "file"
	DeletedItemTypeFileObject DeletedItemType = "file_object"
)

// DeletedItem is a tombstone recorded when a File or FileObject is soft-deleted,
// used by offline clients to discover and purge locally cached objects.
type DeletedItem struct {
	ID         uuid.UUID       `json:"id"`
	EntityType DeletedItemType `json:"entityType"`
	EntityID   uuid.UUID       `json:"entityId"`
	FileID     uuid.UUID       `json:"fileId"`
	DeletedAt  time.Time       `json:"deletedAt"`
}
