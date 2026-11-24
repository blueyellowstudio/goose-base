package domain

import (
	"time"

	"github.com/google/uuid"
)

type Folder struct {
	ID        uuid.UUID  `json:"id"`
	Path      string     `json:"path"` // ltree as string
	ParentID  *uuid.UUID `json:"parentID,omitempty"`
	Name      string     `json:"name"`
	NameRef   *uuid.UUID `json:"nameRef,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
	CreatedBy *uuid.UUID `json:"createdBy"` // nil once the creator's account is deleted
	DeletedAt *time.Time `json:"deletedAt,omitempty"`
	Metadata  []byte     `json:"metadata"`
}
