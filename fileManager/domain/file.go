package domain

import (
	"time"

	"github.com/google/uuid"
)

type File struct {
	ID        uuid.UUID  `json:"id"`
	FolderID  *uuid.UUID `json:"folderId"`
	Name      string     `json:"name"`
	NameRef   *uuid.UUID `json:"nameRef,omitempty"`
	UserID    uuid.UUID  `json:"userId"`
	Category  int        `json:"category"`
	FileType  *string    `json:"fileType,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
	UpdatedAt time.Time  `json:"updatedAt"`
	DeletedAt *time.Time `json:"deletedAt,omitempty"`
	Metadata  []byte     `json:"metadata"`
}

type FileObject struct {
	ID               uuid.UUID  `json:"id"`
	FileID           uuid.UUID  `json:"fileId"`
	Name             string     `json:"name"`
	OriginalFileName string     `json:"originalFileName"`
	LanguageID       *int       `json:"languageId,omitempty"`
	IsAvailable      bool       `json:"isAvailable"`
	UpdatedAt        time.Time  `json:"updatedAt"`
	DeletedAt        *time.Time `json:"deletedAt,omitempty"`
	Metadata         []byte     `json:"metadata"`
}

type FileWithObject struct {
	File
	FileObject *FileObject `json:"fileObject,omitempty"`
}

type StoredFileStatus string

const (
	StoredFileStatusPending    StoredFileStatus = "pending"
	StoredFileStatusActive     StoredFileStatus = "active"
	StoredFileStatusSuperseded StoredFileStatus = "superseded"
)

// StoredFile represents a physical file stored in object storage.
// Each upload attempt creates a new StoredFile; only one can be active per FileObject.
type StoredFile struct {
	ID        uuid.UUID        `json:"id"`
	FileObjID uuid.UUID        `json:"fileObjectId"`
	FileSize  *int64           `json:"fileSize,omitempty"`
	Status    StoredFileStatus `json:"status"`
	CreatedAt time.Time        `json:"createdAt"`
	DeletedAt *time.Time       `json:"deletedAt,omitempty"`
}
