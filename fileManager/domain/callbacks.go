package domain

import (
	"context"

	txpkg "github.com/blueyellowstudio/goose-base/tx"

	"github.com/google/uuid"
)

// DomainCallbacks are implemented by the project layer and called by the
// fileManager service at key lifecycle points.
type DomainCallbacks interface {
	// CreateUploadLinkForStoredFile returns a pre-signed URL for uploading to a StoredFile's storage slot.
	CreateUploadLinkForStoredFile(ctx context.Context, storedFileID uuid.UUID, fileType *string) (string, error)

	// CreateDownloadLinkForFile returns a pre-signed URL for downloading a StoredFile.
	CreateDownloadLinkForFile(ctx context.Context, storedFileID uuid.UUID, filename string, download bool) (string, error)

	// FileSoftDeleted is called within the soft-delete transaction so the project
	// layer can write an outbox event atomically.
	FileSoftDeleted(ctx context.Context, tx txpkg.Transaction, file File) error

	// FolderSoftDeleted is called within the soft-delete transaction for each
	// folder that is soft-deleted.
	FolderSoftDeleted(ctx context.Context, tx txpkg.Transaction, folder Folder) error

	// AnyStoredFileMarkedDeleted is called after a stored file is marked deleted.
	AnyStoredFileMarkedDeleted(ctx context.Context, tx txpkg.Transaction, sf StoredFile) error
}

// DBCallbacks are called by the service at DB lifecycle points.
// Implementations may be no-ops.
type DBCallbacks interface {
	// FileAdded is called within the create-file transaction.
	FileAdded(ctx context.Context, tx txpkg.Transaction, file File) error

	// FileDeleted is called within the hard-delete transaction (background worker).
	FileDeleted(ctx context.Context, tx txpkg.Transaction, file File) error

	// StoredFileDeleted is called before a StoredFile is hard-deleted from the database.
	StoredFileDeleted(ctx context.Context, tx txpkg.Transaction, sf StoredFile) error
}
