package domain

import (
	"context"
	"time"

	txpkg "github.com/blueyellowstudio/goose-base/tx"

	"github.com/google/uuid"
)

type FileRepository interface {
	Create(ctx context.Context, tx txpkg.Transaction, file File) (*File, error)
	GetByID(ctx context.Context, id uuid.UUID) (*File, error)
	GetByIDTx(ctx context.Context, tx txpkg.Transaction, id uuid.UUID) (*File, error)
	Update(ctx context.Context, tx txpkg.Transaction, file File) error
	SoftDelete(ctx context.Context, tx txpkg.Transaction, id uuid.UUID, deletedAt time.Time) error
	ListInFolder(ctx context.Context, folderID uuid.UUID, filter AccessFilter, sort []SortBy) ([]FileWithObject, error)
	ListInFolderPaged(ctx context.Context, folderID *uuid.UUID, filter AccessFilter, cursor *Cursor, limit int, nameSearch *string, sort []SortBy) ([]FileWithObject, error)
	ListFiles(ctx context.Context, filter AccessFilter, sort []SortBy) ([]File, error)
	ListByFolderIDs(ctx context.Context, folderIDs []uuid.UUID) ([]File, error)
	ListByFolderIDsTx(ctx context.Context, tx txpkg.Transaction, folderIDs []uuid.UUID) ([]File, error)
}

type FolderRepository interface {
	Create(ctx context.Context, tx txpkg.Transaction, folder Folder) (*Folder, error)
	GetByID(ctx context.Context, id uuid.UUID) (*Folder, error)
	GetByIDTx(ctx context.Context, tx txpkg.Transaction, id uuid.UUID) (*Folder, error)
	Update(ctx context.Context, tx txpkg.Transaction, folder Folder) error
	SoftDelete(ctx context.Context, tx txpkg.Transaction, id uuid.UUID, deletedAt time.Time) error
	Move(ctx context.Context, tx txpkg.Transaction, folderID uuid.UUID, newParentID *uuid.UUID) error
	ListChildren(ctx context.Context, parentID *uuid.UUID, filter AccessFilter) ([]Folder, error)
	ListChildrenPaged(ctx context.Context, parentID *uuid.UUID, filter AccessFilter, cursor *Cursor, limit int, nameSearch *string) ([]Folder, error)
	GetSubtree(ctx context.Context, folderID uuid.UUID) ([]Folder, error)
	GetSubtreeTx(ctx context.Context, tx txpkg.Transaction, folderID uuid.UUID) ([]Folder, error)
	GetAncestors(ctx context.Context, folderID uuid.UUID) ([]Folder, error)
}

type FileObjectRepository interface {
	Create(ctx context.Context, tx txpkg.Transaction, obj FileObject) (*FileObject, error)
	GetByID(ctx context.Context, id uuid.UUID) (*FileObject, error)
	GetByFileAndLanguage(ctx context.Context, fileID uuid.UUID, languageID int) (*FileObject, error)
	GetDefaultByFile(ctx context.Context, fileID uuid.UUID) (*FileObject, error)
	GetFileObjectWithFile(ctx context.Context, id uuid.UUID) (*FileObject, *File, error)
	GetFileObjectWithFileTx(ctx context.Context, tx txpkg.Transaction, id uuid.UUID) (*FileObject, *File, error)
	Update(ctx context.Context, tx txpkg.Transaction, obj FileObject) error
	MarkAvailable(ctx context.Context, tx txpkg.Transaction, id uuid.UUID) error
	SoftDelete(ctx context.Context, tx txpkg.Transaction, id uuid.UUID) error
	ListByFile(ctx context.Context, fileID uuid.UUID) ([]FileObject, error)
	ListAvailableByFileIDs(ctx context.Context, fileIDs []uuid.UUID) ([]FileObject, error)
}

// StoredFileRepository manages StoredFile records, one per physical upload.
type StoredFileRepository interface {
	// Create inserts a new StoredFile row.
	Create(ctx context.Context, tx txpkg.Transaction, sf StoredFile) (*StoredFile, error)
	// Update persists changes to an existing StoredFile.
	Update(ctx context.Context, tx txpkg.Transaction, sf StoredFile) error
	// Delete soft-deletes a StoredFile by setting deleted_at.
	Delete(ctx context.Context, tx txpkg.Transaction, id uuid.UUID) error
	// DeleteByFileObject soft-deletes all non-deleted StoredFiles for a FileObject.
	DeleteByFileObject(ctx context.Context, tx txpkg.Transaction, fileObjID uuid.UUID) (bool, error)
	// SupersedeActiveByFileObject marks all active non-deleted StoredFiles for a FileObject as superseded and deleted.
	SupersedeActiveByFileObject(ctx context.Context, tx txpkg.Transaction, fileObjID uuid.UUID) (bool, error)
	// Remove hard-deletes a StoredFile row entirely.
	Remove(ctx context.Context, tx txpkg.Transaction, id uuid.UUID) error
	// GetByID retrieves a StoredFile by its ID.
	GetByID(ctx context.Context, id uuid.UUID) (*StoredFile, error)
	// GetByIDTx retrieves a StoredFile within a transaction with FOR UPDATE lock.
	GetByIDTx(ctx context.Context, tx txpkg.Transaction, id uuid.UUID) (*StoredFile, error)
	// GetLatestActive returns the most recently created active StoredFile for a FileObject.
	GetLatestActive(ctx context.Context, fileObjID uuid.UUID) (*StoredFile, error)
	// ListByFileObject returns all StoredFiles for a FileObject (including soft-deleted).
	ListByFileObject(ctx context.Context, fileObjID uuid.UUID) ([]StoredFile, error)
	// ListByFileObjectIDs returns all StoredFiles for a set of FileObjects in a single query.
	ListByFileObjectIDs(ctx context.Context, fileObjIDs []uuid.UUID) ([]StoredFile, error)
	// ListPendingOlderThan returns pending StoredFiles created before the cutoff time.
	ListPendingOlderThan(ctx context.Context, cutoff time.Time) ([]StoredFile, error)
	// ListDeleted returns all StoredFiles with deleted_at set.
	ListDeleted(ctx context.Context) ([]StoredFile, error)
}

// DeletedItemRepository provides read access to the deletion log. Entries are
// written by FileRepository.SoftDelete and FileObjectRepository.SoftDelete.
type DeletedItemRepository interface {
	// ListSince returns all deletion tombstones recorded after the given time, ordered by deleted_at ascending.
	ListSince(ctx context.Context, since time.Time) ([]DeletedItem, error)
}
