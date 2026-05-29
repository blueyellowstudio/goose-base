package fileManager

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/blueyellowstudio/goose-base/fileManager/domain"
	txpkg "github.com/blueyellowstudio/goose-base/tx"

	"github.com/google/uuid"
)

var ErrStoredFileNotFound = errors.New("stored file not found")
var ErrFileNotFound = errors.New("file not found")
var ErrFileObjectNotFound = errors.New("file object not found")

type Service struct {
	txRunner    txpkg.Runner
	files       domain.FileRepository
	folders     domain.FolderRepository
	objects     domain.FileObjectRepository
	storedFiles domain.StoredFileRepository
	domainCbs   domain.DomainCallbacks
	dbCbs       domain.DBCallbacks
	logger      *slog.Logger
}

func NewService(
	txRunner txpkg.Runner,
	files domain.FileRepository,
	folders domain.FolderRepository,
	objects domain.FileObjectRepository,
	storedFiles domain.StoredFileRepository,
	domainCbs domain.DomainCallbacks,
	dbCbs domain.DBCallbacks,
	logger *slog.Logger,
) *Service {
	if txRunner == nil {
		panic("fileManager.NewService: txRunner must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		txRunner:    txRunner,
		files:       files,
		folders:     folders,
		objects:     objects,
		storedFiles: storedFiles,
		domainCbs:   domainCbs,
		dbCbs:       dbCbs,
		logger:      logger,
	}
}

func (s *Service) runInTx(ctx context.Context, operation string, fn func(ctx context.Context, tx txpkg.Transaction) error) error {
	if err := s.txRunner.RunInTx(ctx, fn); err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}

	return nil
}

// CreateFolder creates a new folder, optionally under a parent.
func (s *Service) CreateFolder(ctx context.Context, folder domain.Folder) (*domain.Folder, error) {
	var result *domain.Folder
	err := s.runInTx(ctx, "create folder", func(ctx context.Context, tx txpkg.Transaction) error {
		var err error
		result, err = s.folders.Create(ctx, tx, folder)
		return err
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetFolderBreadcrumbs returns all ancestor folders (including the folder itself),
// ordered from root to the target folder.
func (s *Service) GetFolderBreadcrumbs(ctx context.Context, folderID uuid.UUID) ([]domain.Folder, error) {
	return s.folders.GetAncestors(ctx, folderID)
}

// RenameFolder updates the folder name.
func (s *Service) RenameFolder(ctx context.Context, folder domain.Folder) error {
	return s.runInTx(ctx, "rename folder", func(ctx context.Context, tx txpkg.Transaction) error {
		if err := s.folders.Update(ctx, tx, folder); err != nil {
			return fmt.Errorf("rename folder: %w", err)
		}

		return nil
	})
}

// SoftDeleteFolder soft-deletes a folder and all its descendants (subfolders + their files).
func (s *Service) SoftDeleteFolder(ctx context.Context, folderID uuid.UUID) error {
	return s.runInTx(ctx, "soft delete folder", func(ctx context.Context, tx txpkg.Transaction) error {
		folder, err := s.folders.GetByIDTx(ctx, tx, folderID)
		if err != nil {
			return fmt.Errorf("soft delete folder: lock: %w", err)
		}
		if folder == nil {
			return errors.New("folder not found")
		}

		deletedAt := time.Now()

		// Get entire subtree (includes the root folder itself, ordered parent-first)
		subtree, err := s.folders.GetSubtreeTx(ctx, tx, folderID)
		if err != nil {
			return fmt.Errorf("soft delete folder: get subtree: %w", err)
		}

		// Collect all folder IDs for file deletion
		folderIDs := make([]uuid.UUID, len(subtree))
		for i, f := range subtree {
			folderIDs[i] = f.ID
		}

		// Soft-delete all files in the subtree folders
		files, err := s.files.ListByFolderIDsTx(ctx, tx, folderIDs)
		if err != nil {
			return fmt.Errorf("soft delete folder: list files: %w", err)
		}
		for _, f := range files {
			if err := s.files.SoftDelete(ctx, tx, f.ID, deletedAt); err != nil {
				return fmt.Errorf("soft delete folder: soft delete file %s: %w", f.ID, err)
			}
			if err := s.domainCbs.FileSoftDeleted(ctx, tx, f); err != nil {
				return fmt.Errorf("soft delete folder: file callback %s: %w", f.ID, err)
			}
		}

		// Soft-delete all folders in subtree (leaf-last doesn't matter for soft-delete)
		for _, f := range subtree {
			if err := s.folders.SoftDelete(ctx, tx, f.ID, deletedAt); err != nil {
				return fmt.Errorf("soft delete folder: soft delete folder %s: %w", f.ID, err)
			}
			if err := s.domainCbs.FolderSoftDeleted(ctx, tx, f); err != nil {
				return fmt.Errorf("soft delete folder: folder callback %s: %w", f.ID, err)
			}
		}

		return nil
	})
}

// MoveFolder moves a folder under a new parent (or to root if newParentID is nil).
// Returns an error if the move would create a cycle.
func (s *Service) MoveFolder(ctx context.Context, folderID uuid.UUID, newParentID *uuid.UUID) error {
	return s.runInTx(ctx, "move folder", func(ctx context.Context, tx txpkg.Transaction) error {
		if newParentID != nil {
			// Cycle detection: newParentID must not be in the subtree of folderID
			subtree, err := s.folders.GetSubtreeTx(ctx, tx, folderID)
			if err != nil {
				return fmt.Errorf("move folder: get subtree: %w", err)
			}
			for _, f := range subtree {
				if f.ID == *newParentID {
					return errors.New("move folder: cycle detected — cannot move a folder into its own subtree")
				}
			}
		}

		if err := s.folders.Move(ctx, tx, folderID, newParentID); err != nil {
			return fmt.Errorf("move folder: %w", err)
		}

		return nil
	})
}

// CreateFile creates a new file record and calls the FileAdded callback.
func (s *Service) CreateFile(ctx context.Context, file domain.File) (*domain.File, error) {
	var result *domain.File
	err := s.runInTx(ctx, "create file", func(ctx context.Context, tx txpkg.Transaction) error {
		var createErr error
		result, createErr = s.files.Create(ctx, tx, file)
		if createErr != nil {
			return fmt.Errorf("create file: %w", createErr)
		}

		if err := s.dbCbs.FileAdded(ctx, tx, *result); err != nil {
			return fmt.Errorf("create file: callback: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetFile retrieves a file by ID.
func (s *Service) GetFile(ctx context.Context, id uuid.UUID) (*domain.File, error) {
	return s.files.GetByID(ctx, id)
}

// UpdateFile updates file metadata.
func (s *Service) UpdateFile(ctx context.Context, file domain.File) error {
	return s.runInTx(ctx, "update file", func(ctx context.Context, tx txpkg.Transaction) error {
		if err := s.files.Update(ctx, tx, file); err != nil {
			return fmt.Errorf("update file: %w", err)
		}

		return nil
	})
}

// SoftDeleteFile soft-deletes a file and emits the FileSoftDeleted event.
func (s *Service) SoftDeleteFile(ctx context.Context, fileID uuid.UUID) error {
	return s.runInTx(ctx, "soft delete file", func(ctx context.Context, tx txpkg.Transaction) error {
		file, err := s.files.GetByIDTx(ctx, tx, fileID)
		if err != nil {
			return fmt.Errorf("soft delete file: lock: %w", err)
		}
		if file == nil {
			return errors.New("file not found")
		}

		if err := s.files.SoftDelete(ctx, tx, fileID, time.Now()); err != nil {
			return fmt.Errorf("soft delete file: %w", err)
		}

		if err := s.domainCbs.FileSoftDeleted(ctx, tx, *file); err != nil {
			return fmt.Errorf("soft delete file: callback: %w", err)
		}

		return nil
	})
}

// MoveFile moves a file to a different folder (or to root if newFolderID is nil).
func (s *Service) MoveFile(ctx context.Context, fileID uuid.UUID, newFolderID *uuid.UUID) error {
	return s.runInTx(ctx, "move file", func(ctx context.Context, tx txpkg.Transaction) error {
		file, err := s.files.GetByIDTx(ctx, tx, fileID)
		if err != nil {
			return fmt.Errorf("move file: lock: %w", err)
		}
		if file == nil {
			return errors.New("file not found")
		}

		file.FolderID = newFolderID
		if err := s.files.Update(ctx, tx, *file); err != nil {
			return fmt.Errorf("move file: %w", err)
		}

		return nil
	})
}

// GetFolderContents returns the immediate children folders and files of a folder.
// Folders are not subject to file-level access filtering — any user with company permission can see them.
func (s *Service) GetFolderContents(ctx context.Context, parentID *uuid.UUID, filter domain.AccessFilter) ([]domain.Folder, []domain.FileWithObject, error) {
	folders, err := s.folders.ListChildren(ctx, parentID, domain.NoFilter{})
	if err != nil {
		return nil, nil, fmt.Errorf("get folder contents: folders: %w", err)
	}

	if parentID == nil {
		return folders, []domain.FileWithObject{}, nil
	}

	files, err := s.files.ListInFolder(ctx, *parentID, filter)
	if err != nil {
		return nil, nil, fmt.Errorf("get folder contents: files: %w", err)
	}

	return folders, files, nil
}

// GetFolderContentsPaged returns a page of folders and files in a folder, ordered by name.
// Fetches limit+1 items to detect whether a next page exists; the caller must trim the slice.
// nameSearch filters results by name substring (case-insensitive) when non-nil.
func (s *Service) GetFolderContentsPaged(
	ctx context.Context,
	parentID *uuid.UUID,
	filter domain.AccessFilter,
	folderCursor *domain.Cursor,
	fileCursor *domain.Cursor,
	limit int,
	nameSearch *string,
) (folders []domain.Folder, files []domain.FileWithObject, err error) {
	folders, err = s.folders.ListChildrenPaged(ctx, parentID, domain.NoFilter{}, folderCursor, limit+1, nameSearch)
	if err != nil {
		return nil, nil, fmt.Errorf("get folder contents paged: folders: %w", err)
	}

	files, err = s.files.ListInFolderPaged(ctx, parentID, filter, fileCursor, limit+1, nameSearch)
	if err != nil {
		return nil, nil, fmt.Errorf("get folder contents paged: files: %w", err)
	}

	return folders, files, nil
}

// GetDeviceDocuments returns all files accessible by a given device model.
func (s *Service) GetDeviceDocuments(ctx context.Context, filter domain.AccessFilter) ([]domain.File, error) {
	return s.files.ListFiles(ctx, filter)
}

// CreateFileObject creates a new file object variant.
func (s *Service) CreateFileObject(ctx context.Context, obj domain.FileObject) (*domain.FileObject, error) {
	var result *domain.FileObject
	err := s.runInTx(ctx, "create file object", func(ctx context.Context, tx txpkg.Transaction) error {
		var err error
		result, err = s.objects.Create(ctx, tx, obj)
		return err
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

// UpdateFileObject updates a file object.
func (s *Service) UpdateFileObject(ctx context.Context, obj domain.FileObject) error {
	return s.runInTx(ctx, "update file object", func(ctx context.Context, tx txpkg.Transaction) error {
		if err := s.objects.Update(ctx, tx, obj); err != nil {
			return fmt.Errorf("update file object: %w", err)
		}

		return nil
	})
}

// MarkFileObjectAvailable marks a file object as uploaded and available.
func (s *Service) MarkFileObjectAvailable(ctx context.Context, objectID uuid.UUID) error {
	return s.runInTx(ctx, "mark file object available", func(ctx context.Context, tx txpkg.Transaction) error {
		if err := s.objects.MarkAvailable(ctx, tx, objectID); err != nil {
			return fmt.Errorf("mark file object available: %w", err)
		}

		return nil
	})
}

// SoftDeleteFileObject soft-deletes a file object and all its associated StoredFiles.
func (s *Service) SoftDeleteFileObject(ctx context.Context, objectID uuid.UUID) error {
	return s.runInTx(ctx, "soft delete file object", func(ctx context.Context, tx txpkg.Transaction) error {
		if err := s.objects.SoftDelete(ctx, tx, objectID); err != nil {
			return fmt.Errorf("soft delete file object: %w", err)
		}

		anyMarkedDeleted, err := s.storedFiles.DeleteByFileObject(ctx, tx, objectID)
		if err != nil {
			return fmt.Errorf("soft delete file object: delete stored files by object: %w", err)
		}
		if anyMarkedDeleted {
			if err := s.domainCbs.AnyStoredFileMarkedDeleted(ctx, tx, domain.StoredFile{FileObjID: objectID}); err != nil {
				return fmt.Errorf("soft delete file object: stored file callback: %w", err)
			}
		}

		return nil
	})
}

// GenerateUploadLink creates a pending StoredFile and returns a pre-signed upload URL
// along with the StoredFile ID so the caller can activate it after upload completes.
func (s *Service) GenerateUploadLink(ctx context.Context, fileObjectID uuid.UUID) (string, uuid.UUID, error) {
	_, file, err := s.objects.GetFileObjectWithFile(ctx, fileObjectID)
	if err != nil {
		return "", uuid.Nil, fmt.Errorf("generate upload link: %w", err)
	}

	var storedFile *domain.StoredFile
	err = s.runInTx(ctx, "generate upload link", func(ctx context.Context, tx txpkg.Transaction) error {
		var createErr error
		storedFile, createErr = s.storedFiles.Create(ctx, tx, domain.StoredFile{
			FileObjID: fileObjectID,
			Status:    domain.StoredFileStatusPending,
		})
		return createErr
	})
	if err != nil {
		return "", uuid.Nil, err
	}

	// Call external storage outside the transaction to avoid holding DB locks during I/O.
	url, err := s.domainCbs.CreateUploadLinkForStoredFile(ctx, storedFile.ID, file.FileType)
	if err != nil {
		return "", uuid.Nil, fmt.Errorf("generate upload link: create url: %w", err)
	}

	return url, storedFile.ID, nil
}

func (s *Service) GenerateDownloadLink(ctx context.Context, fileObjectID uuid.UUID, download bool) (string, error) {
	fileObj, file, err := s.objects.GetFileObjectWithFile(ctx, fileObjectID)
	if err != nil {
		return "", fmt.Errorf("generate download link: %w", err)
	}
	if fileObj == nil || file == nil {
		return "", fmt.Errorf("generate download link: object %s: %w", fileObjectID, ErrFileObjectNotFound)
	}

	url, err := s.createDownloadLinkForResolvedFile(ctx, fileObj, file, download)
	if err != nil {
		return "", fmt.Errorf("generate download link: %w", err)
	}
	return url, nil
}

// ActivateStoredFile transitions a pending StoredFile to active, superseding any
// previously active StoredFile for the same FileObject. Idempotent if already active.
func (s *Service) ActivateStoredFile(ctx context.Context, storedFileID uuid.UUID) error {
	return s.runInTx(ctx, "activate stored file", func(ctx context.Context, tx txpkg.Transaction) error {
		storedFile, err := s.storedFiles.GetByIDTx(ctx, tx, storedFileID)
		if err != nil {
			return fmt.Errorf("lock: %w", err)
		}
		if storedFile == nil {
			return ErrStoredFileNotFound
		}
		if storedFile.Status == domain.StoredFileStatusActive {
			return nil
		}

		anyMarkedDeleted, err := s.storedFiles.SupersedeActiveByFileObject(ctx, tx, storedFile.FileObjID)
		if err != nil {
			return fmt.Errorf("supersede active siblings: %w", err)
		}
		if anyMarkedDeleted {
			if err := s.domainCbs.AnyStoredFileMarkedDeleted(ctx, tx, domain.StoredFile{FileObjID: storedFile.FileObjID}); err != nil {
				return fmt.Errorf("supersede callback: %w", err)
			}
		}

		storedFile.Status = domain.StoredFileStatusActive
		storedFile.DeletedAt = nil
		if err := s.storedFiles.Update(ctx, tx, *storedFile); err != nil {
			return fmt.Errorf("activate: %w", err)
		}

		if err := s.objects.MarkAvailable(ctx, tx, storedFile.FileObjID); err != nil {
			return fmt.Errorf("mark available: %w", err)
		}

		return nil
	})
}

// GetFileObject returns a file object by ID.
func (s *Service) GetFileObject(ctx context.Context, id uuid.UUID) (*domain.FileObject, error) {
	return s.objects.GetByID(ctx, id)
}

// ListFileObjects returns all file objects for a file.
func (s *Service) ListFileObjects(ctx context.Context, fileID uuid.UUID) ([]domain.FileObject, error) {
	return s.objects.ListByFile(ctx, fileID)
}

// GetAvailableFileObjects returns all available (uploaded) file objects for a file.
func (s *Service) GetAvailableFileObjects(ctx context.Context, fileID uuid.UUID) ([]domain.FileObject, error) {
	return s.objects.ListAvailableByFileIDs(ctx, []uuid.UUID{fileID})
}

