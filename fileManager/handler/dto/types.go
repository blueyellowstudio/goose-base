package dto

import (
	"encoding/json"

	"github.com/blueyellowstudio/goose-base/fileManager/domain"
	"github.com/google/uuid"
)

type CreateFolderRequest struct {
	Name     string     `json:"name"`
	ParentID *uuid.UUID `json:"parentId,omitempty"`
}

type RenameFolderRequest struct {
	Name string `json:"name"`
}

type MoveFolderRequest struct {
	NewParentID *uuid.UUID `json:"newParentId"`
}

type MoveFileRequest struct {
	NewFolderID *uuid.UUID `json:"newFolderId"`
}

type CreateFileObjectRequest struct {
	Name             string `json:"name"`
	LanguageID       *int   `json:"languageId,omitempty"`
	OriginalFileName string `json:"originalFileName"`
}

type UpdateFileObjectRequest struct {
	Name             string  `json:"name"`
	LanguageID       *int    `json:"languageId,omitempty"`
	OriginalFileName *string `json:"originalFileName,omitempty"`
}

type URLResponse struct {
	URL          string    `json:"url"`
	StoredFileID uuid.UUID `json:"storedFileId,omitempty"`
}

type BreadcrumbItem struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// FolderContentsResponse is the paginated response for folder browse endpoints.
// Files uses json.RawMessage so consumers can inject enriched DTOs without
// the library depending on project-specific types.
type FolderContentsResponse struct {
	Folders          []domain.Folder `json:"folders"`
	FolderNextCursor *string         `json:"folderNextCursor,omitempty"`
	Files            json.RawMessage `json:"files"`
	FileNextCursor   *string         `json:"fileNextCursor,omitempty"`
}

// FolderFilesResponse is the paginated response for the files-only endpoint.
type FolderFilesResponse struct {
	Files          json.RawMessage `json:"files"`
	FileNextCursor *string         `json:"fileNextCursor,omitempty"`
}
