package dto

import "github.com/google/uuid"

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
