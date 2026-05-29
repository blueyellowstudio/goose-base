package directFileAccess

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// DirectFileAccess exposes file-level download metadata and signed URL access.
type DirectFileAccess interface {
	GetFileDownloadMeta(ctx context.Context, fileID uuid.UUID, languageID *int) (FileDownloadMeta, error)
	GetFileDownloadURL(ctx context.Context, fileID uuid.UUID, languageID *int, download bool) (string, error)
}

// FileDownloadMeta describes the latest active downloadable variant of a file.
type FileDownloadMeta struct {
	FileType      *string   `json:"fileType,omitempty"`
	FileSize      *int64    `json:"fileSize,omitempty"`
	FileUpdatedAt time.Time `json:"fileUpdatedAt"`
	MetaUpdatedAt time.Time `json:"metaUpdatedAt"`
	Name          string    `json:"name"`
	FileExtension string    `json:"fileExtension"`
	LanguageID    *int      `json:"languageId,omitempty"`
}
