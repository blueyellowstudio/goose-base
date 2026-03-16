package storage

import (
	"time"
)

// StorageConfig holds configuration for local filesystem storage.
type StorageConfig struct {
	BaseDir        string
	SecretKey      string
	BaseURL        string
	UploadExpiry   time.Duration
	DownloadExpiry time.Duration
}

// SupabaseStorageConfig holds configuration for Supabase Storage.
type SupabaseStorageConfig struct {
	StorageURL       string
	StoragePublicURL string
	ServiceKey       string
	UploadExpiry     time.Duration
	DownloadExpiry   time.Duration
}

// Storage defines the interface for file storage operations
type Storage interface {
	GenerateUploadURL(bucket, objectKey string) (*UploadInfo, error)
	GenerateDownloadURL(bucket, objectKey, filename string) (*DownloadInfo, error)
	DeleteObject(bucket, objectKey string) error
	ListObjects(bucket, prefix string) ([]string, error)
	GetObjectInfo(bucket, objectKey string) (*ObjectInfo, error)
	FileExists(bucket, objectKey string) bool
}

// UploadInfo contains pre-signed upload URL details
type UploadInfo struct {
	URL       string    `json:"url"`
	ObjectKey string    `json:"object_key"`
	Bucket    string    `json:"bucket"`
	ExpiresAt time.Time `json:"expires_at"`
}

// DownloadInfo contains pre-signed download URL details
type DownloadInfo struct {
	URL       string    `json:"url"`
	Filename  string    `json:"filename"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ObjectInfo contains metadata about a stored object
type ObjectInfo struct {
	Size         int64
	LastModified time.Time
}
