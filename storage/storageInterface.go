package storage

import (
	"context"
	"errors"
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

// Storage defines the interface for file storage operations
type Storage interface {
	GenerateUploadURL(bucket, objectKey string, mimeType *string) (*UploadInfo, error)
	GenerateDownloadURL(bucket, objectKey, filename string, download bool) (*DownloadInfo, error)
	DeleteObject(bucket, objectKey string) error
	DeleteObjects(bucket string, objectKeys []string) error
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

// SignedStorage is a Storage whose upload URL signs the content type and whose download URL
// sets response headers (S3 backends). New methods take the context first.
type SignedStorage interface {
	Storage
	PresignUpload(ctx context.Context, bucket, objectKey, contentType string, ttl time.Duration) (*SignedUpload, error)
	PresignDownload(ctx context.Context, bucket, objectKey string, options DownloadOptions, ttl time.Duration) (*DownloadInfo, error)
	HeadObject(ctx context.Context, bucket, objectKey string) (*ObjectDetails, error) // ErrObjectNotFound when missing
	DeleteObjectContext(ctx context.Context, bucket, objectKey string) error          // nil for a missing key
}

// SignedUpload is a presigned upload: the client sends Method to URL with exactly Headers.
type SignedUpload struct {
	URL       string
	Method    string
	Headers   map[string]string
	ExpiresAt time.Time
}

// DownloadOptions are the response headers a presigned download URL asks for.
type DownloadOptions struct {
	FileName     string
	IsInline     bool
	CacheControl string
}

// ObjectDetails is what a HEAD reports about an object.
type ObjectDetails struct {
	Size         int64
	ContentType  string
	LastModified time.Time
}

// ErrObjectNotFound means the object does not exist.
var ErrObjectNotFound = errors.New("storage: object not found")
