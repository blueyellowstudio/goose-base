package storage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"eurodima/internal/config"
)

// FileStorage implements the Storage interface using local filesystem
type FileStorage struct {
	baseDir   string
	secretKey string
	baseURL   string
	config    *config.StorageConfig
}

// NewFileStorage creates a new FileStorage instance
func NewFileStorage(cfg *config.StorageConfig) (*FileStorage, error) {
	// Ensure base directory exists
	if err := os.MkdirAll(cfg.BaseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}

	return &FileStorage{
		baseDir:   cfg.BaseDir,
		secretKey: cfg.SecretKey,
		baseURL:   strings.TrimSuffix(cfg.BaseURL, "/"),
		config:    cfg,
	}, nil
}

// signURL creates an HMAC signature for a URL
func (s *FileStorage) signURL(method, key string, exp int64) string {
	mac := hmac.New(sha256.New, []byte(s.secretKey))
	payload := fmt.Sprintf("%s:%s:%d", method, key, exp)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// GenerateUploadURL creates a signed URL for uploading a file
func (s *FileStorage) GenerateUploadURL(bucket, objectKey string) (*UploadInfo, error) {
	expiry := s.config.UploadExpiry
	if expiry > 7*24*time.Hour {
		expiry = 7 * 24 * time.Hour
	}

	exp := time.Now().Add(expiry).Unix()
	key := filepath.Join(bucket, objectKey)
	sig := s.signURL(http.MethodPut, key, exp)

	params := url.Values{}
	params.Set("key", key)
	params.Set("exp", strconv.FormatInt(exp, 10))
	params.Set("sig", sig)

	uploadURL := fmt.Sprintf("%s/file/upload?%s", s.baseURL, params.Encode())

	slog.Info("Generated upload URL",
		"bucket", bucket,
		"object_key", objectKey,
		"expiry", expiry,
	)

	return &UploadInfo{
		URL:       uploadURL,
		ObjectKey: objectKey,
		Bucket:    bucket,
		ExpiresAt: time.Now().Add(expiry),
	}, nil
}

// GenerateDownloadURL creates a signed URL for downloading a file
func (s *FileStorage) GenerateDownloadURL(bucket, objectKey, filename string) (*DownloadInfo, error) {
	// Verify object exists
	fullPath, err := s.safePath(filepath.Join(bucket, objectKey))
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("object not found: %s/%s", bucket, objectKey)
	}

	expiry := s.config.DownloadExpiry
	if expiry > 7*24*time.Hour {
		expiry = 7 * 24 * time.Hour
	}

	exp := time.Now().Add(expiry).Unix()
	key := filepath.Join(bucket, objectKey)
	sig := s.signURL(http.MethodGet, key, exp)

	params := url.Values{}
	params.Set("key", key)
	params.Set("exp", strconv.FormatInt(exp, 10))
	params.Set("sig", sig)
	if filename != "" {
		params.Set("filename", sanitizeFilename(filename))
	}

	downloadURL := fmt.Sprintf("%s/file/download?%s", s.baseURL, params.Encode())

	slog.Info("Generated download URL",
		"bucket", bucket,
		"object_key", objectKey,
		"expiry", expiry,
	)

	return &DownloadInfo{
		URL:       downloadURL,
		Filename:  filename,
		ExpiresAt: time.Now().Add(expiry),
	}, nil
}

// DeleteObject removes a file from storage
func (s *FileStorage) DeleteObject(bucket, objectKey string) error {
	fullPath, err := s.safePath(filepath.Join(bucket, objectKey))
	if err != nil {
		return err
	}

	if err := os.Remove(fullPath); err != nil {
		if os.IsNotExist(err) {
			return nil // Already deleted
		}
		return fmt.Errorf("failed to delete object: %w", err)
	}

	slog.Info("Deleted object", "bucket", bucket, "object_key", objectKey)
	return nil
}

// ListObjects lists all objects in a bucket with optional prefix
func (s *FileStorage) ListObjects(bucket, prefix string) ([]string, error) {
	bucketPath, err := s.safePath(bucket)
	if err != nil {
		return nil, err
	}

	var objects []string
	searchPath := bucketPath
	if prefix != "" {
		searchPath = filepath.Join(bucketPath, prefix)
	}

	err = filepath.WalkDir(searchPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if !d.IsDir() {
			relPath, _ := filepath.Rel(bucketPath, path)
			objects = append(objects, relPath)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error listing objects: %w", err)
	}

	return objects, nil
}

// GetObjectInfo retrieves metadata about an object
func (s *FileStorage) GetObjectInfo(bucket, objectKey string) (*ObjectInfo, error) {
	fullPath, err := s.safePath(filepath.Join(bucket, objectKey))
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get object info: %w", err)
	}

	return &ObjectInfo{
		Size:         info.Size(),
		LastModified: info.ModTime(),
	}, nil
}

// FileExists checks if a file exists
func (s *FileStorage) FileExists(bucket, objectKey string) bool {
	fullPath, err := s.safePath(filepath.Join(bucket, objectKey))
	if err != nil {
		return false
	}

	_, err = os.Stat(fullPath)
	return err == nil
}

// ValidateSignature validates the signature of a signed URL request
func (s *FileStorage) ValidateSignature(r *http.Request, expectedMethod string) (string, error) {
	if r.Method != expectedMethod {
		return "", errors.New("invalid method")
	}

	key := r.URL.Query().Get("key")
	expStr := r.URL.Query().Get("exp")
	sig := r.URL.Query().Get("sig")

	if key == "" || expStr == "" || sig == "" {
		return "", errors.New("missing parameters")
	}

	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", errors.New("expired or invalid exp")
	}

	expectedSig := s.signURL(expectedMethod, key, exp)
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return "", errors.New("invalid signature")
	}

	return key, nil
}

// safePath validates and returns a safe filesystem path
func (s *FileStorage) safePath(key string) (string, error) {
	if strings.Contains(key, "..") {
		return "", errors.New("invalid path")
	}

	clean := filepath.Clean("/" + key)
	full := filepath.Join(s.baseDir, clean)

	if !strings.HasPrefix(full, filepath.Clean(s.baseDir)) {
		return "", errors.New("path traversal detected")
	}

	return full, nil
}

// UploadHandler handles file uploads via signed URL
func (s *FileStorage) UploadHandler(w http.ResponseWriter, r *http.Request) {
	key, err := s.ValidateSignature(r, http.MethodPut)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	path, err := s.safePath(key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		http.Error(w, "failed to create directory", http.StatusInternalServerError)
		return
	}

	dst, err := os.Create(path)
	if err != nil {
		http.Error(w, "failed to create file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, r.Body); err != nil {
		http.Error(w, "upload failed", http.StatusInternalServerError)
		return
	}

	slog.Info("File uploaded", "key", key)
	w.WriteHeader(http.StatusCreated)
}

// DownloadHandler handles file downloads via signed URL
func (s *FileStorage) DownloadHandler(w http.ResponseWriter, r *http.Request) {
	key, err := s.ValidateSignature(r, http.MethodGet)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	path, err := s.safePath(key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Set Content-Disposition if filename is provided
	if filename := r.URL.Query().Get("filename"); filename != "" {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", sanitizeFilename(filename)))
	}

	http.ServeFile(w, r, path)
}

// sanitizeFilename removes or replaces characters that could cause header injection
func sanitizeFilename(filename string) string {
	filename = strings.ReplaceAll(filename, "\"", "")
	filename = strings.ReplaceAll(filename, "'", "")
	filename = strings.ReplaceAll(filename, "\n", "")
	filename = strings.ReplaceAll(filename, "\r", "")
	filename = strings.ReplaceAll(filename, "\x00", "")
	filename = strings.ReplaceAll(filename, ";", "_")
	filename = strings.ReplaceAll(filename, ":", "_")
	filename = strings.ReplaceAll(filename, ",", "_")
	return filename
}
