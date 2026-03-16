package storage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SupabaseStorage implements the Storage interface using Supabase Storage
type SupabaseStorage struct {
	storageURL       string
	storagePublicURL string
	serviceKey       string
	httpClient       *http.Client
	downloadExpiry   time.Duration
	uploadExpiry     time.Duration
}

// NewSupabaseStorage creates a new SupabaseStorage instance
func NewSupabaseStorage(cfg *SupabaseStorageConfig) (*SupabaseStorage, error) {
	if cfg.StorageURL == "" {
		return nil, fmt.Errorf("storage URL is required")
	}
	if cfg.ServiceKey == "" {
		return nil, fmt.Errorf("service key is required")
	}
	if cfg.StoragePublicURL == "" {
		return nil, fmt.Errorf("storage public URL is required")
	}

	downloadExpiry := cfg.DownloadExpiry
	if downloadExpiry == 0 {
		downloadExpiry = time.Hour
	}

	uploadExpiry := cfg.UploadExpiry
	if uploadExpiry == 0 {
		uploadExpiry = 15 * time.Minute
	}

	return &SupabaseStorage{
		storageURL:       strings.TrimSuffix(cfg.StorageURL, "/"),
		storagePublicURL: strings.TrimSuffix(cfg.StoragePublicURL, "/"),
		serviceKey:       cfg.ServiceKey,
		httpClient:       &http.Client{Timeout: 30 * time.Second},
		downloadExpiry:   downloadExpiry,
		uploadExpiry:     uploadExpiry,
	}, nil
}

// GenerateUploadURL creates a signed URL for uploading a file to Supabase Storage
func (s *SupabaseStorage) GenerateUploadURL(bucket, objectKey string) (*UploadInfo, error) {
	// Supabase Storage API: POST /object/upload/sign/{bucket}/{path}
	endpoint := fmt.Sprintf("%s/object/upload/sign/%s/%s", s.storageURL, bucket, objectKey)

	req, err := http.NewRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	s.setAuthHeaders(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request signed upload URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get signed upload URL: %s - %s", resp.Status, string(body))
	}

	var result struct {
		URL   string `json:"url"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Construct the full upload URL with token
	uploadURL := fmt.Sprintf("%s/object/upload/sign/%s/%s?token=%s",
		s.storagePublicURL, bucket, objectKey, url.QueryEscape(result.Token))

	expiresAt := time.Now().Add(s.uploadExpiry)

	slog.Info("Generated Supabase upload URL",
		"bucket", bucket,
		"object_key", objectKey,
		"expiry", s.uploadExpiry,
	)

	return &UploadInfo{
		URL:       uploadURL,
		ObjectKey: objectKey,
		Bucket:    bucket,
		ExpiresAt: expiresAt,
	}, nil
}

// GenerateDownloadURL creates a signed URL for downloading a file from Supabase Storage
func (s *SupabaseStorage) GenerateDownloadURL(bucket, objectKey, filename string) (*DownloadInfo, error) {
	// First verify the object exists
	if !s.FileExists(bucket, objectKey) {
		return nil, fmt.Errorf("object not found: %s/%s", bucket, objectKey)
	}

	// Supabase Storage API: POST /object/sign/{bucket}/{path}
	endpoint := fmt.Sprintf("%s/object/sign/%s/%s", s.storageURL, bucket, objectKey)

	expirySeconds := int(s.downloadExpiry.Seconds())
	body := map[string]interface{}{
		"expiresIn": expirySeconds,
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	s.setAuthHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request signed download URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get signed download URL: %s - %s", resp.Status, string(respBody))
	}

	var result struct {
		SignedURL string `json:"signedURL"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	downloadURL := result.SignedURL
	// Add download parameter if filename is specified
	if filename != "" {
		separator := "?"
		if strings.Contains(downloadURL, "?") {
			separator = "&"
		}
		downloadURL = fmt.Sprintf("%s%s%sdownload=%s", s.storagePublicURL, downloadURL, separator, url.QueryEscape(filename))
	}

	slog.Info("Generated Supabase download URL",
		"bucket", bucket,
		"object_key", objectKey,
		"expiry", s.downloadExpiry,
	)

	return &DownloadInfo{
		URL:       downloadURL,
		Filename:  filename,
		ExpiresAt: time.Now().Add(s.downloadExpiry),
	}, nil
}

// DeleteObject removes a file from Supabase Storage
func (s *SupabaseStorage) DeleteObject(bucket, objectKey string) error {
	// Supabase Storage API: DELETE /object/{bucket}/{path}
	endpoint := fmt.Sprintf("%s/object/%s/%s", s.storageURL, bucket, objectKey)

	req, err := http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	s.setAuthHeaders(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete object: %w", err)
	}
	defer resp.Body.Close()

	// 200 OK or 404 Not Found are both acceptable
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete object: %s - %s", resp.Status, string(body))
	}

	slog.Info("Deleted object from Supabase", "bucket", bucket, "object_key", objectKey)
	return nil
}

// ListObjects lists all objects in a bucket with optional prefix
func (s *SupabaseStorage) ListObjects(bucket, prefix string) ([]string, error) {
	// Supabase Storage API: POST /object/list/{bucket}
	endpoint := fmt.Sprintf("%s/object/list/%s", s.storageURL, bucket)

	body := map[string]interface{}{
		"prefix": prefix,
		"limit":  1000,
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	s.setAuthHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list objects: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list objects: %s - %s", resp.Status, string(respBody))
	}

	var items []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	objects := make([]string, 0, len(items))
	for _, item := range items {
		if prefix != "" {
			objects = append(objects, prefix+"/"+item.Name)
		} else {
			objects = append(objects, item.Name)
		}
	}

	return objects, nil
}

// GetObjectInfo retrieves metadata about an object
func (s *SupabaseStorage) GetObjectInfo(bucket, objectKey string) (*ObjectInfo, error) {
	// Use HEAD request to get object metadata
	endpoint := fmt.Sprintf("%s/object/%s/%s", s.storageURL, bucket, objectKey)

	req, err := http.NewRequest(http.MethodHead, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	s.setAuthHeaders(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get object info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("object not found: %s/%s", bucket, objectKey)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get object info: %s", resp.Status)
	}

	size := int64(0)
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		size, _ = strconv.ParseInt(contentLength, 10, 64)
	}

	lastModified := time.Now()
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		if parsed, err := time.Parse(http.TimeFormat, lm); err == nil {
			lastModified = parsed
		}
	}

	return &ObjectInfo{
		Size:         size,
		LastModified: lastModified,
	}, nil
}

// FileExists checks if a file exists in Supabase Storage
func (s *SupabaseStorage) FileExists(bucket, objectKey string) bool {
	endpoint := fmt.Sprintf("%s/object/%s/%s", s.storageURL, bucket, objectKey)

	req, err := http.NewRequest(http.MethodHead, endpoint, nil)
	if err != nil {
		return false
	}

	s.setAuthHeaders(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// setAuthHeaders sets the required authentication headers for Supabase API requests
func (s *SupabaseStorage) setAuthHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+s.serviceKey)
	req.Header.Set("apikey", s.serviceKey)
}

// Ensure SupabaseStorage implements Storage interface
var _ Storage = (*SupabaseStorage)(nil)
