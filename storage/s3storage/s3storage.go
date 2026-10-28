// Package s3storage is the storage backend for S3-compatible services (Supabase's S3 protocol,
// SeaweedFS, AWS). It implements storage.Storage and storage.SignedStorage.
package s3storage

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/blueyellowstudio/goose-base/storage"
)

const (
	defaultRegion         = "us-east-1"
	defaultUploadExpiry   = 15 * time.Minute
	defaultDownloadExpiry = time.Hour
	defaultListPageSize   = 1000
	requestTimeout        = 30 * time.Second
	noSuchKeyCode         = "NoSuchKey"
)

// Config configures a Storage. Presigned URLs name Endpoint, so it must be the host clients call.
type Config struct {
	Endpoint       string
	Region         string // default us-east-1
	AccessKey      string
	SecretKey      string
	UploadExpiry   time.Duration // default 15 min
	DownloadExpiry time.Duration // default 1 h
}

// Storage stores objects in an S3-compatible bucket. See docu/storage.md.
type Storage struct {
	client         *s3.Client
	presigner      *s3.PresignClient
	uploadExpiry   time.Duration
	downloadExpiry time.Duration
	listPageSize   int32 // MaxKeys of a list page and size of a batch delete (S3 allows 1000)
}

var _ storage.Storage = (*Storage)(nil)
var _ storage.SignedStorage = (*Storage)(nil)

// New validates cfg and builds the client. Ambient AWS environment and config files are not read.
func New(cfg *Config) (*Storage, error) {
	if cfg == nil {
		return nil, errors.New("s3storage: config is nil")
	}
	if cfg.Endpoint == "" || cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, errors.New("s3storage: endpoint, access key and secret key are required")
	}

	client := s3.New(s3.Options{
		Region:                     valueOr(cfg.Region, defaultRegion),
		BaseEndpoint:               aws.String(cfg.Endpoint),
		UsePathStyle:               true,
		Credentials:                credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, ""),
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
		HTTPClient:                 awshttp.NewBuildableClient().WithTimeout(requestTimeout),
	})

	return &Storage{
		client:         client,
		presigner:      s3.NewPresignClient(client),
		uploadExpiry:   expiryOr(cfg.UploadExpiry, defaultUploadExpiry),
		downloadExpiry: expiryOr(cfg.DownloadExpiry, defaultDownloadExpiry),
		listPageSize:   defaultListPageSize,
	}, nil
}

// PresignUpload returns a PUT URL that only accepts the given content type. A ttl <= 0 uses the default.
func (s *Storage) PresignUpload(ctx context.Context, bucket, objectKey, contentType string, ttl time.Duration) (*storage.SignedUpload, error) {
	ttl = expiryOr(ttl, s.uploadExpiry)
	expiresAt := time.Now().Add(ttl)
	signed, err := s.presigner.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket:      &bucket,
		Key:         &objectKey,
		ContentType: &contentType,
	}, s3.WithPresignExpires(ttl))
	if err != nil {
		return nil, objectError("presign upload", bucket, objectKey, err)
	}
	return &storage.SignedUpload{
		URL:       signed.URL,
		Method:    http.MethodPut,
		Headers:   map[string]string{"Content-Type": contentType},
		ExpiresAt: expiresAt,
	}, nil
}

// PresignDownload returns a GET URL whose response carries the requested headers. A ttl <= 0 uses the default.
func (s *Storage) PresignDownload(ctx context.Context, bucket, objectKey string, options storage.DownloadOptions, ttl time.Duration) (*storage.DownloadInfo, error) {
	ttl = expiryOr(ttl, s.downloadExpiry)
	input := &s3.GetObjectInput{
		Bucket:                     &bucket,
		Key:                        &objectKey,
		ResponseContentDisposition: contentDisposition(options),
	}
	if options.CacheControl != "" {
		input.ResponseCacheControl = &options.CacheControl
	}
	return s.presignGet(ctx, input, options.FileName, ttl)
}

// HeadObject reports size, content type and modification time; a missing object yields storage.ErrObjectNotFound.
func (s *Storage) HeadObject(ctx context.Context, bucket, objectKey string) (*storage.ObjectDetails, error) {
	out, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &objectKey})
	if err != nil {
		return nil, headError(bucket, objectKey, err)
	}
	return &storage.ObjectDetails{
		Size:         aws.ToInt64(out.ContentLength),
		ContentType:  aws.ToString(out.ContentType),
		LastModified: aws.ToTime(out.LastModified),
	}, nil
}

// DeleteObjectContext deletes an object; a missing key is not an error.
func (s *Storage) DeleteObjectContext(ctx context.Context, bucket, objectKey string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &objectKey})
	if err != nil && !hasErrorCode(err, noSuchKeyCode) {
		return objectError("delete", bucket, objectKey, err)
	}
	return nil
}

// GenerateUploadURL signs the content type only when mimeType is given.
func (s *Storage) GenerateUploadURL(bucket, objectKey string, mimeType *string) (*storage.UploadInfo, error) {
	expiresAt := time.Now().Add(s.uploadExpiry)
	signed, err := s.presigner.PresignPutObject(context.Background(), &s3.PutObjectInput{
		Bucket:      &bucket,
		Key:         &objectKey,
		ContentType: mimeType,
	}, s3.WithPresignExpires(s.uploadExpiry))
	if err != nil {
		return nil, objectError("presign upload", bucket, objectKey, err)
	}
	return &storage.UploadInfo{URL: signed.URL, ObjectKey: objectKey, Bucket: bucket, ExpiresAt: expiresAt}, nil
}

// GenerateDownloadURL names the file (attachment) only when download is true.
func (s *Storage) GenerateDownloadURL(bucket, objectKey, filename string, download bool) (*storage.DownloadInfo, error) {
	input := &s3.GetObjectInput{Bucket: &bucket, Key: &objectKey}
	if download {
		input.ResponseContentDisposition = contentDisposition(storage.DownloadOptions{FileName: filename})
	}
	return s.presignGet(context.Background(), input, filename, s.downloadExpiry)
}

// DeleteObject deletes an object; a missing key is not an error.
func (s *Storage) DeleteObject(bucket, objectKey string) error {
	return s.DeleteObjectContext(context.Background(), bucket, objectKey)
}

// DeleteObjects deletes the keys in batches; missing keys are not errors.
func (s *Storage) DeleteObjects(bucket string, objectKeys []string) error {
	for start := 0; start < len(objectKeys); start += int(s.listPageSize) {
		end := min(start+int(s.listPageSize), len(objectKeys))
		if err := s.deleteBatch(bucket, objectKeys[start:end]); err != nil {
			return err
		}
	}
	return nil
}

// ListObjects returns the full keys of all objects under prefix, across pages.
func (s *Storage) ListObjects(bucket, prefix string) ([]string, error) {
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket:  &bucket,
		Prefix:  &prefix,
		MaxKeys: &s.listPageSize,
	})
	var keys []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return nil, fmt.Errorf("s3storage: list bucket %q prefix %q: %w", bucket, prefix, err)
		}
		for _, object := range page.Contents {
			keys = append(keys, aws.ToString(object.Key))
		}
	}
	return keys, nil
}

// GetObjectInfo reports size and modification time; a missing object yields storage.ErrObjectNotFound.
func (s *Storage) GetObjectInfo(bucket, objectKey string) (*storage.ObjectInfo, error) {
	details, err := s.HeadObject(context.Background(), bucket, objectKey)
	if err != nil {
		return nil, err
	}
	return &storage.ObjectInfo{Size: details.Size, LastModified: details.LastModified}, nil
}

// FileExists is false for a missing object and for any failure to find out.
func (s *Storage) FileExists(bucket, objectKey string) bool {
	_, err := s.HeadObject(context.Background(), bucket, objectKey)
	return err == nil
}

func (s *Storage) presignGet(ctx context.Context, input *s3.GetObjectInput, filename string, ttl time.Duration) (*storage.DownloadInfo, error) {
	expiresAt := time.Now().Add(ttl)
	signed, err := s.presigner.PresignGetObject(ctx, input, s3.WithPresignExpires(ttl))
	if err != nil {
		return nil, objectError("presign download", aws.ToString(input.Bucket), aws.ToString(input.Key), err)
	}
	return &storage.DownloadInfo{URL: signed.URL, Filename: filename, ExpiresAt: expiresAt}, nil
}

func (s *Storage) deleteBatch(bucket string, keys []string) error {
	identifiers := make([]types.ObjectIdentifier, len(keys))
	for i := range keys {
		identifiers[i] = types.ObjectIdentifier{Key: &keys[i]}
	}
	out, err := s.client.DeleteObjects(context.Background(), &s3.DeleteObjectsInput{
		Bucket: &bucket,
		Delete: &types.Delete{Objects: identifiers, Quiet: aws.Bool(true)},
	})
	if err != nil {
		return fmt.Errorf("s3storage: delete objects in bucket %q: %w", bucket, err)
	}
	for _, failure := range out.Errors {
		if aws.ToString(failure.Code) != noSuchKeyCode {
			return fmt.Errorf("s3storage: delete object %q in bucket %q: %s: %s",
				aws.ToString(failure.Key), bucket, aws.ToString(failure.Code), aws.ToString(failure.Message))
		}
	}
	return nil
}

func headError(bucket, objectKey string, err error) error {
	if isNotFound(err) {
		return fmt.Errorf("s3storage: object %q in bucket %q: %w", objectKey, bucket, storage.ErrObjectNotFound)
	}
	return objectError("head", bucket, objectKey, err)
}

func objectError(operation, bucket, objectKey string, err error) error {
	return fmt.Errorf("s3storage: %s %q in bucket %q: %w", operation, objectKey, bucket, err)
}

// isNotFound matches the HTTP status because a HEAD answer has no body to carry an error code.
func isNotFound(err error) bool {
	var responseErr *awshttp.ResponseError
	return errors.As(err, &responseErr) && responseErr.HTTPStatusCode() == http.StatusNotFound
}

func hasErrorCode(err error, code string) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == code
}

// contentDisposition percent-encodes the name as RFC 5987 filename*.
func contentDisposition(options storage.DownloadOptions) *string {
	disposition := "attachment"
	if options.IsInline {
		disposition = "inline"
	}
	if options.FileName == "" {
		return aws.String(disposition)
	}
	encodedName := strings.ReplaceAll(url.QueryEscape(options.FileName), "+", "%20")
	return aws.String(disposition + "; filename*=UTF-8''" + encodedName)
}

func expiryOr(ttl, fallback time.Duration) time.Duration {
	if ttl <= 0 {
		return fallback
	}
	return ttl
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
