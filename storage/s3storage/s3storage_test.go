package s3storage_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/blueyellowstudio/goose-base/storage"
	"github.com/blueyellowstudio/goose-base/storage/s3storage"
)

const s3tRegion = "us-east-1"

var (
	s3tOnce      sync.Once
	s3tStartErr  error
	s3tEndpoint  string
	s3tAccessKey string
	s3tSecretKey string
	s3tBucket    string
	s3tContainer testcontainers.Container
)

func TestMain(m *testing.M) {
	code := m.Run()
	if s3tContainer != nil {
		_ = testcontainers.TerminateContainer(s3tContainer)
	}
	os.Exit(code)
}

func TestPresignUploadSignsContentType(t *testing.T) {
	s, bucket := s3tStorage(t)
	ctx := t.Context()
	key := s3tPrefix(t) + "a.jpg"
	body := s3tBytes(1024, 0xff)

	before := time.Now()
	up, err := s.PresignUpload(ctx, bucket, key, "image/jpeg", 15*time.Minute)
	require.NoError(t, err)

	assert.Equal(t, "PUT", up.Method)
	assert.Equal(t, map[string]string{"Content-Type": "image/jpeg"}, up.Headers)
	assert.False(t, up.ExpiresAt.Before(before.Add(15*time.Minute)))
	assert.False(t, up.ExpiresAt.After(time.Now().Add(15*time.Minute)))

	parsed, err := url.Parse(up.URL)
	require.NoError(t, err)
	query := parsed.Query()
	assert.Equal(t, "content-type;host", query.Get("X-Amz-SignedHeaders"))
	for name := range query {
		lower := strings.ToLower(name)
		assert.False(t, strings.HasPrefix(lower, "x-amz-checksum"), "unexpected query key %s", name)
		assert.NotEqual(t, "x-amz-sdk-checksum-algorithm", lower)
	}

	status, _, _ := s3tSend(t, http.MethodPut, up.URL, "application/pdf", body)
	assert.Equal(t, http.StatusForbidden, status, "(a) other content type")

	query.Set("X-Amz-Signature", strings.Repeat("0", 64))
	parsed.RawQuery = query.Encode()
	status, _, _ = s3tSend(t, http.MethodPut, parsed.String(), "image/jpeg", body)
	assert.Equal(t, http.StatusForbidden, status, "(b) changed signature")

	_, err = s.HeadObject(ctx, bucket, key)
	assert.True(t, errors.Is(err, storage.ErrObjectNotFound), "(c) refused PUTs stored nothing: %v", err)

	status, _, _ = s3tSend(t, http.MethodPut, up.URL, "image/jpeg", body)
	assert.Equal(t, http.StatusOK, status, "(d) signed type")

	details, err := s.HeadObject(ctx, bucket, key)
	require.NoError(t, err)
	assert.Equal(t, int64(1024), details.Size)
	assert.Equal(t, "image/jpeg", details.ContentType)
}

func TestHeadObject(t *testing.T) {
	s, bucket := s3tStorage(t)
	ctx := t.Context()
	prefix := s3tPrefix(t)
	key := prefix + "b.pdf"
	s3tPut(t, s, bucket, key, "application/pdf", s3tBytes(2048, 1))

	details, err := s.HeadObject(ctx, bucket, key)
	require.NoError(t, err)
	assert.Equal(t, int64(2048), details.Size)
	assert.Equal(t, "application/pdf", details.ContentType)
	assert.WithinDuration(t, time.Now(), details.LastModified, 5*time.Minute)

	missing, err := s.HeadObject(ctx, bucket, prefix+"missing.pdf")
	assert.True(t, errors.Is(err, storage.ErrObjectNotFound), "got %v", err)
	assert.Nil(t, missing)
}

func TestPresignDownloadSetsResponseHeaders(t *testing.T) {
	s, bucket := s3tStorage(t)
	ctx := t.Context()
	key := s3tPrefix(t) + "c.jpg"
	s3tPut(t, s, bucket, key, "image/jpeg", []byte("receipt-bytes"))

	t.Run("inline", func(t *testing.T) {
		before := time.Now()
		info, err := s.PresignDownload(ctx, bucket, key, storage.DownloadOptions{
			FileName:     "Beleg März.jpg",
			IsInline:     true,
			CacheControl: "private, no-store",
		}, 5*time.Minute)
		require.NoError(t, err)

		status, header, body := s3tSend(t, http.MethodGet, info.URL, "", nil)

		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, "receipt-bytes", string(body))
		assert.Equal(t, "private, no-store", header.Get("Cache-Control"))
		assert.Equal(t, "inline; filename*=UTF-8''Beleg%20M%C3%A4rz.jpg", header.Get("Content-Disposition"))
		assert.Equal(t, "Beleg März.jpg", info.Filename)
		assert.False(t, info.ExpiresAt.Before(before.Add(5*time.Minute)))
		assert.False(t, info.ExpiresAt.After(time.Now().Add(5*time.Minute)))
	})

	t.Run("attachment", func(t *testing.T) {
		info, err := s.PresignDownload(ctx, bucket, key, storage.DownloadOptions{
			FileName: "a.pdf",
			IsInline: false,
		}, 5*time.Minute)
		require.NoError(t, err)

		parsed, err := url.Parse(info.URL)
		require.NoError(t, err)
		assert.NotContains(t, parsed.Query(), "response-cache-control")

		status, header, _ := s3tSend(t, http.MethodGet, info.URL, "", nil)

		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, "attachment; filename*=UTF-8''a.pdf", header.Get("Content-Disposition"))
	})
}

func TestDeleteObject(t *testing.T) {
	s, bucket := s3tStorage(t)
	ctx := t.Context()
	prefix := s3tPrefix(t)
	key := prefix + "d.jpg"
	key2 := prefix + "d2.jpg"
	s3tPut(t, s, bucket, key, "image/jpeg", s3tBytes(10, 3))
	s3tPut(t, s, bucket, key2, "image/jpeg", s3tBytes(10, 4))

	require.NoError(t, s.DeleteObject(bucket, key))
	_, err := s.HeadObject(ctx, bucket, key)
	assert.True(t, errors.Is(err, storage.ErrObjectNotFound), "got %v", err)

	assert.NoError(t, s.DeleteObject(bucket, prefix+"never.jpg"))

	require.NoError(t, s.DeleteObjectContext(ctx, bucket, key2))
	_, err = s.HeadObject(ctx, bucket, key2)
	assert.True(t, errors.Is(err, storage.ErrObjectNotFound), "got %v", err)

	assert.NoError(t, s.DeleteObjectContext(ctx, bucket, prefix+"never2.jpg"))

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	err = s.DeleteObjectContext(cancelled, bucket, key2)
	assert.True(t, errors.Is(err, context.Canceled), "got %v", err)
}

func TestListObjectsReadsEveryPage(t *testing.T) {
	s, bucket := s3tStorage(t)
	s3storage.SetListPageSize(s, 2)
	prefix := s3tPrefix(t)
	var want []string
	for i := 1; i <= 5; i++ {
		key := fmt.Sprintf("%sp/%d", prefix, i)
		want = append(want, key)
		s3tPut(t, s, bucket, key, "image/jpeg", s3tBytes(5, 1))
	}
	s3tPut(t, s, bucket, prefix+"q/1", "image/jpeg", s3tBytes(5, 1))

	got, err := s.ListObjects(bucket, prefix+"p/")

	require.NoError(t, err)
	assert.ElementsMatch(t, want, got)
	assert.Len(t, got, 5)
}

func TestDeleteObjectsInChunks(t *testing.T) {
	s, bucket := s3tStorage(t)
	s3storage.SetListPageSize(s, 2)
	prefix := s3tPrefix(t)
	keys := []string{prefix + "1", prefix + "2", prefix + "3"}
	for _, key := range keys {
		s3tPut(t, s, bucket, key, "image/jpeg", s3tBytes(5, 1))
	}

	require.NoError(t, s.DeleteObjects(bucket, keys))
	remaining, err := s.ListObjects(bucket, prefix)
	require.NoError(t, err)
	assert.Empty(t, remaining)

	assert.NoError(t, s.DeleteObjects(bucket, nil))
}

func TestGenerateUploadURLOldMethod(t *testing.T) {
	s, bucket := s3tStorage(t)
	prefix := s3tPrefix(t)
	key := prefix + "e.png"
	key2 := prefix + "f.bin"
	mimeType := "image/png"

	before := time.Now()
	info, err := s.GenerateUploadURL(bucket, key, &mimeType)
	require.NoError(t, err)

	assert.Equal(t, bucket, info.Bucket)
	assert.Equal(t, key, info.ObjectKey)
	assert.False(t, info.ExpiresAt.Before(before.Add(15*time.Minute)))
	assert.False(t, info.ExpiresAt.After(time.Now().Add(15*time.Minute)))
	assert.Equal(t, "content-type;host", s3tQuery(t, info.URL).Get("X-Amz-SignedHeaders"))

	status, _, _ := s3tSend(t, http.MethodPut, info.URL, "image/png", s3tBytes(64, 7))
	assert.Equal(t, http.StatusOK, status)
	details, err := s.HeadObject(t.Context(), bucket, key)
	require.NoError(t, err)
	assert.Equal(t, "image/png", details.ContentType)

	info2, err := s.GenerateUploadURL(bucket, key2, nil)
	require.NoError(t, err)
	assert.Equal(t, "host", s3tQuery(t, info2.URL).Get("X-Amz-SignedHeaders"))
	status, _, _ = s3tSend(t, http.MethodPut, info2.URL, "application/octet-stream", s3tBytes(64, 7))
	assert.Equal(t, http.StatusOK, status)
}

func TestGenerateDownloadURLOldMethod(t *testing.T) {
	s, bucket := s3tStorage(t)
	key := s3tPrefix(t) + "g.pdf"
	s3tPut(t, s, bucket, key, "application/pdf", []byte("pdf-bytes"))

	before := time.Now()
	download, err := s.GenerateDownloadURL(bucket, key, "x.pdf", true)
	require.NoError(t, err)
	status, header, body := s3tSend(t, http.MethodGet, download.URL, "", nil)

	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "pdf-bytes", string(body))
	assert.Equal(t, "attachment; filename*=UTF-8''x.pdf", header.Get("Content-Disposition"))
	assert.False(t, download.ExpiresAt.Before(before.Add(time.Hour)))
	assert.False(t, download.ExpiresAt.After(time.Now().Add(time.Hour)))
	assert.Equal(t, "x.pdf", download.Filename)

	plain, err := s.GenerateDownloadURL(bucket, key, "x.pdf", false)
	require.NoError(t, err)
	status, header, body = s3tSend(t, http.MethodGet, plain.URL, "", nil)

	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "pdf-bytes", string(body))
	assert.Empty(t, header.Get("Content-Disposition"))
}

func TestGetObjectInfoAndFileExists(t *testing.T) {
	s, bucket := s3tStorage(t)
	prefix := s3tPrefix(t)
	key := prefix + "h.jpg"
	s3tPut(t, s, bucket, key, "image/jpeg", s3tBytes(300, 2))

	info, err := s.GetObjectInfo(bucket, key)
	require.NoError(t, err)
	assert.Equal(t, int64(300), info.Size)
	assert.WithinDuration(t, time.Now(), info.LastModified, 5*time.Minute)
	assert.True(t, s.FileExists(bucket, key))

	missing, err := s.GetObjectInfo(bucket, prefix+"none.jpg")
	assert.True(t, errors.Is(err, storage.ErrObjectNotFound), "got %v", err)
	assert.Nil(t, missing)
	assert.False(t, s.FileExists(bucket, prefix+"none.jpg"))
}

func TestDeleteObjectMissingKeyOn404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code := "NoSuchKey"
		if r.URL.Path == "/nobucket/x.jpg" {
			code = "NoSuchBucket"
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>x</Message></Error>`, code)
	}))
	defer server.Close()
	s, err := s3storage.New(&s3storage.Config{Endpoint: server.URL, AccessKey: "a", SecretKey: "b"})
	require.NoError(t, err)

	assert.NoError(t, s.DeleteObject("b", "gone.jpg"))
	assert.Error(t, s.DeleteObject("nobucket", "x.jpg"))
}

func TestNewRefusesIncompleteConfig(t *testing.T) {
	const endpoint = "http://127.0.0.1:1"
	tests := []struct {
		name    string
		cfg     *s3storage.Config
		wantErr bool
	}{
		{"nil config", nil, true},
		{"no endpoint", &s3storage.Config{AccessKey: "a", SecretKey: "b"}, true},
		{"no access key", &s3storage.Config{Endpoint: endpoint, SecretKey: "b"}, true},
		{"no secret key", &s3storage.Config{Endpoint: endpoint, AccessKey: "a"}, true},
		{"complete", &s3storage.Config{Endpoint: endpoint, AccessKey: "a", SecretKey: "b"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := s3storage.New(tt.cfg)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, s)
				return
			}
			assert.NoError(t, err)
			assert.NotNil(t, s)
		})
	}
}

// s3tStorage returns a storage on the shared test server and its bucket, starting the server once.
func s3tStorage(t *testing.T) (*s3storage.Storage, string) {
	t.Helper()
	if os.Getenv("GOOSE_S3_TEST_ENDPOINT") == "" {
		testcontainers.SkipIfProviderIsNotHealthy(t)
	}
	s3tOnce.Do(func() { s3tStartErr = s3tStartServer(t.Context()) })
	require.NoError(t, s3tStartErr)

	s, err := s3storage.New(&s3storage.Config{
		Endpoint:  s3tEndpoint,
		Region:    s3tRegion,
		AccessKey: s3tAccessKey,
		SecretKey: s3tSecretKey,
	})
	require.NoError(t, err)
	s3tWaitReady(t, s)
	return s, s3tBucket
}

func s3tStartServer(ctx context.Context) error {
	if endpoint := os.Getenv("GOOSE_S3_TEST_ENDPOINT"); endpoint != "" {
		s3tEndpoint = endpoint
		s3tAccessKey = os.Getenv("GOOSE_S3_TEST_ACCESS_KEY")
		s3tSecretKey = os.Getenv("GOOSE_S3_TEST_SECRET_KEY")
		s3tBucket = os.Getenv("GOOSE_S3_TEST_BUCKET")
		if s3tBucket == "" {
			s3tBucket = "goose-s3-test"
		}
		return nil
	}

	var err error
	if s3tAccessKey, err = s3tRandomHex(); err != nil {
		return err
	}
	if s3tSecretKey, err = s3tRandomHex(); err != nil {
		return err
	}
	s3tBucket = "goose-s3-test"
	// Not the request context: the container outlives the first test that starts it.
	container, err := testcontainers.GenericContainer(context.WithoutCancel(ctx), testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "chrislusf/seaweedfs:4.51",
			Cmd:          []string{"mini", "-dir=/data", "-bucket=" + s3tBucket},
			Env:          map[string]string{"AWS_ACCESS_KEY_ID": s3tAccessKey, "AWS_SECRET_ACCESS_KEY": s3tSecretKey},
			ExposedPorts: []string{"8333/tcp"},
			WaitingFor:   wait.ForListeningPort("8333/tcp"),
		},
		Started: true,
	})
	s3tContainer = container
	if err != nil {
		return err
	}
	s3tEndpoint, err = container.PortEndpoint(ctx, "8333/tcp", "http")
	return err
}

// s3tWaitReady polls until the bucket answers; it is created a moment after the port opens.
func s3tWaitReady(t *testing.T, s *s3storage.Storage) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		_, err := s.ListObjects(s3tBucket, "")
		if err == nil {
			return
		}
		require.True(t, time.Now().Before(deadline), "bucket not ready after 60s: %v", err)
		time.Sleep(250 * time.Millisecond)
	}
}

func s3tRandomHex() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func s3tPrefix(t *testing.T) string {
	t.Helper()
	suffix, err := s3tRandomHexN(4)
	require.NoError(t, err)
	return "t/" + strings.ReplaceAll(t.Name(), "/", "-") + "-" + suffix + "/"
}

func s3tRandomHexN(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func s3tPut(t *testing.T, s *s3storage.Storage, bucket, key, contentType string, body []byte) {
	t.Helper()
	up, err := s.PresignUpload(t.Context(), bucket, key, contentType, 15*time.Minute)
	require.NoError(t, err)
	status, _, _ := s3tSend(t, http.MethodPut, up.URL, contentType, body)
	require.Equal(t, http.StatusOK, status)
}

func s3tSend(t *testing.T, method, url, contentType string, body []byte) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, url, bytes.NewReader(body))
	require.NoError(t, err)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, resp.Header, respBody
}

func s3tBytes(size int, fill byte) []byte {
	return bytes.Repeat([]byte{fill}, size)
}

func s3tQuery(t *testing.T, rawURL string) url.Values {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	require.NoError(t, err)
	return parsed.Query()
}
