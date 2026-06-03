// Package medialib is a reusable, entity-agnostic library for semi-public media
// asset management. Assets are visible to any logged-in user and identical for
// all of them; storage and on-the-fly image resizing are delegated to Supabase.
//
// The library owns the asset lifecycle: upload via presigned URL, re-upload,
// a single active object per asset, soft/hard deletion, and a deletion trail for
// client cache invalidation. It knows nothing about the application entities that
// reference its media — those links live on app-side tables.
package medialib

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	domain "github.com/blueyellowstudio/goose-base/medialib/domain"
	"github.com/blueyellowstudio/goose-base/storage"
	txpkg "github.com/blueyellowstudio/goose-base/tx"

	"github.com/google/uuid"
)

var (
	ErrMediaNotFound       = errors.New("media not found")
	ErrMediaObjectNotFound = errors.New("media object not found")
	ErrObjectNotUploaded   = errors.New("media object not uploaded")
	ErrNoActiveObject      = errors.New("no active media object")
)

// Service is the library's public API. It orchestrates the media repositories,
// the injected object Storage, and read-URL building.
type Service struct {
	txRunner  txpkg.Runner
	media     domain.MediaRepository
	objects   domain.MediaObjectRepository
	deletions domain.DeletionRepository
	store     storage.Storage
	urls      *URLBuilder
	bucket    string
	logger    *slog.Logger
}

// NewService wires the library. txRunner, the repositories, store and urls must
// be non-nil; logger defaults to slog.Default().
func NewService(
	txRunner txpkg.Runner,
	media domain.MediaRepository,
	objects domain.MediaObjectRepository,
	deletions domain.DeletionRepository,
	store storage.Storage,
	urls *URLBuilder,
	bucket string,
	logger *slog.Logger,
) *Service {
	if txRunner == nil {
		panic("medialib.NewService: txRunner must not be nil")
	}
	if urls == nil {
		panic("medialib.NewService: urls must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		txRunner:  txRunner,
		media:     media,
		objects:   objects,
		deletions: deletions,
		store:     store,
		urls:      urls,
		bucket:    bucket,
		logger:    logger,
	}
}

func (s *Service) runInTx(ctx context.Context, operation string, fn func(ctx context.Context, tx txpkg.Transaction) error) error {
	if err := s.txRunner.RunInTx(ctx, fn); err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return nil
}

// CreateMedia inserts a new media slot. When storageKey is empty it defaults to
// the generated media id, which keeps each media's object paths uniquely grouped.
func (s *Service) CreateMedia(ctx context.Context, storageKey, mediaType string) (*domain.Media, error) {
	id := uuid.New()
	if storageKey == "" {
		storageKey = id.String()
	}

	var result *domain.Media
	err := s.runInTx(ctx, "create media", func(ctx context.Context, tx txpkg.Transaction) error {
		var createErr error
		result, createErr = s.media.Create(ctx, tx, domain.Media{
			ID:         id,
			StorageKey: storageKey,
			Type:       mediaType,
		})
		return createErr
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// UpdateMedia persists mutable media fields.
func (s *Service) UpdateMedia(ctx context.Context, media domain.Media) error {
	return s.runInTx(ctx, "update media", func(ctx context.Context, tx txpkg.Transaction) error {
		return s.media.Update(ctx, tx, media)
	})
}

// SoftDeleteMedia sets deleted_at on the media row.
func (s *Service) SoftDeleteMedia(ctx context.Context, id uuid.UUID) error {
	return s.runInTx(ctx, "soft delete media", func(ctx context.Context, tx txpkg.Transaction) error {
		return s.media.SoftDelete(ctx, tx, id, time.Now())
	})
}

// HardDeleteMedia removes a media and cascade hard-deletes its objects: each is
// removed from storage and recorded in the deletion trail. Storage I/O happens
// outside the DB transaction; all DB writes commit atomically.
func (s *Service) HardDeleteMedia(ctx context.Context, id uuid.UUID) error {
	media, err := s.media.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("hard delete media: %w", err)
	}
	if media == nil {
		return ErrMediaNotFound
	}

	objects, err := s.objects.ListByMediaID(ctx, id)
	if err != nil {
		return fmt.Errorf("hard delete media: list objects: %w", err)
	}

	paths := make([]string, len(objects))
	for i := range objects {
		paths[i] = s.objectPath(media, &objects[i])
	}
	if len(paths) > 0 {
		if err := s.store.DeleteObjects(s.bucket, paths); err != nil {
			return fmt.Errorf("hard delete media: storage: %w", err)
		}
	}

	return s.runInTx(ctx, "hard delete media", func(ctx context.Context, tx txpkg.Transaction) error {
		for i := range objects {
			if _, err := s.deletions.Create(ctx, tx, domain.MediaObjectDeletion{
				MediaObjectID: objects[i].ID,
				StoragePath:   paths[i],
			}); err != nil {
				return fmt.Errorf("trail %s: %w", objects[i].ID, err)
			}
			if err := s.objects.HardDelete(ctx, tx, objects[i].ID); err != nil {
				return fmt.Errorf("delete object %s: %w", objects[i].ID, err)
			}
		}
		if err := s.media.HardDelete(ctx, tx, id); err != nil {
			return fmt.Errorf("delete media: %w", err)
		}
		return nil
	})
}

// CreateMediaObject creates a pending object on a media and returns a presigned
// upload URL for "{storage_key}/{object_id}/original.{ext}". The client PUTs the
// file directly to that URL, then calls ActivateMediaObject.
func (s *Service) CreateMediaObject(ctx context.Context, mediaID uuid.UUID, mimeType, extension string, sizeBytes *int64) (string, *domain.MediaObject, error) {
	media, err := s.media.GetByID(ctx, mediaID)
	if err != nil {
		return "", nil, fmt.Errorf("create media object: %w", err)
	}
	if media == nil {
		return "", nil, ErrMediaNotFound
	}

	obj := domain.MediaObject{
		ID:               uuid.New(),
		MediaID:          mediaID,
		Status:           domain.MediaObjectStatusPending,
		ProcessingStatus: domain.ProcessingStatusPending,
		SizeBytes:        sizeBytes,
		MimeType:         strPtr(mimeType),
		Extension:        strPtr(extension),
	}

	var created *domain.MediaObject
	err = s.runInTx(ctx, "create media object", func(ctx context.Context, tx txpkg.Transaction) error {
		var createErr error
		created, createErr = s.objects.Create(ctx, tx, obj)
		return createErr
	})
	if err != nil {
		return "", nil, err
	}

	// Generate the presigned URL outside the transaction to avoid holding DB
	// locks during external I/O. The object key is used verbatim by Storage.
	path := s.objectPath(media, created)
	info, err := s.store.GenerateUploadURL(s.bucket, path, strPtr(mimeType))
	if err != nil {
		return "", nil, fmt.Errorf("create media object: upload url: %w", err)
	}
	return info.URL, created, nil
}

// ActivateMediaObject verifies the upload landed in storage, overwrites
// size_bytes with the real size, and transitions the object to active —
// superseding any previously active object of the same media within a single
// media-row-locked transaction. Idempotent if the object is already active.
func (s *Service) ActivateMediaObject(ctx context.Context, objectID uuid.UUID, sizeBytes int64) error {
	obj, err := s.objects.GetByID(ctx, objectID)
	if err != nil {
		return fmt.Errorf("activate media object: %w", err)
	}
	if obj == nil {
		return ErrMediaObjectNotFound
	}
	if obj.Status == domain.MediaObjectStatusActive {
		return nil
	}

	media, err := s.media.GetByID(ctx, obj.MediaID)
	if err != nil {
		return fmt.Errorf("activate media object: %w", err)
	}
	if media == nil {
		return ErrMediaNotFound
	}

	path := s.objectPath(media, obj)
	if !s.store.FileExists(s.bucket, path) {
		return ErrObjectNotUploaded
	}

	// Prefer the real stored size; fall back to the client-reported value.
	actualSize := sizeBytes
	if info, err := s.store.GetObjectInfo(s.bucket, path); err == nil {
		actualSize = info.Size
	} else {
		s.logger.Warn("activate media object: get object info failed, using client size",
			"object_id", objectID, "err", err)
	}

	return s.runInTx(ctx, "activate media object", func(ctx context.Context, tx txpkg.Transaction) error {
		// Lock the media row to serialize concurrent activations.
		if _, err := s.media.GetByIDTx(ctx, tx, obj.MediaID); err != nil {
			return fmt.Errorf("lock media: %w", err)
		}

		// Supersede the prior active object before activating this one so the
		// partial unique index never sees two active rows.
		if _, err := s.objects.SupersedeActiveByMediaID(ctx, tx, obj.MediaID); err != nil {
			return fmt.Errorf("supersede active: %w", err)
		}

		obj.Status = domain.MediaObjectStatusActive
		obj.SizeBytes = &actualSize
		obj.DeletedAt = nil
		if err := s.objects.Update(ctx, tx, *obj); err != nil {
			return fmt.Errorf("activate: %w", err)
		}
		return nil
	})
}

// HardDeleteMediaObject removes a single object from storage, deletes its row,
// and records a deletion-trail entry.
func (s *Service) HardDeleteMediaObject(ctx context.Context, objectID uuid.UUID) error {
	obj, err := s.objects.GetByID(ctx, objectID)
	if err != nil {
		return fmt.Errorf("hard delete media object: %w", err)
	}
	if obj == nil {
		return ErrMediaObjectNotFound
	}

	media, err := s.media.GetByID(ctx, obj.MediaID)
	if err != nil {
		return fmt.Errorf("hard delete media object: %w", err)
	}
	if media == nil {
		return ErrMediaNotFound
	}

	path := s.objectPath(media, obj)
	if err := s.store.DeleteObject(s.bucket, path); err != nil {
		return fmt.Errorf("hard delete media object: storage: %w", err)
	}

	return s.runInTx(ctx, "hard delete media object", func(ctx context.Context, tx txpkg.Transaction) error {
		if _, err := s.deletions.Create(ctx, tx, domain.MediaObjectDeletion{
			MediaObjectID: obj.ID,
			StoragePath:   path,
		}); err != nil {
			return fmt.Errorf("trail: %w", err)
		}
		if err := s.objects.HardDelete(ctx, tx, obj.ID); err != nil {
			return fmt.Errorf("delete object: %w", err)
		}
		return nil
	})
}

// GetActiveURL returns the fully-built read URL for the active object of a media.
// Image-typed media get a render-capable URL (the app appends ?width=<n>); other
// types get the plain object URL.
func (s *Service) GetActiveURL(ctx context.Context, mediaID uuid.UUID) (string, error) {
	media, err := s.media.GetByID(ctx, mediaID)
	if err != nil {
		return "", fmt.Errorf("get active url: %w", err)
	}
	if media == nil {
		return "", ErrMediaNotFound
	}

	obj, err := s.objects.GetActiveByMediaID(ctx, mediaID)
	if err != nil {
		return "", fmt.Errorf("get active url: %w", err)
	}
	if obj == nil {
		return "", ErrNoActiveObject
	}

	return s.urls.BuildURL(media.Type, s.objectPath(media, obj)), nil
}

// ResolvedMedia is the read-side view of a media: its asset type and active
// read URL. HasActive is false when no object is active yet (URL is then empty).
type ResolvedMedia struct {
	Type      string
	URL       string
	HasActive bool
}

// ResolveActiveURLs resolves the asset type and active read URL for many media
// in a single query (media LEFT JOIN active object), with no per-id round-trips.
// Missing media ids are absent from the result; media without an active object
// are present with their Type set, HasActive=false and an empty URL.
func (s *Service) ResolveActiveURLs(ctx context.Context, mediaIDs []uuid.UUID) (map[uuid.UUID]ResolvedMedia, error) {
	out := make(map[uuid.UUID]ResolvedMedia, len(mediaIDs))
	if len(mediaIDs) == 0 {
		return out, nil
	}

	rows, err := s.media.ListWithActiveObjectByIDs(ctx, dedupeUUIDs(mediaIDs))
	if err != nil {
		return nil, fmt.Errorf("resolve active urls: %w", err)
	}

	for _, row := range rows {
		resolved := ResolvedMedia{Type: row.Media.Type}
		if row.Object != nil {
			resolved.URL = s.urls.BuildURL(row.Media.Type, s.objectPath(&row.Media, row.Object))
			resolved.HasActive = true
		}
		out[row.Media.ID] = resolved
	}
	return out, nil
}

// dedupeUUIDs returns ids with duplicates removed, preserving first-seen order.
func dedupeUUIDs(ids []uuid.UUID) []uuid.UUID {
	seen := make(map[uuid.UUID]struct{}, len(ids))
	out := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// GetDeletionsSince returns deletion-trail entries newer than the given
// timestamp, so clients can purge stale cache entries for removed objects.
func (s *Service) GetDeletionsSince(ctx context.Context, since time.Time) ([]domain.MediaObjectDeletion, error) {
	return s.deletions.ListSince(ctx, since)
}

// GetMedia returns a media by id (nil when not found).
func (s *Service) GetMedia(ctx context.Context, id uuid.UUID) (*domain.Media, error) {
	return s.media.GetByID(ctx, id)
}

func (s *Service) objectPath(media *domain.Media, obj *domain.MediaObject) string {
	ext := ""
	if obj.Extension != nil {
		ext = *obj.Extension
	}
	return ObjectPath(media.StorageKey, obj.ID, ext)
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
