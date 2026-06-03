package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/blueyellowstudio/goose-base/medialib"
	domain "github.com/blueyellowstudio/goose-base/medialib/domain"
	txpkg "github.com/blueyellowstudio/goose-base/tx"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type MediaObjectRepository struct {
	pool   *pgxpool.Pool
	tables medialib.Tables
}

func NewMediaObjectRepository(pool *pgxpool.Pool, tables medialib.Tables) *MediaObjectRepository {
	return &MediaObjectRepository{pool: pool, tables: tables}
}

const mediaObjectColumns = `id, media_id, status, processing_status, size_bytes, mime_type, extension, created_at, updated_at, deleted_at`

// Create inserts a new media object and returns it with server-generated defaults.
func (r *MediaObjectRepository) Create(ctx context.Context, tx txpkg.Transaction, o domain.MediaObject) (*domain.MediaObject, error) {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return nil, fmt.Errorf("create media object: %w", err)
	}

	query := fmt.Sprintf(`
		INSERT INTO %s (id, media_id, status, processing_status, size_bytes, mime_type, extension)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING %s`,
		r.tables.MediaObjects, mediaObjectColumns,
	)

	row := pgxTx.QueryRow(ctx, query,
		o.ID, o.MediaID, o.Status, o.ProcessingStatus, o.SizeBytes, o.MimeType, o.Extension,
	)
	result, err := scanMediaObject(row)
	if err != nil {
		return nil, fmt.Errorf("create media object: %w", err)
	}
	return result, nil
}

// Update persists mutable media object fields (status, processing, size, deleted_at).
func (r *MediaObjectRepository) Update(ctx context.Context, tx txpkg.Transaction, o domain.MediaObject) error {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return fmt.Errorf("update media object: %w", err)
	}

	query := fmt.Sprintf(`
		UPDATE %s
		SET status = $1, processing_status = $2, size_bytes = $3, deleted_at = $4, updated_at = now()
		WHERE id = $5`,
		r.tables.MediaObjects,
	)

	if _, err := pgxTx.Exec(ctx, query, o.Status, o.ProcessingStatus, o.SizeBytes, o.DeletedAt, o.ID); err != nil {
		return fmt.Errorf("update media object: %w", err)
	}
	return nil
}

// GetByID retrieves a media object by its primary key.
func (r *MediaObjectRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.MediaObject, error) {
	query := fmt.Sprintf(`SELECT %s FROM %s WHERE id = $1`, mediaObjectColumns, r.tables.MediaObjects)

	row := r.pool.QueryRow(ctx, query, id)
	result, err := scanMediaObject(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get media object by id: %w", err)
	}
	return result, nil
}

// GetActiveByMediaID returns the active, non-deleted object for a media, if any.
func (r *MediaObjectRepository) GetActiveByMediaID(ctx context.Context, mediaID uuid.UUID) (*domain.MediaObject, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM %s
		WHERE media_id = $1 AND status = 'active' AND deleted_at IS NULL`,
		mediaObjectColumns, r.tables.MediaObjects,
	)

	row := r.pool.QueryRow(ctx, query, mediaID)
	result, err := scanMediaObject(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get active media object: %w", err)
	}
	return result, nil
}

// ListByMediaID returns all objects for a media, including soft-deleted rows.
func (r *MediaObjectRepository) ListByMediaID(ctx context.Context, mediaID uuid.UUID) ([]domain.MediaObject, error) {
	query := fmt.Sprintf(`SELECT %s FROM %s WHERE media_id = $1`, mediaObjectColumns, r.tables.MediaObjects)

	rows, err := r.pool.Query(ctx, query, mediaID)
	if err != nil {
		return nil, fmt.Errorf("list media objects: %w", err)
	}
	defer rows.Close()
	return scanMediaObjects(rows)
}

// SupersedeActiveByMediaID marks the active, non-deleted object of a media as
// deleted. Returns whether a row was affected.
func (r *MediaObjectRepository) SupersedeActiveByMediaID(ctx context.Context, tx txpkg.Transaction, mediaID uuid.UUID) (bool, error) {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return false, fmt.Errorf("supersede active media object: %w", err)
	}

	query := fmt.Sprintf(`
		UPDATE %s
		SET status = 'deleted', deleted_at = now(), updated_at = now()
		WHERE media_id = $1 AND status = 'active' AND deleted_at IS NULL`,
		r.tables.MediaObjects,
	)

	result, err := pgxTx.Exec(ctx, query, mediaID)
	if err != nil {
		return false, fmt.Errorf("supersede active media object: %w", err)
	}
	return result.RowsAffected() > 0, nil
}

// HardDelete removes a media object row entirely.
func (r *MediaObjectRepository) HardDelete(ctx context.Context, tx txpkg.Transaction, id uuid.UUID) error {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return fmt.Errorf("hard delete media object: %w", err)
	}

	query := fmt.Sprintf(`DELETE FROM %s WHERE id = $1`, r.tables.MediaObjects)
	if _, err := pgxTx.Exec(ctx, query, id); err != nil {
		return fmt.Errorf("hard delete media object: %w", err)
	}
	return nil
}

func scanMediaObject(row pgx.Row) (*domain.MediaObject, error) {
	var o domain.MediaObject
	err := row.Scan(
		&o.ID,
		&o.MediaID,
		&o.Status,
		&o.ProcessingStatus,
		&o.SizeBytes,
		&o.MimeType,
		&o.Extension,
		&o.CreatedAt,
		&o.UpdatedAt,
		&o.DeletedAt,
	)
	if err != nil {
		return nil, err
	}
	return &o, nil
}

func scanMediaObjects(rows pgx.Rows) ([]domain.MediaObject, error) {
	var objects []domain.MediaObject
	for rows.Next() {
		o, err := scanMediaObject(rows)
		if err != nil {
			return nil, fmt.Errorf("scan media object: %w", err)
		}
		objects = append(objects, *o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate media objects: %w", err)
	}
	if objects == nil {
		objects = []domain.MediaObject{}
	}
	return objects, nil
}

var _ domain.MediaObjectRepository = (*MediaObjectRepository)(nil)
