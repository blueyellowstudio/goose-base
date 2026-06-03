package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blueyellowstudio/goose-base/medialib"
	domain "github.com/blueyellowstudio/goose-base/medialib/domain"
	txpkg "github.com/blueyellowstudio/goose-base/tx"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type MediaRepository struct {
	pool   *pgxpool.Pool
	tables medialib.Tables
}

func NewMediaRepository(pool *pgxpool.Pool, tables medialib.Tables) *MediaRepository {
	return &MediaRepository{pool: pool, tables: tables}
}

const mediaColumns = `id, storage_key, type, created_at, updated_at, deleted_at`

// Create inserts a new media row and returns it with server-generated defaults.
func (r *MediaRepository) Create(ctx context.Context, tx txpkg.Transaction, m domain.Media) (*domain.Media, error) {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return nil, fmt.Errorf("create media: %w", err)
	}

	query := fmt.Sprintf(`
		INSERT INTO %s (id, storage_key, type)
		VALUES ($1, $2, $3)
		RETURNING %s`,
		r.tables.Media, mediaColumns,
	)

	row := pgxTx.QueryRow(ctx, query, m.ID, m.StorageKey, m.Type)
	result, err := scanMedia(row)
	if err != nil {
		return nil, fmt.Errorf("create media: %w", err)
	}
	return result, nil
}

// Update persists mutable media fields.
func (r *MediaRepository) Update(ctx context.Context, tx txpkg.Transaction, m domain.Media) error {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return fmt.Errorf("update media: %w", err)
	}

	query := fmt.Sprintf(`
		UPDATE %s
		SET storage_key = $1, type = $2, updated_at = now()
		WHERE id = $3`,
		r.tables.Media,
	)

	if _, err := pgxTx.Exec(ctx, query, m.StorageKey, m.Type, m.ID); err != nil {
		return fmt.Errorf("update media: %w", err)
	}
	return nil
}

// GetByID retrieves a media row by its primary key.
func (r *MediaRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Media, error) {
	query := fmt.Sprintf(`SELECT %s FROM %s WHERE id = $1`, mediaColumns, r.tables.Media)

	row := r.pool.QueryRow(ctx, query, id)
	result, err := scanMedia(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get media by id: %w", err)
	}
	return result, nil
}

// GetByIDTx retrieves a media row within a transaction, locking it with
// FOR UPDATE to serialize concurrent object activations.
func (r *MediaRepository) GetByIDTx(ctx context.Context, tx txpkg.Transaction, id uuid.UUID) (*domain.Media, error) {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return nil, fmt.Errorf("get media by id (tx): %w", err)
	}

	query := fmt.Sprintf(`SELECT %s FROM %s WHERE id = $1 FOR UPDATE`, mediaColumns, r.tables.Media)

	row := pgxTx.QueryRow(ctx, query, id)
	result, err := scanMedia(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get media by id (tx): %w", err)
	}
	return result, nil
}

// ListWithActiveObjectByIDs loads many media by id, each LEFT JOINed to its
// single active object (nil when none), in one query. Exactly one row per
// requested, existing media id (at most one active object per media).
func (r *MediaRepository) ListWithActiveObjectByIDs(ctx context.Context, ids []uuid.UUID) ([]domain.MediaWithActiveObject, error) {
	if len(ids) == 0 {
		return []domain.MediaWithActiveObject{}, nil
	}

	query := fmt.Sprintf(`
		SELECT %s, %s
		FROM %s m
		LEFT JOIN %s o
			ON o.media_id = m.id AND o.status = 'active' AND o.deleted_at IS NULL
		WHERE m.id = ANY($1)`,
		prefixColumns("m", mediaColumns), prefixColumns("o", mediaObjectColumns),
		r.tables.Media, r.tables.MediaObjects,
	)

	rows, err := r.pool.Query(ctx, query, ids)
	if err != nil {
		return nil, fmt.Errorf("list media with active object: %w", err)
	}
	defer rows.Close()

	var out []domain.MediaWithActiveObject
	for rows.Next() {
		entry, err := scanMediaWithActiveObject(rows)
		if err != nil {
			return nil, fmt.Errorf("scan media with active object: %w", err)
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate media with active object: %w", err)
	}
	if out == nil {
		out = []domain.MediaWithActiveObject{}
	}
	return out, nil
}

// scanMediaWithActiveObject scans a media row joined to its (nullable) active
// object. The object side is all-NULL when no active object exists, in which
// case Object stays nil.
func scanMediaWithActiveObject(row pgx.Row) (domain.MediaWithActiveObject, error) {
	var (
		m          domain.Media
		oID        *uuid.UUID
		oMediaID   *uuid.UUID
		oStatus    *string
		oProcess   *string
		oSizeBytes *int64
		oMimeType  *string
		oExtension *string
		oCreatedAt *time.Time
		oUpdatedAt *time.Time
		oDeletedAt *time.Time
	)
	err := row.Scan(
		&m.ID, &m.StorageKey, &m.Type, &m.CreatedAt, &m.UpdatedAt, &m.DeletedAt,
		&oID, &oMediaID, &oStatus, &oProcess, &oSizeBytes, &oMimeType, &oExtension,
		&oCreatedAt, &oUpdatedAt, &oDeletedAt,
	)
	if err != nil {
		return domain.MediaWithActiveObject{}, err
	}

	entry := domain.MediaWithActiveObject{Media: m}
	if oID != nil {
		obj := domain.MediaObject{
			ID:        *oID,
			MediaID:   *oMediaID,
			SizeBytes: oSizeBytes,
			MimeType:  oMimeType,
			Extension: oExtension,
			DeletedAt: oDeletedAt,
		}
		if oStatus != nil {
			obj.Status = domain.MediaObjectStatus(*oStatus)
		}
		if oProcess != nil {
			obj.ProcessingStatus = domain.ProcessingStatus(*oProcess)
		}
		if oCreatedAt != nil {
			obj.CreatedAt = *oCreatedAt
		}
		if oUpdatedAt != nil {
			obj.UpdatedAt = *oUpdatedAt
		}
		entry.Object = &obj
	}
	return entry, nil
}

// prefixColumns qualifies a comma-separated column list with a table alias,
// e.g. prefixColumns("m", "id, type") => "m.id, m.type".
func prefixColumns(alias, columns string) string {
	parts := strings.Split(columns, ", ")
	for i, p := range parts {
		parts[i] = alias + "." + p
	}
	return strings.Join(parts, ", ")
}

// SoftDelete sets deleted_at on the media row.
func (r *MediaRepository) SoftDelete(ctx context.Context, tx txpkg.Transaction, id uuid.UUID, deletedAt time.Time) error {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return fmt.Errorf("soft delete media: %w", err)
	}

	query := fmt.Sprintf(`UPDATE %s SET deleted_at = $1, updated_at = now() WHERE id = $2`, r.tables.Media)
	if _, err := pgxTx.Exec(ctx, query, deletedAt, id); err != nil {
		return fmt.Errorf("soft delete media: %w", err)
	}
	return nil
}

// HardDelete removes the media row entirely.
func (r *MediaRepository) HardDelete(ctx context.Context, tx txpkg.Transaction, id uuid.UUID) error {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return fmt.Errorf("hard delete media: %w", err)
	}

	query := fmt.Sprintf(`DELETE FROM %s WHERE id = $1`, r.tables.Media)
	if _, err := pgxTx.Exec(ctx, query, id); err != nil {
		return fmt.Errorf("hard delete media: %w", err)
	}
	return nil
}

func scanMedia(row pgx.Row) (*domain.Media, error) {
	var m domain.Media
	err := row.Scan(
		&m.ID,
		&m.StorageKey,
		&m.Type,
		&m.CreatedAt,
		&m.UpdatedAt,
		&m.DeletedAt,
	)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

var _ domain.MediaRepository = (*MediaRepository)(nil)
