package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/blueyellowstudio/goose-base/medialib"
	domain "github.com/blueyellowstudio/goose-base/medialib/domain"
	txpkg "github.com/blueyellowstudio/goose-base/tx"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DeletionRepository struct {
	pool   *pgxpool.Pool
	tables medialib.Tables
}

func NewDeletionRepository(pool *pgxpool.Pool, tables medialib.Tables) *DeletionRepository {
	return &DeletionRepository{pool: pool, tables: tables}
}

const deletionColumns = `id, media_object_id, storage_path, deleted_at`

// Create writes a deletion-trail entry and returns it with server-generated
// id and deleted_at.
func (r *DeletionRepository) Create(ctx context.Context, tx txpkg.Transaction, d domain.MediaObjectDeletion) (*domain.MediaObjectDeletion, error) {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return nil, fmt.Errorf("create deletion: %w", err)
	}

	query := fmt.Sprintf(`
		INSERT INTO %s (media_object_id, storage_path)
		VALUES ($1, $2)
		RETURNING %s`,
		r.tables.MediaObjectsDeletions, deletionColumns,
	)

	row := pgxTx.QueryRow(ctx, query, d.MediaObjectID, d.StoragePath)
	result, err := scanDeletion(row)
	if err != nil {
		return nil, fmt.Errorf("create deletion: %w", err)
	}
	return result, nil
}

// ListSince returns all deletion-trail entries deleted strictly after the given
// timestamp, oldest first.
func (r *DeletionRepository) ListSince(ctx context.Context, since time.Time) ([]domain.MediaObjectDeletion, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM %s
		WHERE deleted_at > $1
		ORDER BY deleted_at ASC`,
		deletionColumns, r.tables.MediaObjectsDeletions,
	)

	rows, err := r.pool.Query(ctx, query, since)
	if err != nil {
		return nil, fmt.Errorf("list deletions since: %w", err)
	}
	defer rows.Close()
	return scanDeletions(rows)
}

func scanDeletion(row pgx.Row) (*domain.MediaObjectDeletion, error) {
	var d domain.MediaObjectDeletion
	err := row.Scan(&d.ID, &d.MediaObjectID, &d.StoragePath, &d.DeletedAt)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func scanDeletions(rows pgx.Rows) ([]domain.MediaObjectDeletion, error) {
	var deletions []domain.MediaObjectDeletion
	for rows.Next() {
		d, err := scanDeletion(rows)
		if err != nil {
			return nil, fmt.Errorf("scan deletion: %w", err)
		}
		deletions = append(deletions, *d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate deletions: %w", err)
	}
	if deletions == nil {
		deletions = []domain.MediaObjectDeletion{}
	}
	return deletions, nil
}

var _ domain.DeletionRepository = (*DeletionRepository)(nil)
