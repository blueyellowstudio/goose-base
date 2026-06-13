package db

import (
	"context"
	"fmt"
	"time"

	domain "github.com/blueyellowstudio/goose-base/fileManager/domain"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DeletedItemRepository struct {
	pool   *pgxpool.Pool
	tables FileManagerTables
}

func NewDeletedItemRepository(pool *pgxpool.Pool, tables FileManagerTables) *DeletedItemRepository {
	return &DeletedItemRepository{pool: pool, tables: tables}
}

// ListSince returns all deletion tombstones recorded after the given time, ordered by deleted_at ascending.
func (r *DeletedItemRepository) ListSince(ctx context.Context, since time.Time) ([]domain.DeletedItem, error) {
	query := fmt.Sprintf(`
		SELECT id, entity_type, entity_id, file_id, deleted_at
		FROM %s
		WHERE deleted_at > $1
		ORDER BY deleted_at ASC`,
		r.tables.DeletedItems,
	)

	rows, err := r.pool.Query(ctx, query, since)
	if err != nil {
		return nil, fmt.Errorf("list deleted items since: %w", err)
	}
	defer rows.Close()

	return scanDeletedItems(rows)
}

func scanDeletedItems(rows pgx.Rows) ([]domain.DeletedItem, error) {
	var items []domain.DeletedItem
	for rows.Next() {
		var item domain.DeletedItem
		if err := rows.Scan(&item.ID, &item.EntityType, &item.EntityID, &item.FileID, &item.DeletedAt); err != nil {
			return nil, fmt.Errorf("scan deleted item: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate deleted items: %w", err)
	}
	if items == nil {
		items = []domain.DeletedItem{}
	}
	return items, nil
}
