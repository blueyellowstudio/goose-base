package db

import (
	"context"
	"fmt"
	"strings"
	"time"

	domain "github.com/blueyellowstudio/goose-base/fileManager/domain"
	txpkg "github.com/blueyellowstudio/goose-base/tx"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type FolderRepository struct {
	pool   *pgxpool.Pool
	tables FileManagerTables
}

func NewFolderRepository(pool *pgxpool.Pool, tables FileManagerTables) *FolderRepository {
	return &FolderRepository{pool: pool, tables: tables}
}

func scanFolder(row pgx.Row) (*domain.Folder, error) {
	var f domain.Folder
	err := row.Scan(
		&f.ID,
		&f.Path,
		&f.ParentID,
		&f.Name,
		&f.NameRef,
		&f.CreatedAt,
		&f.CreatedBy,
		&f.DeletedAt,
		&f.Metadata,
	)
	if err != nil {
		return nil, err
	}
	return &f, nil
}

func (r *FolderRepository) Create(ctx context.Context, tx txpkg.Transaction, folder domain.Folder) (*domain.Folder, error) {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return nil, fmt.Errorf("create folder: %w", err)
	}

	var query string
	var args []any

	if folder.ParentID == nil {
		// Root folder: path is just the new UUID (converted to ltree-safe label)
		query = fmt.Sprintf(`
			INSERT INTO %s (path, parent_id, name, name_ref, created_by, metadata)
			VALUES (text2ltree(replace(gen_random_uuid()::text, '-', '_')), NULL, $1, $2, $3, $4)
			RETURNING id, path::text, parent_id, name, name_ref, created_at, created_by, deleted_at, metadata`,
			r.tables.Folders,
		)
		args = []any{folder.Name, folder.NameRef, folder.CreatedBy, folder.Metadata}
	} else {
		// Child folder: path = parent_path.new_uuid
		query = fmt.Sprintf(`
			INSERT INTO %s (path, parent_id, name, name_ref, created_by, metadata)
			SELECT
				p.path || text2ltree(replace(gen_random_uuid()::text, '-', '_')),
				$1,
				$2,
				$3,
				$4,
				$5
			FROM %s p WHERE p.id = $1 AND p.deleted_at IS NULL
			RETURNING id, path::text, parent_id, name, name_ref, created_at, created_by, deleted_at, metadata`,
			r.tables.Folders,
			r.tables.Folders,
		)
		args = []any{folder.ParentID, folder.Name, folder.NameRef, folder.CreatedBy, folder.Metadata}
	}

	row := pgxTx.QueryRow(ctx, query, args...)
	result, err := scanFolder(row)
	if err != nil {
		return nil, fmt.Errorf("create folder: %w", err)
	}
	return result, nil
}

func (r *FolderRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Folder, error) {
	query := fmt.Sprintf(`
		SELECT id, path::text, parent_id, name, name_ref, created_at, created_by, deleted_at, metadata
		FROM %s WHERE id = $1`,
		r.tables.Folders,
	)

	row := r.pool.QueryRow(ctx, query, id)
	result, err := scanFolder(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get folder by id: %w", err)
	}
	return result, nil
}

func (r *FolderRepository) GetByIDTx(ctx context.Context, tx txpkg.Transaction, id uuid.UUID) (*domain.Folder, error) {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return nil, fmt.Errorf("get folder by id (tx): %w", err)
	}

	query := fmt.Sprintf(`
		SELECT id, path::text, parent_id, name, name_ref, created_at, created_by, deleted_at, metadata
		FROM %s WHERE id = $1 FOR UPDATE`,
		r.tables.Folders,
	)

	row := pgxTx.QueryRow(ctx, query, id)
	result, err := scanFolder(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get folder by id (tx): %w", err)
	}
	return result, nil
}

func (r *FolderRepository) Update(ctx context.Context, tx txpkg.Transaction, folder domain.Folder) error {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return fmt.Errorf("update folder: %w", err)
	}

	query := fmt.Sprintf(`UPDATE %s SET name = $1, name_ref = $2, metadata = $3 WHERE id = $4`, r.tables.Folders)
	_, err = pgxTx.Exec(ctx, query, folder.Name, folder.NameRef, folder.Metadata, folder.ID)
	if err != nil {
		return fmt.Errorf("update folder: %w", err)
	}
	return nil
}

func (r *FolderRepository) SoftDelete(ctx context.Context, tx txpkg.Transaction, id uuid.UUID, deletedAt time.Time) error {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return fmt.Errorf("soft delete folder: %w", err)
	}

	query := fmt.Sprintf(`UPDATE %s SET deleted_at = $1 WHERE id = $2`, r.tables.Folders)
	_, err = pgxTx.Exec(ctx, query, deletedAt, id)
	if err != nil {
		return fmt.Errorf("soft delete folder: %w", err)
	}
	return nil
}

// Move updates the ltree path for a folder and all its descendants.
// Cycle detection must be done by the caller before invoking this method.
func (r *FolderRepository) Move(ctx context.Context, tx txpkg.Transaction, folderID uuid.UUID, newParentID *uuid.UUID) error {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return fmt.Errorf("move folder: %w", err)
	}

	// Lock the folder being moved
	var currentPath string
	sourcePathQuery := fmt.Sprintf(`SELECT path::text FROM %s WHERE id = $1 FOR UPDATE`, r.tables.Folders)
	err = pgxTx.QueryRow(ctx, sourcePathQuery, folderID).Scan(&currentPath)
	if err != nil {
		return fmt.Errorf("move folder: lock source: %w", err)
	}

	var newBasePath string
	if newParentID == nil {
		// Moving to root: new path is just the folder's own label (last segment)
		parts := strings.Split(currentPath, ".")
		newBasePath = parts[len(parts)-1]
	} else {
		var parentPath string
		parentPathQuery := fmt.Sprintf(`SELECT path::text FROM %s WHERE id = $1`, r.tables.Folders)
		err = pgxTx.QueryRow(ctx, parentPathQuery, newParentID).Scan(&parentPath)
		if err != nil {
			return fmt.Errorf("move folder: get parent path: %w", err)
		}
		parts := strings.Split(currentPath, ".")
		newBasePath = parentPath + "." + parts[len(parts)-1]
	}

	// Update all descendants (path prefix replacement)
	query := fmt.Sprintf(`
		UPDATE %s
		SET path = CASE
				WHEN path = text2ltree($2) THEN text2ltree($1)
				ELSE text2ltree($1) || subpath(path, nlevel(text2ltree($2)))
			END,
		    parent_id = CASE WHEN id = $3 THEN $4 ELSE parent_id END
		WHERE path <@ text2ltree($2)`,
		r.tables.Folders,
	)

	_, err = pgxTx.Exec(ctx, query, newBasePath, currentPath, folderID, newParentID)
	if err != nil {
		return fmt.Errorf("move folder: update paths: %w", err)
	}
	return nil
}

func (r *FolderRepository) ListChildren(ctx context.Context, parentID *uuid.UUID, filter domain.AccessFilter) ([]domain.Folder, error) {
	var args []any
	var whereClause string

	if parentID == nil {
		whereClause = "f.parent_id IS NULL"
	} else {
		whereClause = "f.parent_id = $1"
		args = append(args, *parentID)
	}

	argOffset := len(args) + 1
	clause, filterArgs := filter.SQLWhereClause("f", argOffset)

	query := fmt.Sprintf(`
		SELECT f.id, f.path::text, f.parent_id, f.name, f.name_ref, f.created_at, f.created_by, f.deleted_at, f.metadata
		FROM %s f
		WHERE %s AND f.deleted_at IS NULL`,
		r.tables.Folders,
		whereClause,
	)

	if clause != "" {
		query += " AND " + clause
		args = append(args, filterArgs...)
	}

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list folder children: %w", err)
	}
	defer rows.Close()

	return scanFolders(rows)
}

func (r *FolderRepository) ListChildrenPaged(ctx context.Context, parentID *uuid.UUID, filter domain.AccessFilter, cursor *domain.Cursor, limit int, nameSearch *string) ([]domain.Folder, error) {
	var args []any
	var baseWhere string

	if parentID == nil {
		baseWhere = "f.parent_id IS NULL"
	} else {
		baseWhere = "f.parent_id = $1"
		args = append(args, *parentID)
	}

	argOffset := len(args) + 1
	filterClause, filterArgs := filter.SQLWhereClause("f", argOffset)
	args = append(args, filterArgs...)
	argOffset += len(filterArgs)

	query := fmt.Sprintf(`
		SELECT f.id, f.path::text, f.parent_id, f.name, f.name_ref, f.created_at, f.created_by, f.deleted_at, f.metadata
		FROM %s f
		WHERE %s AND f.deleted_at IS NULL`,
		r.tables.Folders,
		baseWhere,
	)

	if filterClause != "" {
		query += " AND " + filterClause
	}

	if cursor != nil {
		query += fmt.Sprintf(
			" AND (f.name > $%d OR (f.name = $%d AND f.id > $%d))",
			argOffset, argOffset, argOffset+1,
		)
		args = append(args, cursor.Name, cursor.ID)
		argOffset += 2
	}

	if nameSearch != nil {
		query += fmt.Sprintf(" AND f.name ILIKE '%%' || $%d || '%%'", argOffset)
		args = append(args, *nameSearch)
		argOffset++
	}

	query += fmt.Sprintf(" ORDER BY f.name ASC, f.id ASC LIMIT $%d", argOffset)
	args = append(args, limit)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list folder children paged: %w", err)
	}
	defer rows.Close()

	return scanFolders(rows)
}

// GetSubtree returns all folders whose path is a descendant of the given folder's path,
// including the folder itself. Results are ordered so parents come before children.
func (r *FolderRepository) GetSubtree(ctx context.Context, folderID uuid.UUID) ([]domain.Folder, error) {
	query := fmt.Sprintf(`
		SELECT f.id, f.path::text, f.parent_id, f.name, f.name_ref, f.created_at, f.created_by, f.deleted_at, f.metadata
		FROM %s f
		WHERE f.path <@ (SELECT path FROM %s WHERE id = $1)
		ORDER BY nlevel(f.path) ASC`,
		r.tables.Folders,
		r.tables.Folders,
	)

	rows, err := r.pool.Query(ctx, query, folderID)
	if err != nil {
		return nil, fmt.Errorf("get folder subtree: %w", err)
	}
	defer rows.Close()

	return scanFolders(rows)
}

func (r *FolderRepository) GetSubtreeTx(ctx context.Context, tx txpkg.Transaction, folderID uuid.UUID) ([]domain.Folder, error) {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return nil, fmt.Errorf("get folder subtree (tx): %w", err)
	}

	query := fmt.Sprintf(`
		SELECT f.id, f.path::text, f.parent_id, f.name, f.name_ref, f.created_at, f.created_by, f.deleted_at, f.metadata
		FROM %s f
		WHERE f.path <@ (SELECT path FROM %s WHERE id = $1)
		ORDER BY nlevel(f.path) ASC`,
		r.tables.Folders,
		r.tables.Folders,
	)

	rows, err := pgxTx.Query(ctx, query, folderID)
	if err != nil {
		return nil, fmt.Errorf("get folder subtree (tx): %w", err)
	}
	defer rows.Close()

	return scanFolders(rows)
}

// GetAncestors returns all folders that are ancestors of (or equal to) the given folder,
// ordered from root to the folder itself.
func (r *FolderRepository) GetAncestors(ctx context.Context, folderID uuid.UUID) ([]domain.Folder, error) {
	query := fmt.Sprintf(`
		SELECT f.id, f.path::text, f.parent_id, f.name, f.name_ref, f.created_at, f.created_by, f.deleted_at, f.metadata
		FROM %s f
		WHERE f.path @> (SELECT path FROM %s WHERE id = $1)
		ORDER BY nlevel(f.path) ASC`,
		r.tables.Folders,
		r.tables.Folders,
	)

	rows, err := r.pool.Query(ctx, query, folderID)
	if err != nil {
		return nil, fmt.Errorf("get folder ancestors: %w", err)
	}
	defer rows.Close()

	return scanFolders(rows)
}

func scanFolders(rows pgx.Rows) ([]domain.Folder, error) {
	var folders []domain.Folder
	for rows.Next() {
		var f domain.Folder
		if err := rows.Scan(
			&f.ID, &f.Path, &f.ParentID, &f.Name, &f.NameRef,
			&f.CreatedAt, &f.CreatedBy, &f.DeletedAt, &f.Metadata,
		); err != nil {
			return nil, fmt.Errorf("scan folder: %w", err)
		}
		folders = append(folders, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate folders: %w", err)
	}
	if folders == nil {
		folders = []domain.Folder{}
	}
	return folders, nil
}
