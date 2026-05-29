package db

import (
	"context"
	"fmt"
	"time"

	domain "github.com/blueyellowstudio/goose-base/fileManager/domain"
	txpkg "github.com/blueyellowstudio/goose-base/tx"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type StoredFileRepository struct {
	pool   *pgxpool.Pool
	tables FileManagerTables
}

func NewStoredFileRepository(pool *pgxpool.Pool, tables FileManagerTables) *StoredFileRepository {
	return &StoredFileRepository{pool: pool, tables: tables}
}

// Create inserts a new StoredFile and returns the row with server-generated defaults.
func (r *StoredFileRepository) Create(ctx context.Context, tx txpkg.Transaction, sf domain.StoredFile) (*domain.StoredFile, error) {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return nil, fmt.Errorf("create stored file: %w", err)
	}

	query := fmt.Sprintf(`
		INSERT INTO %s (file_obj_id, file_size, status)
		VALUES ($1, $2, $3)
		RETURNING id, file_obj_id, file_size, status, created_at, deleted_at`,
		r.tables.StoredFiles,
	)

	row := pgxTx.QueryRow(ctx, query, sf.FileObjID, sf.FileSize, sf.Status)
	result, err := scanStoredFile(row)
	if err != nil {
		return nil, fmt.Errorf("create stored file: %w", err)
	}
	return result, nil
}

// Update persists file_size and status changes for an existing StoredFile.
func (r *StoredFileRepository) Update(ctx context.Context, tx txpkg.Transaction, sf domain.StoredFile) error {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return fmt.Errorf("update stored file: %w", err)
	}

	query := fmt.Sprintf(`
		UPDATE %s
		SET file_size = $1, status = $2
		WHERE id = $3`,
		r.tables.StoredFiles,
	)

	_, err = pgxTx.Exec(ctx, query, sf.FileSize, sf.Status, sf.ID)
	if err != nil {
		return fmt.Errorf("update stored file: %w", err)
	}
	return nil
}

// Delete soft-deletes a StoredFile by setting deleted_at to now.
func (r *StoredFileRepository) Delete(ctx context.Context, tx txpkg.Transaction, id uuid.UUID) error {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return fmt.Errorf("soft delete stored file: %w", err)
	}

	query := fmt.Sprintf(`UPDATE %s SET deleted_at = now() WHERE id = $1`, r.tables.StoredFiles)
	_, err = pgxTx.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("soft delete stored file: %w", err)
	}
	return nil
}

// DeleteByFileObject soft-deletes all non-deleted StoredFiles for a FileObject.
func (r *StoredFileRepository) DeleteByFileObject(ctx context.Context, tx txpkg.Transaction, fileObjID uuid.UUID) (bool, error) {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return false, fmt.Errorf("soft delete stored files by file object: %w", err)
	}

	query := fmt.Sprintf(`UPDATE %s SET deleted_at = now() WHERE file_obj_id = $1 AND deleted_at IS NULL`, r.tables.StoredFiles)
	result, err := pgxTx.Exec(ctx, query, fileObjID)
	if err != nil {
		return false, fmt.Errorf("soft delete stored files by file object: %w", err)
	}

	return result.RowsAffected() > 0, nil
}

// SupersedeActiveByFileObject marks all active non-deleted StoredFiles for a FileObject as superseded and deleted.
func (r *StoredFileRepository) SupersedeActiveByFileObject(ctx context.Context, tx txpkg.Transaction, fileObjID uuid.UUID) (bool, error) {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return false, fmt.Errorf("supersede active stored files by file object: %w", err)
	}

	query := fmt.Sprintf(`
		UPDATE %s
		SET status = 'superseded', deleted_at = now()
		WHERE file_obj_id = $1 AND status = 'active' AND deleted_at IS NULL`,
		r.tables.StoredFiles,
	)
	result, err := pgxTx.Exec(ctx, query, fileObjID)
	if err != nil {
		return false, fmt.Errorf("supersede active stored files by file object: %w", err)
	}

	return result.RowsAffected() > 0, nil
}

// Remove hard-deletes a StoredFile row entirely.
func (r *StoredFileRepository) Remove(ctx context.Context, tx txpkg.Transaction, id uuid.UUID) error {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return fmt.Errorf("remove stored file: %w", err)
	}

	query := fmt.Sprintf(`DELETE FROM %s WHERE id = $1`, r.tables.StoredFiles)
	_, err = pgxTx.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("remove stored file: %w", err)
	}
	return nil
}

// GetByID retrieves a StoredFile by its primary key.
func (r *StoredFileRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.StoredFile, error) {
	query := fmt.Sprintf(`
		SELECT id, file_obj_id, file_size, status, created_at, deleted_at
		FROM %s WHERE id = $1`,
		r.tables.StoredFiles,
	)

	row := r.pool.QueryRow(ctx, query, id)
	result, err := scanStoredFile(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get stored file by id: %w", err)
	}
	return result, nil
}

// GetByIDTx retrieves a StoredFile within a transaction, locking the row with FOR UPDATE.
func (r *StoredFileRepository) GetByIDTx(ctx context.Context, tx txpkg.Transaction, id uuid.UUID) (*domain.StoredFile, error) {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return nil, fmt.Errorf("get stored file by id (tx): %w", err)
	}

	query := fmt.Sprintf(`
		SELECT id, file_obj_id, file_size, status, created_at, deleted_at
		FROM %s WHERE id = $1
		FOR UPDATE`,
		r.tables.StoredFiles,
	)

	row := pgxTx.QueryRow(ctx, query, id)
	result, err := scanStoredFile(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get stored file by id (tx): %w", err)
	}
	return result, nil
}

// GetLatestActive returns the most recently created active StoredFile for a FileObject.
func (r *StoredFileRepository) GetLatestActive(ctx context.Context, fileObjID uuid.UUID) (*domain.StoredFile, error) {
	query := fmt.Sprintf(`
		SELECT id, file_obj_id, file_size, status, created_at, deleted_at
		FROM %s
		WHERE file_obj_id = $1 AND status = 'active' AND deleted_at IS NULL
		ORDER BY created_at DESC
		LIMIT 1`,
		r.tables.StoredFiles,
	)

	row := r.pool.QueryRow(ctx, query, fileObjID)
	result, err := scanStoredFile(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get latest active stored file: %w", err)
	}
	return result, nil
}

// ListByFileObject returns all StoredFiles for a FileObject, including soft-deleted rows.
func (r *StoredFileRepository) ListByFileObject(ctx context.Context, fileObjID uuid.UUID) ([]domain.StoredFile, error) {
	query := fmt.Sprintf(`
		SELECT id, file_obj_id, file_size, status, created_at, deleted_at
		FROM %s
		WHERE file_obj_id = $1`,
		r.tables.StoredFiles,
	)

	rows, err := r.pool.Query(ctx, query, fileObjID)
	if err != nil {
		return nil, fmt.Errorf("list stored files by file object: %w", err)
	}
	defer rows.Close()
	return scanStoredFiles(rows)
}

// ListByFileObjectIDs returns all StoredFiles for a set of FileObjects in a single query.
func (r *StoredFileRepository) ListByFileObjectIDs(ctx context.Context, fileObjIDs []uuid.UUID) ([]domain.StoredFile, error) {
	if len(fileObjIDs) == 0 {
		return []domain.StoredFile{}, nil
	}

	query := fmt.Sprintf(`
		SELECT id, file_obj_id, file_size, status, created_at, deleted_at
		FROM %s
		WHERE file_obj_id = ANY($1)`,
		r.tables.StoredFiles,
	)

	rows, err := r.pool.Query(ctx, query, fileObjIDs)
	if err != nil {
		return nil, fmt.Errorf("list stored files by file object ids: %w", err)
	}
	defer rows.Close()
	return scanStoredFiles(rows)
}

// ListPendingOlderThan returns non-deleted StoredFiles still in pending status created before the cutoff.
func (r *StoredFileRepository) ListPendingOlderThan(ctx context.Context, cutoff time.Time) ([]domain.StoredFile, error) {
	query := fmt.Sprintf(`
		SELECT id, file_obj_id, file_size, status, created_at, deleted_at
		FROM %s
		WHERE status = 'pending' AND created_at < $1 AND deleted_at IS NULL`,
		r.tables.StoredFiles,
	)

	rows, err := r.pool.Query(ctx, query, cutoff)
	if err != nil {
		return nil, fmt.Errorf("list pending stored files older than cutoff: %w", err)
	}
	defer rows.Close()
	return scanStoredFiles(rows)
}

// ListDeleted returns all soft-deleted StoredFiles.
func (r *StoredFileRepository) ListDeleted(ctx context.Context) ([]domain.StoredFile, error) {
	query := fmt.Sprintf(`
		SELECT id, file_obj_id, file_size, status, created_at, deleted_at
		FROM %s
		WHERE deleted_at IS NOT NULL`,
		r.tables.StoredFiles,
	)

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list deleted stored files: %w", err)
	}
	defer rows.Close()
	return scanStoredFiles(rows)
}

// --- scan helpers ---

func scanStoredFile(row pgx.Row) (*domain.StoredFile, error) {
	var sf domain.StoredFile
	err := row.Scan(
		&sf.ID,
		&sf.FileObjID,
		&sf.FileSize,
		&sf.Status,
		&sf.CreatedAt,
		&sf.DeletedAt,
	)
	if err != nil {
		return nil, err
	}
	return &sf, nil
}

func scanStoredFiles(rows pgx.Rows) ([]domain.StoredFile, error) {
	var files []domain.StoredFile
	for rows.Next() {
		sf, err := scanStoredFile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan stored file: %w", err)
		}
		files = append(files, *sf)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate stored files: %w", err)
	}
	if files == nil {
		files = []domain.StoredFile{}
	}
	return files, nil
}
