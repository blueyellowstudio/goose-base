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

type FileObjectRepository struct {
	pool   *pgxpool.Pool
	tables FileManagerTables
}

func NewFileObjectRepository(pool *pgxpool.Pool, tables FileManagerTables) *FileObjectRepository {
	return &FileObjectRepository{pool: pool, tables: tables}
}

func scanFileObject(row pgx.Row) (*domain.FileObject, error) {
	var o domain.FileObject
	err := row.Scan(
		&o.ID,
		&o.FileID,
		&o.Name,
		&o.OriginalFileName,
		&o.LanguageID,
		&o.IsAvailable,
		&o.UpdatedAt,
		&o.DeletedAt,
		&o.Metadata,
	)
	if err != nil {
		return nil, err
	}
	return &o, nil
}

func scanFileObjectWithFile(row pgx.Row) (*domain.FileObject, *domain.File, error) {
	var o domain.FileObject
	var f domain.File
	err := row.Scan(
		&o.ID,
		&o.FileID,
		&o.Name,
		&o.OriginalFileName,
		&o.LanguageID,
		&o.IsAvailable,
		&o.UpdatedAt,
		&o.DeletedAt,
		&o.Metadata,
		&f.ID,
		&f.FolderID,
		&f.Name,
		&f.NameRef,
		&f.UserID,
		&f.FileType,
		&f.Category,
		&f.CreatedAt,
		&f.UpdatedAt,
		&f.DeletedAt,
		&f.Metadata,
	)
	if err != nil {
		return nil, nil, err
	}
	return &o, &f, nil
}

func (r *FileObjectRepository) Create(ctx context.Context, tx txpkg.Transaction, obj domain.FileObject) (*domain.FileObject, error) {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return nil, fmt.Errorf("create file object: %w", err)
	}

	query := fmt.Sprintf(`
		INSERT INTO %s (file_id, name, language_id, metadata, original_file_name)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, file_id, name, original_file_name, language_id, is_available, updated_at, deleted_at, metadata`,
		r.tables.FileObjects,
	)

	row := pgxTx.QueryRow(ctx, query, obj.FileID, obj.Name, obj.LanguageID, obj.Metadata, obj.OriginalFileName)
	result, err := scanFileObject(row)
	if err != nil {
		return nil, fmt.Errorf("create file object: %w", err)
	}
	return result, nil
}

func (r *FileObjectRepository) GetFileObjectWithFile(ctx context.Context, id uuid.UUID) (*domain.FileObject, *domain.File, error) {
	query := fmt.Sprintf(`
		SELECT
			fo.id, fo.file_id, fo.name, fo.original_file_name, fo.language_id, fo.is_available, fo.updated_at, fo.deleted_at, fo.metadata,
			f.id, f.folder_id, f.name, f.name_ref, f.user_id, f.file_type, f.category, f.created_at, f.updated_at, f.deleted_at, f.metadata
		FROM %s fo
		JOIN %s f ON f.id = fo.file_id
		WHERE fo.id = $1`,
		r.tables.FileObjects,
		r.tables.Files,
	)

	row := r.pool.QueryRow(ctx, query, id)
	obj, file, err := scanFileObjectWithFile(row)
	if err == pgx.ErrNoRows {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("get file object with file: %w", err)
	}

	return obj, file, nil
}

func (r *FileObjectRepository) GetFileObjectWithFileTx(ctx context.Context, tx txpkg.Transaction, id uuid.UUID) (*domain.FileObject, *domain.File, error) {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return nil, nil, fmt.Errorf("get file object with file (tx): %w", err)
	}

	query := fmt.Sprintf(`
		SELECT
			fo.id, fo.file_id, fo.name, fo.original_file_name, fo.language_id, fo.is_available, fo.updated_at, fo.deleted_at, fo.metadata,
			f.id, f.folder_id, f.name, f.name_ref, f.user_id, f.file_type, f.category, f.created_at, f.updated_at, f.deleted_at, f.metadata
		FROM %s fo
		JOIN %s f ON f.id = fo.file_id
		WHERE fo.id = $1
		FOR UPDATE`,
		r.tables.FileObjects,
		r.tables.Files,
	)

	row := pgxTx.QueryRow(ctx, query, id)
	obj, file, err := scanFileObjectWithFile(row)
	if err == pgx.ErrNoRows {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("get file object with file (tx): %w", err)
	}

	return obj, file, nil
}

func (r *FileObjectRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.FileObject, error) {
	query := fmt.Sprintf(`
		SELECT id, file_id, name, original_file_name, language_id, is_available, updated_at, deleted_at, metadata
		FROM %s WHERE id = $1`,
		r.tables.FileObjects,
	)

	row := r.pool.QueryRow(ctx, query, id)
	result, err := scanFileObject(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get file object by id: %w", err)
	}
	return result, nil
}

func (r *FileObjectRepository) GetByFileAndLanguage(ctx context.Context, fileID uuid.UUID, languageID int) (*domain.FileObject, error) {
	query := fmt.Sprintf(`
		SELECT id, file_id, name, original_file_name, language_id, is_available, updated_at, deleted_at, metadata
		FROM %s
		WHERE file_id = $1 AND language_id = $2 AND deleted_at IS NULL
		LIMIT 1`,
		r.tables.FileObjects,
	)

	row := r.pool.QueryRow(ctx, query, fileID, languageID)
	result, err := scanFileObject(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get file object by file and language: %w", err)
	}
	return result, nil
}

func (r *FileObjectRepository) GetDefaultByFile(ctx context.Context, fileID uuid.UUID) (*domain.FileObject, error) {
	query := fmt.Sprintf(`
		SELECT id, file_id, name, original_file_name, language_id, is_available, updated_at, deleted_at, metadata
		FROM %s
		WHERE file_id = $1 AND deleted_at IS NULL
		ORDER BY language_id NULLS FIRST
		LIMIT 1`,
		r.tables.FileObjects,
	)

	row := r.pool.QueryRow(ctx, query, fileID)
	result, err := scanFileObject(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get default file object by file: %w", err)
	}
	return result, nil
}

func (r *FileObjectRepository) Update(ctx context.Context, tx txpkg.Transaction, obj domain.FileObject) error {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return fmt.Errorf("update file object: %w", err)
	}

	query := fmt.Sprintf(`
		UPDATE %s
		SET name = $1, language_id = $2, metadata = $3, original_file_name = $4, updated_at = now()
		WHERE id = $5`,
		r.tables.FileObjects,
	)

	_, err = pgxTx.Exec(ctx, query, obj.Name, obj.LanguageID, obj.Metadata, obj.OriginalFileName, obj.ID)
	if err != nil {
		return fmt.Errorf("update file object: %w", err)
	}
	return nil
}

func (r *FileObjectRepository) MarkAvailable(ctx context.Context, tx txpkg.Transaction, id uuid.UUID) error {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return fmt.Errorf("mark file object available: %w", err)
	}

	query := fmt.Sprintf(`UPDATE %s SET is_available = true, updated_at = now() WHERE id = $1`, r.tables.FileObjects)
	_, err = pgxTx.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("mark file object available: %w", err)
	}
	return nil
}

func (r *FileObjectRepository) SoftDelete(ctx context.Context, tx txpkg.Transaction, id uuid.UUID) error {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return fmt.Errorf("soft delete file object: %w", err)
	}

	query := fmt.Sprintf(`UPDATE %s SET deleted_at = $1 WHERE id = $2`, r.tables.FileObjects)
	_, err = pgxTx.Exec(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("soft delete file object: %w", err)
	}
	return nil
}

func scanFileObjects(rows pgx.Rows) ([]domain.FileObject, error) {
	var objects []domain.FileObject
	for rows.Next() {
		o, err := scanFileObject(rows)
		if err != nil {
			return nil, fmt.Errorf("scan file object: %w", err)
		}
		objects = append(objects, *o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate file objects: %w", err)
	}
	if objects == nil {
		objects = []domain.FileObject{}
	}
	return objects, nil
}

func (r *FileObjectRepository) ListByFile(ctx context.Context, fileID uuid.UUID) ([]domain.FileObject, error) {
	query := fmt.Sprintf(`
		SELECT id, file_id, name, original_file_name, language_id, is_available, updated_at, deleted_at, metadata
		FROM %s
		WHERE file_id = $1 AND deleted_at IS NULL`,
		r.tables.FileObjects,
	)

	rows, err := r.pool.Query(ctx, query, fileID)
	if err != nil {
		return nil, fmt.Errorf("list file objects: %w", err)
	}
	defer rows.Close()
	return scanFileObjects(rows)
}

func (r *FileObjectRepository) ListAvailableByFileIDs(ctx context.Context, fileIDs []uuid.UUID) ([]domain.FileObject, error) {
	query := fmt.Sprintf(`
		SELECT id, file_id, name, original_file_name, language_id, is_available, updated_at, deleted_at, metadata
		FROM %s
		WHERE file_id = ANY($1) AND is_available = true AND deleted_at IS NULL`,
		r.tables.FileObjects,
	)

	rows, err := r.pool.Query(ctx, query, fileIDs)
	if err != nil {
		return nil, fmt.Errorf("list available file objects by file ids: %w", err)
	}
	defer rows.Close()
	return scanFileObjects(rows)
}
