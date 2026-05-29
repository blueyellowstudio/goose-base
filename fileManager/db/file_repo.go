package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	domain "github.com/blueyellowstudio/goose-base/fileManager/domain"
	txpkg "github.com/blueyellowstudio/goose-base/tx"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type FileRepository struct {
	pool   *pgxpool.Pool
	tables FileManagerTables
}

func NewFileRepository(pool *pgxpool.Pool, tables FileManagerTables) *FileRepository {
	return &FileRepository{pool: pool, tables: tables}
}

func scanFile(row pgx.Row) (*domain.File, error) {
	var f domain.File
	err := row.Scan(
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
		return nil, err
	}
	return &f, nil
}

func (r *FileRepository) Create(ctx context.Context, tx txpkg.Transaction, file domain.File) (*domain.File, error) {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return nil, fmt.Errorf("create file: %w", err)
	}

	query := fmt.Sprintf(`
		INSERT INTO %s (folder_id, name, name_ref, user_id, file_type, category, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, folder_id, name, name_ref, user_id, file_type, category, created_at, updated_at, deleted_at, metadata`,
		r.tables.Files,
	)

	row := pgxTx.QueryRow(ctx, query,
		file.FolderID, file.Name, file.NameRef, file.UserID,
		file.FileType, file.Category, file.Metadata,
	)
	result, err := scanFile(row)
	if err != nil {
		return nil, fmt.Errorf("create file: %w", err)
	}
	return result, nil
}

func (r *FileRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.File, error) {
	query := fmt.Sprintf(`
		SELECT id, folder_id, name, name_ref, user_id, file_type, category, created_at, updated_at, deleted_at, metadata
		FROM %s WHERE id = $1`,
		r.tables.Files,
	)

	row := r.pool.QueryRow(ctx, query, id)
	result, err := scanFile(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get file by id: %w", err)
	}
	return result, nil
}

func (r *FileRepository) GetByIDTx(ctx context.Context, tx txpkg.Transaction, id uuid.UUID) (*domain.File, error) {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return nil, fmt.Errorf("get file by id (tx): %w", err)
	}

	query := fmt.Sprintf(`
		SELECT id, folder_id, name, name_ref, user_id, file_type, category, created_at, updated_at, deleted_at, metadata
		FROM %s WHERE id = $1 FOR UPDATE`,
		r.tables.Files,
	)

	row := pgxTx.QueryRow(ctx, query, id)
	result, err := scanFile(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get file by id (tx): %w", err)
	}
	return result, nil
}

func (r *FileRepository) Update(ctx context.Context, tx txpkg.Transaction, file domain.File) error {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return fmt.Errorf("update file: %w", err)
	}

	query := fmt.Sprintf(`
		UPDATE %s
		SET folder_id = $1, name = $2, name_ref = $3, file_type = $4, category = $5, metadata = $6, updated_at = now()
		WHERE id = $7`,
		r.tables.Files,
	)

	_, err = pgxTx.Exec(ctx, query,
		file.FolderID, file.Name, file.NameRef, file.FileType, file.Category, file.Metadata, file.ID,
	)
	if err != nil {
		return fmt.Errorf("update file: %w", err)
	}
	return nil
}

func (r *FileRepository) SoftDelete(ctx context.Context, tx txpkg.Transaction, id uuid.UUID, deletedAt time.Time) error {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return fmt.Errorf("soft delete file: %w", err)
	}

	query := fmt.Sprintf(`UPDATE %s SET deleted_at = $1 WHERE id = $2`, r.tables.Files)
	_, err = pgxTx.Exec(ctx, query, deletedAt, id)
	if err != nil {
		return fmt.Errorf("soft delete file: %w", err)
	}
	return nil
}

func (r *FileRepository) ListInFolder(ctx context.Context, folderID uuid.UUID, filter domain.AccessFilter) ([]domain.FileWithObject, error) {
	clause, args := filter.SQLWhereClause("f", 2)

	query := fmt.Sprintf(`
		SELECT
			f.id,
			f.folder_id,
			f.name,
			f.name_ref,
			f.user_id,
			f.file_type,
			f.category,
			f.created_at,
			f.updated_at,
			f.deleted_at,
			f.metadata,

			fo.id         AS file_object_id,
			fo.language_id,
			fo.is_available,
			fo.updated_at AS file_object_updated_at,
			fo.deleted_at AS file_object_deleted_at,
			fo.metadata   AS file_object_metadata,
			fo.name       AS file_object_name
		FROM %s f
		LEFT JOIN LATERAL (
			SELECT fo.*
			FROM %s fo
			WHERE fo.file_id = f.id
			  AND fo.deleted_at IS NULL
			ORDER BY fo.id
			LIMIT 1
		) fo ON true
		WHERE (
			f.folder_id = $1
			OR ($1 IS NULL AND f.folder_id IS NULL)
		)
		AND f.deleted_at IS NULL`,
		r.tables.Files,
		r.tables.FileObjects,
	)

	if clause != "" {
		query += " AND " + clause
	}

	rows, err := r.pool.Query(ctx, query, append([]any{folderID}, args...)...)
	if err != nil {
		return nil, fmt.Errorf("list files in folder: %w", err)
	}
	defer rows.Close()

	return scanFilesWithObject(rows)
}

func (r *FileRepository) ListInFolderPaged(ctx context.Context, folderID *uuid.UUID, filter domain.AccessFilter, cursor *domain.Cursor, limit int, nameSearch *string) ([]domain.FileWithObject, error) {
	args := []any{folderID}
	argOffset := 2

	filterClause, filterArgs := filter.SQLWhereClause("f", argOffset)
	args = append(args, filterArgs...)
	argOffset += len(filterArgs)

	query := fmt.Sprintf(`
		SELECT
			f.id,
			f.folder_id,
			f.name,
			f.name_ref,
			f.user_id,
			f.file_type,
			f.category,
			f.created_at,
			f.updated_at,
			f.deleted_at,
			f.metadata,

			fo.id         AS file_object_id,
			fo.language_id,
			fo.is_available,
			fo.updated_at AS file_object_updated_at,
			fo.deleted_at AS file_object_deleted_at,
			fo.metadata   AS file_object_metadata,
			fo.name       AS file_object_name
		FROM %s f
		LEFT JOIN LATERAL (
			SELECT fo.*
			FROM %s fo
			WHERE fo.file_id = f.id
			  AND fo.deleted_at IS NULL
			ORDER BY fo.id
			LIMIT 1
		) fo ON true
		WHERE (
        	f.folder_id = $1
        	OR ($1 IS NULL AND f.folder_id IS NULL)
    	) AND f.deleted_at IS NULL`,
		r.tables.Files,
		r.tables.FileObjects,
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
		return nil, fmt.Errorf("list files in folder paged: %w", err)
	}
	defer rows.Close()

	return scanFilesWithObject(rows)
}

func (r *FileRepository) ListFiles(ctx context.Context, filter domain.AccessFilter) ([]domain.File, error) {
	clause, args := filter.SQLWhereClause("f", 1)

	query := fmt.Sprintf(`
		SELECT f.id, f.folder_id, f.name, f.name_ref, f.user_id, f.file_type, f.category, f.created_at, f.updated_at, f.deleted_at, f.metadata
		FROM %s f
		WHERE f.deleted_at IS NULL`,
		r.tables.Files,
	)

	if clause != "" {
		query += " AND " + clause
	}

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list files for device: %w", err)
	}
	defer rows.Close()

	return scanFiles(rows)
}

func (r *FileRepository) ListByFolderIDs(ctx context.Context, folderIDs []uuid.UUID) ([]domain.File, error) {
	query := fmt.Sprintf(`
		SELECT id, folder_id, name, name_ref, user_id, file_type, category, created_at, updated_at, deleted_at, metadata
		FROM %s
		WHERE folder_id = ANY($1) AND deleted_at IS NULL`,
		r.tables.Files,
	)

	rows, err := r.pool.Query(ctx, query, folderIDs)
	if err != nil {
		return nil, fmt.Errorf("list files by folder ids: %w", err)
	}
	defer rows.Close()

	return scanFiles(rows)
}

func (r *FileRepository) ListByFolderIDsTx(ctx context.Context, tx txpkg.Transaction, folderIDs []uuid.UUID) ([]domain.File, error) {
	pgxTx, err := asPgxTx(tx)
	if err != nil {
		return nil, fmt.Errorf("list files by folder ids (tx): %w", err)
	}

	query := fmt.Sprintf(`
		SELECT id, folder_id, name, name_ref, user_id, file_type, category, created_at, updated_at, deleted_at, metadata
		FROM %s
		WHERE folder_id = ANY($1) AND deleted_at IS NULL`,
		r.tables.Files,
	)

	rows, err := pgxTx.Query(ctx, query, folderIDs)
	if err != nil {
		return nil, fmt.Errorf("list files by folder ids (tx): %w", err)
	}
	defer rows.Close()

	return scanFiles(rows)
}

func scanFiles(rows pgx.Rows) ([]domain.File, error) {
	var files []domain.File
	for rows.Next() {
		var f domain.File
		if err := rows.Scan(
			&f.ID, &f.FolderID, &f.Name, &f.NameRef, &f.UserID,
			&f.FileType, &f.Category, &f.CreatedAt, &f.UpdatedAt, &f.DeletedAt, &f.Metadata,
		); err != nil {
			return nil, fmt.Errorf("scan file: %w", err)
		}
		files = append(files, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate files: %w", err)
	}
	if files == nil {
		files = []domain.File{}
	}
	return files, nil
}

func scanFilesWithObject(rows pgx.Rows) ([]domain.FileWithObject, error) {
	var files []domain.FileWithObject
	for rows.Next() {
		var f domain.FileWithObject
		var fileObjectID *uuid.UUID
		var languageID *int
		var isAvailable *bool
		var fileObjectUpdatedAt *time.Time
		var fileObjectDeletedAt *time.Time
		var fileObjectMetadata []byte
		var fileObjectName *string

		if err := rows.Scan(
			&f.ID, &f.FolderID, &f.Name, &f.NameRef, &f.UserID,
			&f.FileType, &f.Category, &f.CreatedAt, &f.UpdatedAt, &f.DeletedAt, &f.Metadata,
			&fileObjectID, &languageID, &isAvailable,
			&fileObjectUpdatedAt, &fileObjectDeletedAt, &fileObjectMetadata, &fileObjectName,
		); err != nil {
			return nil, fmt.Errorf("scan file with object: %w", err)
		}

		if fileObjectID != nil {
			fo := domain.FileObject{
				ID:         *fileObjectID,
				FileID:     f.ID,
				LanguageID: languageID,
				DeletedAt:  fileObjectDeletedAt,
				Metadata:   fileObjectMetadata,
			}
			if fileObjectName != nil {
				fo.Name = *fileObjectName
			}
			if isAvailable != nil {
				fo.IsAvailable = *isAvailable
			}
			if fileObjectUpdatedAt != nil {
				fo.UpdatedAt = *fileObjectUpdatedAt
			}

			f.FileObject = &fo
		}

		files = append(files, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate files with object: %w", err)
	}
	if files == nil {
		files = []domain.FileWithObject{}
	}
	return files, nil
}
