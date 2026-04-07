package simpledbmigrations

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Migration holds the connection pool used to run database migrations.
type Migration struct {
	pool      *pgxpool.Pool
	tableName string
}

// NewMigration creates a Migration instance with the given connection pool.
func NewMigration(pool *pgxpool.Pool) *Migration {
	return &Migration{pool: pool, tableName: "simple_db_migrations"}
}

// ensureTable creates the simple_db_migrations table if it does not exist yet.
func (m *Migration) ensureTable() error {
	createTable := `CREATE TABLE IF NOT EXISTS ` + m.tableName + ` (id INT PRIMARY KEY)`
	_, err := m.pool.Exec(context.Background(), createTable)
	return err
}

// getDBVersion queries the migrations table for the latest applied version.
// Returns -1 if the table exists but contains no rows.
func (m *Migration) getDBVersion() (int, error) {
	if err := m.ensureTable(); err != nil {
		return -1, fmt.Errorf("failed to ensure migrations table: %w", err)
	}

	var dbVersion int
	query := `SELECT id FROM ` + m.tableName + ` ORDER BY id DESC LIMIT 1`
	err := m.pool.QueryRow(context.Background(), query).Scan(&dbVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return -1, nil
	}
	if err != nil {
		return -1, err
	}
	return dbVersion, nil
}

// RunMigrations checks the current DB version and executes all necessary migration
// files from migrationsPath to bring the database up to requiredDbVersion.
func (m *Migration) RunMigrations(migrationsPath string, requiredDbVersion int) (int, error) {
	currentVersion, err := m.getDBVersion()
	if err != nil {
		return 0, fmt.Errorf("failed to get current DB version: %w", err)
	}

	if currentVersion >= requiredDbVersion {
		log.Printf("Database is up to date (version %d)", currentVersion)
		return currentVersion, nil
	}

	log.Printf("Database version %d, required version %d. Running migrations...", currentVersion, requiredDbVersion)

	for version := currentVersion + 1; version <= requiredDbVersion; version++ {
		migrationFile := filepath.Join(migrationsPath, fmt.Sprintf("%d.sql", version))
		log.Printf("Running migration %d: %s", version, migrationFile)

		sqlBytes, err := os.ReadFile(migrationFile)
		if err != nil {
			return currentVersion, fmt.Errorf("failed to read migration file %s: %w", migrationFile, err)
		}

		_, err = m.pool.Exec(context.Background(), string(sqlBytes))
		if err != nil {
			return currentVersion, fmt.Errorf("failed to execute migration %d: %w", version, err)
		}

		insertQuery := `INSERT INTO ` + m.tableName + ` (id) VALUES ($1)`
		_, err = m.pool.Exec(context.Background(), insertQuery, version)
		if err != nil {
			return currentVersion, fmt.Errorf("failed to update db_version to %d: %w", version, err)
		}

		log.Printf("Successfully applied migration %d", version)
	}

	currentVersion, err = m.getDBVersion()
	if err != nil {
		return -1, fmt.Errorf("failed to get current DB version: %w", err)
	}
	log.Printf("Database migrations completed. Now at version %d", currentVersion)
	return currentVersion, nil
}
