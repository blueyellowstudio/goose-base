package query

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// EntityQuery describes the columns and row scanner shared by queries for one entity.
type EntityQuery[T any] struct {
	Columns string
	Scan    func(row pgx.Row) (*T, error)
}

// Querier is implemented by PostgreSQL connections, pools, and transactions.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// QueryOne executes a query and scans its single result with the entity descriptor.
func QueryOne[T any](ctx context.Context, conn Querier, entity EntityQuery[T], sql string, args ...any) (*T, error) {
	return entity.Scan(conn.QueryRow(ctx, sql, args...))
}

// QueryMany executes a query and scans all results with the entity descriptor.
func QueryMany[T any](ctx context.Context, conn Querier, entity EntityQuery[T], sql string, args ...any) ([]T, error) {
	rows, err := conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []T
	for rows.Next() {
		item, err := entity.Scan(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, *item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return results, nil
}
