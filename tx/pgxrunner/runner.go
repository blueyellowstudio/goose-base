package pgxrunner

import (
	"context"
	"fmt"

	txpkg "github.com/blueyellowstudio/goose-base/tx"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Runner struct {
	pool *pgxpool.Pool
}

func NewRunner(pool *pgxpool.Pool) *Runner {
	return &Runner{pool: pool}
}

func (r *Runner) RunInTx(ctx context.Context, fn func(ctx context.Context, tx txpkg.Transaction) error) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	if err := fn(ctx, txpkg.Wrap(tx)); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}
