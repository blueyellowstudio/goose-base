package db

import (
	txpgxrunner "github.com/blueyellowstudio/goose-base/tx/pgxrunner"

	"github.com/jackc/pgx/v5/pgxpool"
)

type TxRunner = txpgxrunner.Runner

func NewTxRunner(pool *pgxpool.Pool) *TxRunner {
	return txpgxrunner.NewRunner(pool)
}
