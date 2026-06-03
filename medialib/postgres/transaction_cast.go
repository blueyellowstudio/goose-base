package postgres

import (
	"fmt"

	txpkg "github.com/blueyellowstudio/goose-base/tx"

	"github.com/jackc/pgx/v5"
)

func asPgxTx(tx txpkg.Transaction) (pgx.Tx, error) {
	pgxTx, ok := txpkg.Unwrap[pgx.Tx](tx)
	if !ok {
		return nil, fmt.Errorf("invalid transaction type")
	}

	return pgxTx, nil
}
