package tx

import "context"

// Transaction is an opaque transaction handle passed across service and domain boundaries.
// Infrastructure layers can unwrap it to concrete driver transactions (e.g. pgx.Tx).
type Transaction interface {
	privateTransaction() any
}

type transaction struct {
	value any
}

func (t transaction) privateTransaction() any {
	return t.value
}

func Wrap(value any) Transaction {
	return transaction{value: value}
}

func Unwrap[T any](tr Transaction) (T, bool) {
	wrapped, ok := tr.(transaction)
	if !ok {
		var zero T
		return zero, false
	}

	value, ok := wrapped.value.(T)
	if !ok {
		var zero T
		return zero, false
	}

	return value, ok
}

type Runner interface {
	RunInTx(ctx context.Context, fn func(ctx context.Context, tx Transaction) error) error
}
