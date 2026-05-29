package domain

// AccessFilter is injected at query time to restrict which documents a caller may see.
// Implementations live in the project layer.
type AccessFilter interface {
	// SQLWhereClause returns an SQL fragment (e.g. "EXISTS (...)") and its
	// arguments. tableAlias is the alias used for the files/folders table in
	// the calling query; argOffset is the index of the first placeholder ($N)
	// so that argument positions do not collide with the base query's args.
	// Return an empty clause and nil args to apply no filter (full access).
	SQLWhereClause(tableAlias string, argOffset int) (clause string, args []any)
}

// NoFilter applies no access restriction — used by elevated back-office users.
type NoFilter struct{}

func (NoFilter) SQLWhereClause(string, int) (string, []any) { return "", nil }
