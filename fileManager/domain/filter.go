package domain

import (
	"fmt"
	"time"
)

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

type AccessFilterGropuedCondition string

const (
	ConditionAnd AccessFilterGropuedCondition = "AND"
	ConditionOr  AccessFilterGropuedCondition = "OR"
)

type AccessFilterGrouped struct {
	Filters   []AccessFilter
	Condition AccessFilterGropuedCondition
}

func NewAccessFilterGrouped(cond AccessFilterGropuedCondition, filters ...AccessFilter) AccessFilter {
	return AccessFilterGrouped{Filters: filters, Condition: cond}
}

func (a AccessFilterGrouped) SQLWhereClause(tableAlias string, argOffset int) (clause string, args []any) {
	clause += "("
	for i, filter := range a.Filters {
		thisClauses, thisArgs := filter.SQLWhereClause(tableAlias, argOffset)

		if i > 0 {
			clause += " " + string(a.Condition) + " " + thisClauses
		} else {
			clause += thisClauses
		}
		args = append(args, thisArgs...)

		argOffset += len(thisArgs)
	}

	clause += ")"
	return clause, args
}

type AfterUpdatedAtFilter struct {
	UpdatedAt time.Time
}

func (f AfterUpdatedAtFilter) SQLWhereClause(alias string, n int) (string, []any) {
	var args []any
	clause := fmt.Sprintf(
		"%s.updated_at > $%d",
		alias, n,
	)
	return clause, append(args, f.UpdatedAt)
}
