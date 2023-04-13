package types

import (
	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"
)

type RunCounter struct {
	sqlg.ObjectMeta

	GroupID string
	Value   uint64
}

func NewRunCounter(tx *sql.Tx, groupID string) *RunCounter {
	return &RunCounter{
		ObjectMeta: sqlg.NewObjectMeta(tx),

		GroupID: groupID,
	}
}
