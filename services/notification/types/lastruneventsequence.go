package types

import (
	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"
)

type LastRunEventSequence struct {
	sqlg.ObjectMeta

	Value uint64 `json:"value"`
}

func NewLastRunEventSequence(tx *sql.Tx) *LastRunEventSequence {
	return &LastRunEventSequence{
		ObjectMeta: sqlg.NewObjectMeta(tx),
	}
}
