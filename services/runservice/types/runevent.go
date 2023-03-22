package types

import (
	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"
)

type RunEvent struct {
	sqlg.ObjectMeta

	Sequence uint64

	RunID  string
	Phase  RunPhase
	Result RunResult
}

func NewRunEvent(tx *sql.Tx) *RunEvent {
	return &RunEvent{
		ObjectMeta: sqlg.NewObjectMeta(tx),
	}
}
