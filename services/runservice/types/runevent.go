package types

import (
	"github.com/gofrs/uuid"

	"agola.io/agola/internal/sql"
	stypes "agola.io/agola/services/types"
)

const (
	RunEventKind    = "runevent"
	RunEventVersion = "v0.1.0"
)

type RunEvent struct {
	stypes.TypeMeta
	stypes.ObjectMeta

	Sequence uint64

	RunID  string
	Phase  RunPhase
	Result RunResult
}

func NewRunEvent(tx *sql.Tx) *RunEvent {
	return &RunEvent{
		TypeMeta: stypes.TypeMeta{
			Kind:    RunEventKind,
			Version: RunEventVersion,
		},
		ObjectMeta: stypes.ObjectMeta{
			ID:   uuid.Must(uuid.NewV4()).String(),
			TxID: tx.ID(),
		},
	}
}
