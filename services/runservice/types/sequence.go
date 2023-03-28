package types

import (
	"github.com/gofrs/uuid"

	"agola.io/agola/internal/sql"
	stypes "agola.io/agola/services/types"
)

const (
	SequenceKind    = "sequence"
	SequenceVersion = "v0.1.0"
)

type SequenceType string

const (
	SequenceTypeRun      SequenceType = "run"
	SequenceTypeRunEvent SequenceType = "runevent"
)

// Sequence is an unique (per runservice) increasing sequence number
type Sequence struct {
	stypes.TypeMeta
	stypes.ObjectMeta

	Value        uint64       `json:"value"`
	SequenceType SequenceType `json:"sequence_type"`
}

func NewSequence(tx *sql.Tx, sequenceType SequenceType) *Sequence {
	return &Sequence{
		TypeMeta: stypes.TypeMeta{
			Kind:    SequenceKind,
			Version: SequenceVersion,
		},
		ObjectMeta: stypes.ObjectMeta{
			ID:   uuid.Must(uuid.NewV4()).String(),
			TxID: tx.ID(),
		},
		SequenceType: sequenceType,
	}
}
