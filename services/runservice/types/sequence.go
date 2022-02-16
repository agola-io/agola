package types

import (
	stypes "agola.io/agola/services/types"

	"github.com/gofrs/uuid"
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

func NewSequence(sequenceType SequenceType) *Sequence {
	return &Sequence{
		TypeMeta: stypes.TypeMeta{
			Kind:    SequenceKind,
			Version: SequenceVersion,
		},
		ObjectMeta: stypes.ObjectMeta{
			ID: uuid.Must(uuid.NewV4()).String(),
		},
		SequenceType: sequenceType,
	}
}
