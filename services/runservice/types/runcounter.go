package types

import (
	stypes "agola.io/agola/services/types"

	"github.com/gofrs/uuid"
)

const (
	RunCounterKind    = "runcounter"
	RunCounterVersion = "v0.1.0"
)

type RunCounter struct {
	stypes.TypeMeta
	stypes.ObjectMeta

	GroupID string
	Value   uint64
}

func NewRunCounter(groupID string) *RunCounter {
	return &RunCounter{
		TypeMeta: stypes.TypeMeta{
			Kind:    RunCounterKind,
			Version: RunCounterVersion,
		},
		ObjectMeta: stypes.ObjectMeta{
			ID: uuid.Must(uuid.NewV4()).String(),
		},
		GroupID: groupID,
	}
}
