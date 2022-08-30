package types

import (
	stypes "agola.io/agola/services/types"

	"github.com/gofrs/uuid"
)

const (
	ChangeGroupKind    = "changegroup"
	ChangeGroupVersion = "v0.1.0"
)

type ChangeGroupType string

const (
	ChangeGroupTypeRun      ChangeGroupType = "run"
	ChangeGroupTypeRunEvent ChangeGroupType = "runevent"
)

type ChangeGroup struct {
	stypes.TypeMeta
	stypes.ObjectMeta

	Name  string `json:"name"`
	Value string `json:"value"`
}

func NewChangeGroup() *ChangeGroup {
	return &ChangeGroup{
		TypeMeta: stypes.TypeMeta{
			Kind:    ChangeGroupKind,
			Version: ChangeGroupVersion,
		},
		ObjectMeta: stypes.ObjectMeta{
			ID: uuid.Must(uuid.NewV4()).String(),
		},
	}
}
