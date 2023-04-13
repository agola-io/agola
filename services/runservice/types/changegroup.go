package types

import (
	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"
)

type ChangeGroupType string

const (
	ChangeGroupTypeRun      ChangeGroupType = "run"
	ChangeGroupTypeRunEvent ChangeGroupType = "runevent"
)

type ChangeGroup struct {
	sqlg.ObjectMeta

	Name  string `json:"name"`
	Value string `json:"value"`
}

func NewChangeGroup(tx *sql.Tx) *ChangeGroup {
	return &ChangeGroup{
		ObjectMeta: sqlg.NewObjectMeta(tx),
	}
}
