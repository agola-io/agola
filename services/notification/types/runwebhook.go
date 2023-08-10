package types

import (
	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"
)

type RunWebhook struct {
	sqlg.ObjectMeta

	Payload []byte `json:"payload"`
}

func NewRunWebhook(tx *sql.Tx) *RunWebhook {
	return &RunWebhook{
		ObjectMeta: sqlg.NewObjectMeta(tx),
	}
}
