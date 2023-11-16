package types

import (
	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"
)

type RunWebhook struct {
	sqlg.ObjectMeta

	Payload   []byte `json:"payload"`
	ProjectID string `json:"project_id"`
}

func NewRunWebhook(tx *sql.Tx) *RunWebhook {
	return &RunWebhook{
		ObjectMeta: sqlg.NewObjectMeta(tx),
	}
}
