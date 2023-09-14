package types

import (
	"time"

	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"
)

type CommitStatusDelivery struct {
	sqlg.ObjectMeta

	Sequence uint64 `json:"sequence"`

	CommitStatusID string         `json:"commit_status_id"`
	DeliveryStatus DeliveryStatus `json:"delivery_status"`
	DeliveredAt    *time.Time     `json:"delivered_at"`
}

func NewCommitStatusDelivery(tx *sql.Tx) *CommitStatusDelivery {
	return &CommitStatusDelivery{
		ObjectMeta: sqlg.NewObjectMeta(tx),
	}
}
