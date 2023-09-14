package types

import (
	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"
)

type CommitState string

const (
	CommitStatePending CommitState = "pending"
	CommitStateSuccess CommitState = "success"
	CommitStateError   CommitState = "error"
	CommitStateFailed  CommitState = "failed"
)

type CommitStatus struct {
	sqlg.ObjectMeta

	ProjectID   string      `json:"project_id"`
	State       CommitState `json:"status"`
	CommitSHA   string      `json:"commit_sha"`
	RunCounter  uint64      `json:"run_counter"`
	Description string      `json:"description"`
	Context     string      `json:"context"`
}

func NewCommitStatus(tx *sql.Tx) *CommitStatus {
	return &CommitStatus{
		ObjectMeta: sqlg.NewObjectMeta(tx),
	}
}
