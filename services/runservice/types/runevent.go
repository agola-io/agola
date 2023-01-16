package types

import (
	"encoding/json"
	"time"

	"github.com/sorintlab/errors"

	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"
)

type RunEventType string

const (
	RunPhaseChanged RunEventType = "run_phase_changed"

	RunEventDataVersion = 1
)

type RunEvent struct {
	sqlg.ObjectMeta

	Sequence uint64

	RunEventType RunEventType
	RunID        string
	Phase        RunPhase
	Result       RunResult

	Data        any
	DataVersion uint64
}

func (e *RunEvent) PreJSON() error {
	switch e.DataVersion {
	case 1:
		e.Data = &RunEventData{}
	default:
		return errors.Errorf("unknown runevent data version: %d", e.DataVersion)
	}

	return nil
}

func (e *RunEvent) UnmarshalJSON(data []byte) error {
	type origRunEvent RunEvent
	type runEvent struct {
		origRunEvent
		Data json.RawMessage
	}

	v := &runEvent{}

	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	*e = RunEvent(v.origRunEvent)

	switch v.DataVersion {
	case 1:
		e.Data = &RunEventData{}
	default:
		return errors.Errorf("unknown runevent data version: %d", e.DataVersion)
	}

	if err := json.Unmarshal(v.Data, &e.Data); err != nil {
		return err
	}

	return nil
}

type RunEventData struct {
	ID          string                          `json:"id,omitempty"`
	Name        string                          `json:"name,omitempty"`
	Counter     uint64                          `json:"counter,omitempty"`
	Phase       string                          `json:"phase,omitempty"`
	Result      string                          `json:"result,omitempty"`
	SetupErrors []string                        `json:"setup_errors,omitempty"`
	Tasks       map[string]*RunEventDataRunTask `json:"tasks,omitempty"`
	EnqueueTime *time.Time                      `json:"enqueue_time,omitempty"`
	StartTime   *time.Time                      `json:"start_time,omitempty"`
	EndTime     *time.Time                      `json:"end_time,omitempty"`
	Annotations map[string]string               `json:"annotations,omitempty"`
}

type RunEventDataRunTask struct {
	ID              string                                `json:"id,omitempty"`
	Name            string                                `json:"name,omitempty"`
	Level           int                                   `json:"level,omitempty"`
	Skip            bool                                  `json:"skip,omitempty"`
	Depends         map[string]*RunEventDataRunTaskDepend `json:"depends,omitempty"`
	Status          string                                `json:"status,omitempty"`
	Timedout        bool                                  `json:"timedout,omitempty"`
	WaitingApproval bool                                  `json:"waiting_approval,omitempty"`
	Approved        bool                                  `json:"approved,omitempty"`
	SetupStep       RunEventDataRunTaskStep               `json:"setup_step,omitempty"`
	Steps           []*RunEventDataRunTaskStep            `json:"steps,omitempty"`
	StartTime       *time.Time                            `json:"start_time,omitempty"`
	EndTime         *time.Time                            `json:"end_time,omitempty"`
}

type RunEventDataRunTaskStep struct {
	Phase      string     `json:"phase,omitempty"`
	ExitStatus *int       `json:"exit_status,omitempty"`
	StartTime  *time.Time `json:"start_time,omitempty"`
	EndTime    *time.Time `json:"end_time,omitempty"`
}

type RunEventDataRunTaskDepend struct {
	TaskID     string   `json:"task_id,omitempty"`
	Conditions []string `json:"conditions,omitempty"`
}

func NewRunEvent(tx *sql.Tx) *RunEvent {
	return &RunEvent{
		ObjectMeta: sqlg.NewObjectMeta(tx),
	}
}
