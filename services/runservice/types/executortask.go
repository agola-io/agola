package types

import (
	"time"

	"github.com/mitchellh/copystructure"

	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"
	stypes "agola.io/agola/services/types"
)

type ExecutorTaskPhase string

const (
	ExecutorTaskPhaseNotStarted ExecutorTaskPhase = "notstarted"
	ExecutorTaskPhaseCancelled  ExecutorTaskPhase = "cancelled"
	ExecutorTaskPhaseRunning    ExecutorTaskPhase = "running"
	ExecutorTaskPhaseStopped    ExecutorTaskPhase = "stopped"
	ExecutorTaskPhaseSuccess    ExecutorTaskPhase = "success"
	ExecutorTaskPhaseFailed     ExecutorTaskPhase = "failed"
)

func (s ExecutorTaskPhase) IsFinished() bool {
	return s == ExecutorTaskPhaseCancelled || s == ExecutorTaskPhaseStopped || s == ExecutorTaskPhaseSuccess || s == ExecutorTaskPhaseFailed
}

type ExecutorTask struct {
	sqlg.ObjectMeta

	ExecutorID string `json:"executor_id,omitempty"`
	RunID      string `json:"run_id,omitempty"`
	RunTaskID  string `json:"run_task_id,omitempty"`

	// Stop is used to signal from the scheduler when the task must be stopped
	Stop bool `json:"stop,omitempty"`

	Phase    ExecutorTaskPhase `json:"phase,omitempty"`
	Timedout bool              `json:"timedout,omitempty"`

	FailError string `json:"fail_error,omitempty"`

	SetupStep ExecutorTaskStepStatus    `json:"setup_step,omitempty"`
	Steps     []*ExecutorTaskStepStatus `json:"steps,omitempty"`

	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`
}

func (et *ExecutorTask) DeepCopy() *ExecutorTask {
	net, err := copystructure.Copy(et)
	if err != nil {
		panic(err)
	}
	return net.(*ExecutorTask)
}

// ExecutorTaskSpecData defines the task data required to execute the tasks.
// These values are not saved in the db to avoid using too much space but are
// generated everytime they are sent to the executor
type ExecutorTaskSpecData struct {
	TaskName    string            `json:"task_name,omitempty"`
	Arch        stypes.Arch       `json:"arch,omitempty"`
	Containers  []*Container      `json:"containers,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	WorkingDir  string            `json:"working_dir,omitempty"`
	Shell       string            `json:"shell,omitempty"`
	User        string            `json:"user,omitempty"`
	Privileged  bool              `json:"privileged"`

	WorkspaceOperations []WorkspaceOperation `json:"workspace_operations,omitempty"`

	DockerRegistriesAuth map[string]DockerRegistryAuth `json:"docker_registries_auth"`

	// Cache prefix to use when asking for a cache key. To isolate caches between
	// groups (projects)
	CachePrefix string `json:"cache_prefix,omitempty"`

	Steps Steps `json:"steps,omitempty"`

	TaskTimeoutInterval time.Duration `json:"task_timeout_interval"`
}

type ExecutorTaskStepStatus struct {
	Phase ExecutorTaskPhase `json:"phase,omitempty"`

	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`

	ExitStatus *int `json:"exit_status,omitempty"`
}

type WorkspaceOperation struct {
	TaskID    string `json:"task_id,omitempty"`
	Step      int    `json:"step,omitempty"`
	Overwrite bool   `json:"overwrite,omitempty"`
}

func NewExecutorTask(tx *sql.Tx) *ExecutorTask {
	return &ExecutorTask{
		ObjectMeta: sqlg.NewObjectMeta(tx),
	}
}
