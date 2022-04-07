package types

import (
	"fmt"
	"time"

	stypes "agola.io/agola/services/types"
	"agola.io/agola/util"

	"github.com/gofrs/uuid"
	"github.com/mitchellh/copystructure"
)

const (
	RunKind    = "run"
	RunVersion = "v0.1.0"
)

type RunPhase string

const (
	RunPhaseSetupError RunPhase = "setuperror"
	RunPhaseQueued     RunPhase = "queued"
	RunPhaseCancelled  RunPhase = "cancelled"
	RunPhaseRunning    RunPhase = "running"
	RunPhaseFinished   RunPhase = "finished"
)

type RunResult string

const (
	RunResultUnknown RunResult = "unknown"
	RunResultStopped RunResult = "stopped"
	RunResultSuccess RunResult = "success"
	RunResultFailed  RunResult = "failed"
)

func (s RunPhase) IsFinished() bool {
	return s == RunPhaseSetupError || s == RunPhaseCancelled || s == RunPhaseFinished
}

func (s RunResult) IsSet() bool {
	return s != RunResultUnknown
}

func RunPhaseFromStringSlice(slice []string) []RunPhase {
	rss := make([]RunPhase, len(slice))
	for i, s := range slice {
		rss[i] = RunPhase(s)
	}
	return rss
}

func RunResultFromStringSlice(slice []string) []RunResult {
	rss := make([]RunResult, len(slice))
	for i, s := range slice {
		rss[i] = RunResult(s)
	}
	return rss
}

// Run is the run status of a RUN. It should containt the status of the current
// run. The run definition must live in the RunConfig and not here.
type Run struct {
	stypes.TypeMeta
	stypes.ObjectMeta

	// Sequence is an unique per runservice increasing sequence number
	Sequence uint64 `json:"sequence"`

	Name string `json:"name,omitempty"`

	RunConfigID string `json:"run_config_id,omitempty"`

	Counter uint64 `json:"counter,omitempty"`

	// Group is the run group of the run. Every run is assigned to a specific group
	// The format is /$grouptypes/groupname(/$grouptype/groupname ...)
	// i.e. /project/$projectid/branch/$branchname
	//      /project/$projectid/pr/$prid
	Group string `json:"group,omitempty"`

	// Annotations contain custom run annotations
	Annotations map[string]string `json:"annotations,omitempty"`

	// Phase represent the current run status. A run could be running but already
	// marked as failed due to some tasks failed. The run will be marked as finished
	// only then all the executor tasks are known to be really ended. This permits
	// "at most once" running runs per branch/project (useful for example to avoid
	// multiple concurrent "deploy" tasks that may cause issues)
	Phase RunPhase `json:"phase,omitempty"`

	// Result of a Run.
	Result RunResult `json:"result,omitempty"`

	// Stop is used to signal from the scheduler when the run must be stopped
	Stop bool `json:"stop,omitempty"`

	Tasks       map[string]*RunTask `json:"tasks,omitempty"`
	EnqueueTime *time.Time          `json:"enqueue_time,omitempty"`
	StartTime   *time.Time          `json:"start_time,omitempty"`
	EndTime     *time.Time          `json:"end_time,omitempty"`

	Archived bool `json:"archived,omitempty"`
}

func (r *Run) DeepCopy() *Run {
	nr, err := copystructure.Copy(r)
	if err != nil {
		panic(err)
	}
	return nr.(*Run)
}

func (r *Run) ChangePhase(phase RunPhase) {
	r.Phase = phase
	switch {
	case phase == RunPhaseRunning:
		r.StartTime = util.TimeP(time.Now())
	case phase.IsFinished():
		r.EndTime = util.TimeP(time.Now())
	}
}

func (r *Run) TasksWaitingApproval() []string {
	runTasksIDs := []string{}
	for _, rt := range r.Tasks {
		if rt.WaitingApproval {
			runTasksIDs = append(runTasksIDs, rt.ID)
		}
	}
	return runTasksIDs
}

// CanRestartFromScratch reports if the run can be restarted from scratch
func (r *Run) CanRestartFromScratch() (bool, string) {
	if r.Phase == RunPhaseSetupError {
		return false, "run has setup errors"
	}
	// can restart only if the run phase is finished or cancelled
	if !r.Phase.IsFinished() {
		return false, fmt.Sprintf("run is not finished, phase: %q", r.Phase)
	}
	return true, ""
}

// CanRestartFromFailedTasks reports if the run can be restarted from failed tasks
func (r *Run) CanRestartFromFailedTasks() (bool, string) {
	if r.Phase == RunPhaseSetupError {
		return false, "run has setup errors"
	}
	// can restart only if the run phase is finished or cancelled
	if !r.Phase.IsFinished() {
		return false, fmt.Sprintf("run is not finished, phase: %q", r.Phase)
	}
	// can restart from failed tasks only if there're some failed tasks
	if r.Result == RunResultSuccess {
		return false, fmt.Sprintf("run %q has success result, cannot restart from failed tasks", r.ID)
	}
	// can restart only if the successful tasks are fully archived
	for _, rt := range r.Tasks {
		if rt.Status == RunTaskStatusSuccess {
			if !rt.LogsFetchFinished() || !rt.ArchivesFetchFinished() {
				return false, fmt.Sprintf("run %q task %q not fully archived", r.ID, rt.ID)
			}
		}
	}
	return true, ""
}

type RunTaskStatus string

const (
	RunTaskStatusNotStarted RunTaskStatus = "notstarted"
	RunTaskStatusSkipped    RunTaskStatus = "skipped"
	RunTaskStatusCancelled  RunTaskStatus = "cancelled"
	RunTaskStatusRunning    RunTaskStatus = "running"
	RunTaskStatusStopped    RunTaskStatus = "stopped"
	RunTaskStatusSuccess    RunTaskStatus = "success"
	RunTaskStatusFailed     RunTaskStatus = "failed"
)

func (s RunTaskStatus) IsFinished() bool {
	return s == RunTaskStatusCancelled || s == RunTaskStatusSkipped || s == RunTaskStatusStopped || s == RunTaskStatusSuccess || s == RunTaskStatusFailed
}

type RunTaskFetchPhase string

const (
	RunTaskFetchPhaseNotStarted RunTaskFetchPhase = "notstarted"
	RunTaskFetchPhaseFinished   RunTaskFetchPhase = "finished"
)

type RunTask struct {
	ID string `json:"id,omitempty"`

	// Status is the current known RunTask status reported by the executor. So
	// sometime it won't be the real status since there may be some already running
	// executor tasks not yet reported back.
	// So don't rely to know if a runtask is really not running but also check that
	// there're no executor tasks scheduled
	Status RunTaskStatus `json:"status,omitempty"`

	// Annotations contain custom task annotations
	// these are opaque to the runservice and used for multiple pourposes. For
	// example to stores task approval metadata.
	Annotations map[string]string `json:"annotations,omitempty"`

	Skip bool `json:"skip,omitempty"`

	WaitingApproval bool `json:"waiting_approval,omitempty"`
	Approved        bool `json:"approved,omitempty"`

	SetupStep RunTaskStep    `json:"setup_step,omitempty"`
	Steps     []*RunTaskStep `json:"steps,omitempty"`

	// steps numbers of workspace archives,
	WorkspaceArchives      []int               `json:"workspace_archives,omitempty"`
	WorkspaceArchivesPhase []RunTaskFetchPhase `json:"workspace_archives_phase,omitempty"`

	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`
}

func (rt *RunTask) LogsFetchFinished() bool {
	if rt.SetupStep.LogPhase != RunTaskFetchPhaseFinished {
		return false
	}
	for _, rts := range rt.Steps {
		lp := rts.LogPhase
		if lp != RunTaskFetchPhaseFinished {
			return false
		}
	}
	return true
}

func (rt *RunTask) ArchivesFetchFinished() bool {
	for _, p := range rt.WorkspaceArchivesPhase {
		if p != RunTaskFetchPhaseFinished {
			return false
		}
	}
	return true
}

type RunTaskStep struct {
	Phase ExecutorTaskPhase `json:"phase,omitempty"`

	// one logphase for every task step
	LogPhase RunTaskFetchPhase `json:"log_phase,omitempty"`

	ExitStatus *int `json:"exit_status"`

	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`
}

func NewRun() *Run {
	return &Run{
		TypeMeta: stypes.TypeMeta{
			Kind:    RunKind,
			Version: RunVersion,
		},
		ObjectMeta: stypes.ObjectMeta{
			ID: uuid.Must(uuid.NewV4()).String(),
		},
	}
}
