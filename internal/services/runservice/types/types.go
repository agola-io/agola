// Copyright 2019 Sorint.lab
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied
// See the License for the specific language governing permissions and
// limitations under the License.

package types

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sorintlab/agola/internal/util"
)

type RunBundle struct {
	Run *Run
	Rc  *RunConfig
	Rd  *RunData
}

type SortOrder int

const (
	SortOrderAsc SortOrder = iota
	SortOrderDesc
)

type RunPhase string

const (
	RunPhaseQueued    RunPhase = "queued"
	RunPhaseCancelled RunPhase = "cancelled"
	RunPhaseRunning   RunPhase = "running"
	RunPhaseFinished  RunPhase = "finished"
)

type RunResult string

const (
	RunResultUnknown RunResult = "unknown"
	RunResultStopped RunResult = "stopped"
	RunResultSuccess RunResult = "success"
	RunResultFailed  RunResult = "failed"
)

func (s RunPhase) IsFinished() bool {
	return s == RunPhaseCancelled || s == RunPhaseFinished
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

// Run is the run status of a RUN. Until the run is not finished it'll live in
// etcd. So we should keep it smaller to avoid using too much space
type Run struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`

	Counter uint64 `json:"counter,omitempty"`

	// Group is the run group of the run. Every run is assigned to a specific group
	// The format is /$grouptypes/groupname(/$grouptype/groupname ...)
	// i.e. /project/$projectid/branch/$branchname
	//      /project/$projectid/pr/$prid
	Group string `json:"group,omitempty"`

	// Annotations contain custom run properties
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

	RunTasks    map[string]*RunTask `json:"run_tasks,omitempty"`
	EnqueueTime *time.Time          `json:"enqueue_time,omitempty"`
	StartTime   *time.Time          `json:"start_time,omitempty"`
	EndTime     *time.Time          `json:"end_time,omitempty"`

	Archived bool `json:"archived,omitempty"`

	// internal values not saved
	Revision int64 `json:"-"`
}

func (r *Run) ChangePhase(phase RunPhase) {
	r.Phase = phase
	switch {
	case phase == RunPhaseRunning:
		r.StartTime = util.TimePtr(time.Now())
	case phase.IsFinished():
		r.EndTime = util.TimePtr(time.Now())
	}
}

func (r *Run) TasksWaitingApproval() []string {
	runTasksIDs := []string{}
	for _, rt := range r.RunTasks {
		if rt.WaitingApproval {
			runTasksIDs = append(runTasksIDs, rt.ID)
		}
	}
	return runTasksIDs
}

// CanRestartFromScratch reports if the run can be restarted from scratch
func (r *Run) CanRestartFromScratch() (bool, string) {
	// can restart only if the run phase is finished or cancelled
	if !r.Phase.IsFinished() {
		return false, fmt.Sprintf("run is not finished, phase: %q", r.Phase)
	}
	return true, ""
}

// CanRestartFromFailedTasks reports if the run can be restarted from failed tasks
func (r *Run) CanRestartFromFailedTasks() (bool, string) {
	// can restart only if the run phase is finished or cancelled
	if !r.Phase.IsFinished() {
		return false, fmt.Sprintf("run is not finished, phase: %q", r.Phase)
	}
	// can restart from failed tasks only if there're some failed tasks
	if r.Result == RunResultSuccess {
		return false, fmt.Sprintf("run %q has success result, cannot restart from failed tasks", r.ID)
	}
	// can restart only if the successful tasks are fully archived
	for _, rt := range r.RunTasks {
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

	Skip bool `json:"skip,omitempty"`

	WaitingApproval bool `json:"waiting_approval,omitempty"`
	Approved        bool `json:"approved,omitempty"`
	// ApprovalAnnotations stores data that the user can set on the approval. Useful
	// to save approval information like the user who approved the task.
	// This data is opaque to the run service
	ApprovalAnnotations map[string]string `json:"approval_annotations,omitempty"`

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

	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`
}

// RunData

// RunData is the data for a RUN. It contains everything that isn't a state
// (it's contained in a Run) and that may use a lot of space. It lives in the
// storage. There is a RunData for every Run.
type RunData struct {
	ID string `json:"id,omitempty"`

	// Group is the run group of the run. Every run is assigned to a specific group
	// i.e. project/$projectid/$branch
	// i.e. user/$projectid/$branch (for a user run)
	// this is the format that will be used to archive the runs in the lts. It's
	// also needed to fetch them when they aren't indexed in the readdb.
	Group string `json:"group,omitempty"`

	// Environment contains all environment variables that are different between runs also if using the same RunConfig
	// (like secrets that may change or user provided enviroment specific to this run)
	Environment map[string]string `json:"environment,omitempty"`

	// Annotations contain custom run properties
	// Note: Annotations are currently both saved in a Run and in RunData to easily return them without loading RunData from the lts
	Annotations map[string]string `json:"annotations,omitempty"`
}

// RunConfig

// RunConfig is the run configuration. It lives in the storage. It can be
// copied (i.e when we create a new run from an previous run).
// It could also be shared but to simplify the run delete logic we will just
// copy it when creating a new run as a modified previous run.
type RunConfig struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`

	// Environment contains all environment variables that won't change when
	// generating a new run (like COMMIT_SHA, BRANCH, REPOSITORY_URL etc...)
	Environment map[string]string `json:"environment,omitempty"`

	Tasks map[string]*RunConfigTask `json:"tasks,omitempty"`
}

type RunConfigTask struct {
	Level         int                    `json:"level,omitempty"`
	ID            string                 `json:"id,omitempty"`
	Name          string                 `json:"name,omitempty"`
	Depends       []*RunConfigTaskDepend `json:"depends"`
	Runtime       *Runtime               `json:"runtime,omitempty"`
	Environment   map[string]string      `json:"environment,omitempty"`
	WorkingDir    string                 `json:"working_dir,omitempty"`
	Shell         string                 `json:"shell,omitempty"`
	User          string                 `json:"user,omitempty"`
	Steps         []interface{}          `json:"steps,omitempty"`
	IgnoreFailure bool                   `json:"ignore_failure,omitempty"`
	NeedsApproval bool                   `json:"needs_approval,omitempty"`
	Skip          bool                   `json:"skip,omitempty"`
}

type RunConfigTaskDependCondition string

const (
	RunConfigTaskDependConditionOnSuccess RunConfigTaskDependCondition = "on_success"
	RunConfigTaskDependConditionOnFailure RunConfigTaskDependCondition = "on_failure"
)

type RunConfigTaskDepend struct {
	TaskID     string                         `json:"task_id,omitempty"`
	Conditions []RunConfigTaskDependCondition `json:"conditions,omitempty"`
}

type RuntimeType string

const (
	RuntimeTypePod RuntimeType = "pod"
)

type Runtime struct {
	Type       RuntimeType  `json:"type,omitempty"`
	Containers []*Container `json:"containers,omitempty"`
}

func (rct *RunConfigTask) UnmarshalJSON(b []byte) error {
	type rctask RunConfigTask

	type task struct {
		Steps []json.RawMessage `json:"steps,omitempty"`
	}

	rctt := (*rctask)(rct)
	if err := json.Unmarshal(b, &rctt); err != nil {
		return err
	}

	var st task
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}

	steps := make([]interface{}, len(st.Steps))
	for i, s := range st.Steps {
		var bs Step
		if err := json.Unmarshal(s, &bs); err != nil {
			return err
		}
		switch bs.Type {
		case "run":
			var rs RunStep
			if err := json.Unmarshal(s, &rs); err != nil {
				return err
			}
			steps[i] = &rs
		case "save_to_workspace":
			var rs SaveToWorkspaceStep
			if err := json.Unmarshal(s, &rs); err != nil {
				return err
			}
			steps[i] = &rs
		case "restore_workspace":
			var rs RestoreWorkspaceStep
			if err := json.Unmarshal(s, &rs); err != nil {
				return err
			}
			steps[i] = &rs
		}
	}

	rct.Steps = steps

	return nil
}

type Step struct {
	Type string `json:"type,omitempty"`
	Name string `json:"name,omitempty"`
}

type RunStep struct {
	Step
	Command     string            `json:"command,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	WorkingDir  string            `json:"working_dir,omitempty"`
	Shell       string            `json:"shell,omitempty"`
	User        string            `json:"user,omitempty"`
}

type SaveToWorkspaceContent struct {
	SourceDir string   `json:"source_dir,omitempty"`
	DestDir   string   `json:"dest_dir,omitempty"`
	Paths     []string `json:"paths,omitempty"`
}

type SaveToWorkspaceStep struct {
	Step
	Contents []SaveToWorkspaceContent `json:"contents,omitempty"`
}

type RestoreWorkspaceStep struct {
	Step
	DestDir string `json:"dest_dir,omitempty"`
}

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
	Revision    int64             `json:"revision,omitempty"`
	ID          string            `json:"id,omitempty"`
	RunID       string            `json:"run_id,omitempty"`
	TaskName    string            `json:"task_name,omitempty"`
	Containers  []*Container      `json:"containers,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	WorkingDir  string            `json:"working_dir,omitempty"`
	Shell       string            `json:"shell,omitempty"`
	User        string            `json:"user,omitempty"`
	Privileged  bool              `yaml:"privileged"`

	Steps []interface{} `json:"steps,omitempty"`

	Status     ExecutorTaskStatus `json:"status,omitempty"`
	SetupError string             `fail_reason:"setup_error,omitempty"`
	FailError  string             `fail_reason:"fail_error,omitempty"`

	Workspace Workspace `json:"workspace,omitempty"`

	// Stop is used to signal from the scheduler when the task must be stopped
	Stop bool `json:"stop,omitempty"`
}

type ExecutorTaskStatus struct {
	ExecutorID string            `json:"executor_id,omitempty"`
	Phase      ExecutorTaskPhase `json:"phase,omitempty"`

	SetupStep ExecutorTaskStepStatus    `json:"setup_step,omitempty"`
	Steps     []*ExecutorTaskStepStatus `json:"steps,omitempty"`

	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`
}

type ExecutorTaskStepStatus struct {
	Phase ExecutorTaskPhase `json:"phase,omitempty"`

	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`

	ExitCode int `json:"exit_code,omitempty"`
}

type Container struct {
	Image       string            `json:"image,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	User        string            `json:"user,omitempty"`
	Privileged  bool              `json:"privileged"`
	Entrypoint  string            `json:"entrypoint"`
}

type Workspace []WorkspaceLevel

type WorkspaceLevel []WorkspaceArchives

type WorkspaceArchives []WorkspaceArchive

type WorkspaceArchive struct {
	TaskID string `json:"task_id,omitempty"`
	Step   int    `json:"step,omitempty"`
}

func (et *ExecutorTask) UnmarshalJSON(b []byte) error {
	type etask ExecutorTask

	type task struct {
		Steps []json.RawMessage `json:"steps,omitempty"`
	}

	ett := (*etask)(et)
	if err := json.Unmarshal(b, &ett); err != nil {
		return err
	}

	var st task
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}

	steps := make([]interface{}, len(ett.Steps))
	for i, s := range st.Steps {
		var bs Step
		if err := json.Unmarshal(s, &bs); err != nil {
			return err
		}
		switch bs.Type {
		case "run":
			var rs RunStep
			if err := json.Unmarshal(s, &rs); err != nil {
				return err
			}
			steps[i] = &rs
		case "save_to_workspace":
			var rs SaveToWorkspaceStep
			if err := json.Unmarshal(s, &rs); err != nil {
				return err
			}
			steps[i] = &rs
		case "restore_workspace":
			var rs RestoreWorkspaceStep
			if err := json.Unmarshal(s, &rs); err != nil {
				return err
			}
			steps[i] = &rs
		}
	}

	et.Steps = steps

	return nil
}

type ChangeGroupsUpdateToken struct {
	CurRevision           int64                 `json:"cur_revision"`
	ChangeGroupsRevisions ChangeGroupsRevisions `json:"change_groups_revisions"`
}

type ChangeGroupsRevisions map[string]int64

func MarshalChangeGroupsUpdateToken(t *ChangeGroupsUpdateToken) (string, error) {
	tj, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(tj), nil
}

func UnmarshalChangeGroupsUpdateToken(s string) (*ChangeGroupsUpdateToken, error) {
	if s == "" {
		return nil, nil
	}

	tj, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	var t *ChangeGroupsUpdateToken
	if err := json.Unmarshal(tj, &t); err != nil {
		return nil, err
	}
	return t, nil
}

type Executor struct {
	// ID is the Executor unique id
	ID        string `json:"id,omitempty"`
	ListenURL string `json:"listenURL,omitempty"`

	// internal values not saved
	Revision int64 `json:"-"`
}
