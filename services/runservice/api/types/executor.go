package types

import (
	"time"

	"agola.io/agola/services/runservice/types"
	stypes "agola.io/agola/services/types"
)

type ExecutorStatus struct {
	ListenURL string `json:"listenURL,omitempty"`

	Archs []stypes.Arch `json:"archs,omitempty"`

	Labels map[string]string `json:"labels,omitempty"`

	AllowPrivilegedContainers bool `json:"allow_privileged_containers,omitempty"`

	ActiveTasksLimit int `json:"active_tasks_limit,omitempty"`
	ActiveTasks      int `json:"active_tasks,omitempty"`

	Dynamic bool `json:"dynamic,omitempty"`

	ExecutorGroup string `json:"executor_group,omitempty"`

	SiblingsExecutors []string `json:"siblings_executors,omitempty"`
}

type ExecutorTask struct {
	ID string `json:"id"`

	ExecutorID string `json:"executor_id"`

	Stop bool `json:"stop"`

	Status *ExecutorTaskStatus `json:"status"`

	Spec *ExecutorTaskSpecData `json:"spec"`
}

type ExecutorTaskStatus struct {
	Phase    types.ExecutorTaskPhase `json:"phase"`
	Timedout bool                    `json:"timedout"`

	FailError string `json:"fail_error"`

	SetupStep ExecutorTaskStepStatus    `json:"setup_step"`
	Steps     []*ExecutorTaskStepStatus `json:"steps"`

	StartTime *time.Time `json:"start_time"`
	EndTime   *time.Time `json:"end_time"`
}

type ExecutorTaskStepStatus struct {
	Phase types.ExecutorTaskPhase `json:"phase"`

	StartTime *time.Time `json:"start_time"`
	EndTime   *time.Time `json:"end_time"`

	ExitStatus *int `json:"exit_status"`
}

type ExecutorTaskSpecData struct {
	TaskName    string             `json:"task_name"`
	Arch        stypes.Arch        `json:"arch"`
	Containers  []*types.Container `json:"containers"`
	Environment map[string]string  `json:"environment"`
	WorkingDir  string             `json:"working_dir"`
	Shell       string             `json:"shell"`
	User        string             `json:"user"`
	Privileged  bool               `json:"privileged"`

	WorkspaceOperations []types.WorkspaceOperation `json:"workspace_operations"`

	DockerRegistriesAuth map[string]types.DockerRegistryAuth `json:"docker_registries_auth"`

	CachePrefix string `json:"cache_prefix"`

	Steps types.Steps `json:"steps"`

	TaskTimeoutInterval time.Duration `json:"task_timeout_interval"`
}
