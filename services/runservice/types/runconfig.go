package types

import (
	"encoding/json"

	"agola.io/agola/internal/errors"
	stypes "agola.io/agola/services/types"
	"agola.io/agola/util"

	"github.com/gofrs/uuid"
	"github.com/mitchellh/copystructure"
)

const (
	RunConfigKind    = "runconfig"
	RunConfigVersion = "v0.1.0"
)

// RunConfig

// RunConfig is the run configuration.
// It contains everything that isn't a state (that is contained in a Run) and
// that may use a lot of space. It lives in the storage. There is a RunConfig
// for every Run.
type RunConfig struct {
	stypes.TypeMeta
	stypes.ObjectMeta

	Name string `json:"name,omitempty"`

	// Group is the run group of the run. Every run is assigned to a specific group
	// The format is /$grouptypes/groupname(/$grouptype/groupname ...)
	// i.e. /project/$projectid/branch/$branchname
	//      /project/$projectid/pr/$prid
	Group string `json:"group,omitempty"`

	// A list of setup errors when the run is in phase setuperror
	SetupErrors []string `json:"setup_errors,omitempty"`

	// Annotations contain custom run annotations
	// Note: Annotations are currently both saved in a Run and in RunConfig to
	// easily return them without loading RunConfig from the lts
	Annotations map[string]string `json:"annotations,omitempty"`

	// StaticEnvironment contains all environment variables that won't change when
	// generating a new run (like COMMIT_SHA, BRANCH, REPOSITORY_URL etc...)
	StaticEnvironment map[string]string `json:"static_environment,omitempty"`

	// Environment contains all environment variables that are different between
	// runs recreations (like secrets that may change or user provided enviroment
	// specific to this run)
	Environment map[string]string `json:"environment,omitempty"`

	Tasks map[string]*RunConfigTask `json:"tasks,omitempty"`

	// CacheGroup is the cache group where the run caches belongs
	CacheGroup string `json:"cache_group,omitempty"`
}

func (rc *RunConfig) DeepCopy() *RunConfig {
	nrc, err := copystructure.Copy(rc)
	if err != nil {
		panic(err)
	}
	return nrc.(*RunConfig)
}

type RunConfigTask struct {
	Level                int                             `json:"level,omitempty"`
	ID                   string                          `json:"id,omitempty"`
	Name                 string                          `json:"name,omitempty"`
	Depends              map[string]*RunConfigTaskDepend `json:"depends"`
	Runtime              *Runtime                        `json:"runtime,omitempty"`
	Environment          map[string]string               `json:"environment,omitempty"`
	WorkingDir           string                          `json:"working_dir,omitempty"`
	Shell                string                          `json:"shell,omitempty"`
	User                 string                          `json:"user,omitempty"`
	Steps                Steps                           `json:"steps,omitempty"`
	IgnoreFailure        bool                            `json:"ignore_failure,omitempty"`
	NeedsApproval        bool                            `json:"needs_approval,omitempty"`
	Skip                 bool                            `json:"skip,omitempty"`
	DockerRegistriesAuth map[string]DockerRegistryAuth   `json:"docker_registries_auth"`
}

func (rct *RunConfigTask) DeepCopy() *RunConfigTask {
	nrct, err := copystructure.Copy(rct)
	if err != nil {
		panic(err)
	}
	return nrct.(*RunConfigTask)
}

type RunConfigTaskDependCondition string

const (
	RunConfigTaskDependConditionOnSuccess RunConfigTaskDependCondition = "on_success"
	RunConfigTaskDependConditionOnFailure RunConfigTaskDependCondition = "on_failure"
	RunConfigTaskDependConditionOnSkipped RunConfigTaskDependCondition = "on_skipped"
)

type RunConfigTaskDepend struct {
	TaskID     string                         `json:"task_id,omitempty"`
	Conditions []RunConfigTaskDependCondition `json:"conditions,omitempty"`
}

type RuntimeType string

const (
	RuntimeTypePod RuntimeType = "pod"
)

type DockerRegistryAuthType string

const (
	DockerRegistryAuthTypeBasic       DockerRegistryAuthType = "basic"
	DockerRegistryAuthTypeEncodedAuth DockerRegistryAuthType = "encodedauth"
)

type DockerRegistryAuth struct {
	Type DockerRegistryAuthType `json:"type"`

	// basic auth
	Username string `json:"username"`
	Password string `json:"password"`

	// encoded auth string
	Auth string `json:"auth"`

	// future auths like aws ecr auth
}

type Runtime struct {
	Type       RuntimeType  `json:"type,omitempty"`
	Arch       stypes.Arch  `json:"arch,omitempty"`
	Containers []*Container `json:"containers,omitempty"`
}

type Container struct {
	Image       string            `json:"image,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	User        string            `json:"user,omitempty"`
	Privileged  bool              `json:"privileged"`
	Entrypoint  string            `json:"entrypoint"`
	Volumes     []Volume          `json:"volumes"`
}

type Volume struct {
	Path string `json:"path"`

	TmpFS *VolumeTmpFS `json:"tmpfs"`
}

type VolumeTmpFS struct {
	Size int64 `json:"size"`
}

type Step interface{}

type Steps []Step

type BaseStep struct {
	Type string `json:"type,omitempty"`
	Name string `json:"name,omitempty"`
}

type RunStep struct {
	BaseStep
	Command     string            `json:"command,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	WorkingDir  string            `json:"working_dir,omitempty"`
	Shell       string            `json:"shell,omitempty"`
	Tty         *bool             `json:"tty,omitempty"`
}

type SaveContent struct {
	SourceDir string   `json:"source_dir,omitempty"`
	DestDir   string   `json:"dest_dir,omitempty"`
	Paths     []string `json:"paths,omitempty"`
}

type SaveToWorkspaceStep struct {
	BaseStep
	Contents []SaveContent `json:"contents,omitempty"`
}

type RestoreWorkspaceStep struct {
	BaseStep
	DestDir string `json:"dest_dir,omitempty"`
}

type SaveCacheStep struct {
	BaseStep
	Key      string        `json:"key,omitempty"`
	Contents []SaveContent `json:"contents,omitempty"`
}

type RestoreCacheStep struct {
	BaseStep
	Keys    []string `json:"keys,omitempty"`
	DestDir string   `json:"dest_dir,omitempty"`
}

func (et *Steps) UnmarshalJSON(b []byte) error {
	type rawSteps []json.RawMessage

	var rs rawSteps
	if err := json.Unmarshal(b, &rs); err != nil {
		return errors.WithStack(err)
	}

	steps := make(Steps, len(rs))
	for i, step := range rs {
		var bs BaseStep
		if err := json.Unmarshal(step, &bs); err != nil {
			return errors.WithStack(err)
		}
		switch bs.Type {
		case "run":
			var s RunStep
			if err := json.Unmarshal(step, &s); err != nil {
				return errors.WithStack(err)
			}
			if s.Tty == nil {
				s.Tty = util.BoolP(true)
			}
			steps[i] = &s
		case "save_to_workspace":
			var s SaveToWorkspaceStep
			if err := json.Unmarshal(step, &s); err != nil {
				return errors.WithStack(err)
			}
			steps[i] = &s
		case "restore_workspace":
			var s RestoreWorkspaceStep
			if err := json.Unmarshal(step, &s); err != nil {
				return errors.WithStack(err)
			}
			steps[i] = &s
		case "save_cache":
			var s SaveCacheStep
			if err := json.Unmarshal(step, &s); err != nil {
				return errors.WithStack(err)
			}
			steps[i] = &s
		case "restore_cache":
			var s RestoreCacheStep
			if err := json.Unmarshal(step, &s); err != nil {
				return errors.WithStack(err)
			}
			steps[i] = &s
		}
	}

	*et = steps

	return nil
}

func NewRunConfig() *RunConfig {
	return &RunConfig{
		TypeMeta: stypes.TypeMeta{
			Kind:    RunConfigKind,
			Version: RunConfigVersion,
		},
		ObjectMeta: stypes.ObjectMeta{
			ID: uuid.Must(uuid.NewV4()).String(),
		},
	}
}
