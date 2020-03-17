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

package config

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	itypes "agola.io/agola/internal/services/types"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/types"

	"github.com/ghodss/yaml"
	errors "golang.org/x/xerrors"
	"k8s.io/apimachinery/pkg/api/resource"
)

const (
	maxConfigSize     = 1024 * 1024 // 1MiB
	maxRunNameLength  = 100
	maxTaskNameLength = 100
	maxStepNameLength = 100

	defaultWorkingDir = "~/project"
)

type ConfigFormat int

const (
	// ConfigFormatJSON handles both json or yaml format (since json is a subset of yaml)
	ConfigFormatJSON ConfigFormat = iota
	ConfigFormatJsonnet
	ConfigFormatStarlark
)

var (
	regExpDelimiters = []string{"/", "#"}
)

type Config struct {
	Runs []*Run `json:"runs"`

	DockerRegistriesAuth map[string]*DockerRegistryAuth `json:"docker_registries_auth"`
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
	Username Value `json:"username"`
	Password Value `json:"password"`

	// encoded auth string
	Auth string `json:"auth"`

	// future auths like aws ecr auth
}

type Runtime struct {
	Type       RuntimeType  `json:"type,omitempty"`
	Arch       types.Arch   `json:"arch,omitempty"`
	Containers []*Container `json:"containers,omitempty"`
}

type Container struct {
	Image       string           `json:"image,omitempty"`
	Environment map[string]Value `json:"environment,omitempty"`
	User        string           `json:"user"`
	Privileged  bool             `json:"privileged"`
	Entrypoint  string           `json:"entrypoint"`
	Volumes     []Volume         `json:"volumes"`
}

type Volume struct {
	Path string `json:"path"`

	TmpFS *VolumeTmpFS `json:"tmpfs"`
}

type VolumeTmpFS struct {
	Size *resource.Quantity `json:"size"`
}

type Run struct {
	Name                 string                         `json:"name"`
	Tasks                []*Task                        `json:"tasks"`
	When                 *When                          `json:"when"`
	DockerRegistriesAuth map[string]*DockerRegistryAuth `json:"docker_registries_auth"`
}

type Task struct {
	Name                 string                         `json:"name"`
	Runtime              *Runtime                       `json:"runtime"`
	Environment          map[string]Value               `json:"environment,omitempty"`
	WorkingDir           string                         `json:"working_dir"`
	Shell                string                         `json:"shell"`
	User                 string                         `json:"user"`
	Steps                Steps                          `json:"steps"`
	Depends              Depends                        `json:"depends"`
	IgnoreFailure        bool                           `json:"ignore_failure"`
	Approval             bool                           `json:"approval"`
	When                 *When                          `json:"when"`
	DockerRegistriesAuth map[string]*DockerRegistryAuth `json:"docker_registries_auth"`
}

type DependCondition string

const (
	DependConditionOnSuccess DependCondition = "on_success"
	DependConditionOnFailure DependCondition = "on_failure"
	DependConditionOnSkipped DependCondition = "on_skipped"
)

type Depends []*Depend

type Depend struct {
	TaskName   string            `json:"task"`
	Conditions []DependCondition `json:"conditions"`
}

type Step interface{}

type Steps []Step

type BaseStep struct {
	Type string `json:"type"`
	Name string `json:"name"`
	When *When  `json:"when"`
}

type CloneStep struct {
	BaseStep          `json:",inline"`
	Depth             *int `json:"depth"`
	RecurseSubmodules bool `json:"recurse_submodules"`
}

type RunStep struct {
	BaseStep    `json:",inline"`
	Command     string           `json:"command"`
	Environment map[string]Value `json:"environment,omitempty"`
	WorkingDir  string           `json:"working_dir"`
	Shell       string           `json:"shell"`
	Tty         *bool            `json:"tty"`
}

type SaveToWorkspaceStep struct {
	BaseStep `json:",inline"`
	Contents []*SaveContent `json:"contents"`
}

type RestoreWorkspaceStep struct {
	BaseStep `json:",inline"`
	DestDir  string `json:"dest_dir"`
}

type SaveCacheStep struct {
	BaseStep `json:",inline"`
	Key      string         `json:"key"`
	Contents []*SaveContent `json:"contents"`
}

type RestoreCacheStep struct {
	BaseStep `json:",inline"`
	Keys     []string `json:"keys"`
	DestDir  string   `json:"dest_dir"`
}

type SaveContent struct {
	SourceDir string   `json:"source_dir"`
	DestDir   string   `json:"dest_dir"`
	Paths     []string `json:"paths"`
}

func (s *Steps) UnmarshalJSON(b []byte) error {
	var stepsRaw []json.RawMessage
	if err := json.Unmarshal(b, &stepsRaw); err != nil {
		return err
	}

	steps := make(Steps, len(stepsRaw))
	for i, stepRaw := range stepsRaw {
		var step interface{}

		var stepMap map[string]json.RawMessage
		if err := json.Unmarshal(stepRaw, &stepMap); err != nil {
			return err
		}
		// handle default step definition using format { type: "steptype", other steps fields }
		if _, ok := stepMap["type"]; ok {
			var stepTypeI interface{}
			if err := json.Unmarshal(stepMap["type"], &stepTypeI); err != nil {
				return err
			}
			stepType, ok := stepTypeI.(string)
			if !ok {
				return errors.Errorf("step type at index %d must be a string", i)
			}

			switch stepType {
			case "clone":
				var s CloneStep
				if err := json.Unmarshal(stepRaw, &s); err != nil {
					return err
				}
				s.Type = stepType
				step = &s

			case "run":
				var s RunStep
				if err := json.Unmarshal(stepRaw, &s); err != nil {
					return err
				}
				if s.Tty == nil {
					s.Tty = util.BoolP(true)
				}
				s.Type = stepType
				step = &s

			case "save_to_workspace":
				var s SaveToWorkspaceStep
				if err := json.Unmarshal(stepRaw, &s); err != nil {
					return err
				}
				s.Type = stepType
				step = &s

			case "restore_workspace":
				var s RestoreWorkspaceStep
				if err := json.Unmarshal(stepRaw, &s); err != nil {
					return err
				}
				s.Type = stepType
				step = &s

			case "save_cache":
				var s SaveCacheStep
				if err := json.Unmarshal(stepRaw, &s); err != nil {
					return err
				}
				s.Type = stepType
				step = &s

			case "restore_cache":
				var s RestoreCacheStep
				if err := json.Unmarshal(stepRaw, &s); err != nil {
					return err
				}
				s.Type = stepType
				step = &s
			default:
				return errors.Errorf("unknown step type: %s", stepType)
			}
		} else {
			// handle simpler (for yaml not for json) steps definition using format "steptype": { stepSpecification }
			if len(stepMap) > 1 {
				return errors.Errorf("wrong steps description at index %d: more than one step name per list entry", i)
			}
			for stepType, stepSpecRaw := range stepMap {
				var stepSpec interface{}
				if err := json.Unmarshal(stepSpecRaw, &stepSpec); err != nil {
					return err
				}

				switch stepType {
				case "clone":
					var s CloneStep
					if err := json.Unmarshal(stepSpecRaw, &s); err != nil {
						return err
					}
					s.Type = stepType
					step = &s

				case "run":
					var s RunStep
					switch stepSpec := stepSpec.(type) {
					case string:
						s.Command = stepSpec
					default:
						if err := json.Unmarshal(stepSpecRaw, &s); err != nil {
							return err
						}
					}
					s.Type = stepType
					step = &s

				case "save_to_workspace":
					var s SaveToWorkspaceStep
					if err := json.Unmarshal(stepSpecRaw, &s); err != nil {
						return err
					}
					s.Type = stepType
					step = &s

				case "restore_workspace":
					var s RestoreWorkspaceStep
					if err := json.Unmarshal(stepSpecRaw, &s); err != nil {
						return err
					}
					s.Type = stepType
					step = &s

				case "save_cache":
					var s SaveCacheStep
					if err := json.Unmarshal(stepSpecRaw, &s); err != nil {
						return err
					}
					s.Type = stepType
					step = &s

				case "restore_cache":
					var s RestoreCacheStep
					if err := json.Unmarshal(stepSpecRaw, &s); err != nil {
						return err
					}
					s.Type = stepType
					step = &s
				default:
					return errors.Errorf("unknown step type: %s", stepType)
				}
			}
		}

		steps[i] = step
	}

	*s = steps

	return nil
}

func (d *Depends) UnmarshalJSON(b []byte) error {
	var dependsRaw []json.RawMessage

	if err := json.Unmarshal(b, &dependsRaw); err != nil {
		return err
	}

	depends := make([]*Depend, len(dependsRaw))
	for i, dependRaw := range dependsRaw {
		var dependi interface{}
		if err := json.Unmarshal(dependRaw, &dependi); err != nil {
			return err
		}
		var depend *Depend
		isSimpler := false
		switch de := dependi.(type) {
		// handle simpler (for yaml) depends definition using format "taskname":
		case string:
			depend = &Depend{
				TaskName: dependi.(string),
			}
		case map[string]interface{}:
			if len(de) == 1 {
				for _, v := range de {
					switch v.(type) {
					case []interface{}:
						isSimpler = true
					case string:
					default:
						return errors.Errorf("unsupported depend entry format")
					}
				}
			}
			if !isSimpler {
				// handle default depends definition using format "task": "taskname", conditions: [ list of conditions ]
				if err := json.Unmarshal(dependRaw, &depend); err != nil {
					return err
				}
			} else {
				// handle simpler (for yaml) depends definition using format "taskname": [ list of conditions ]
				if len(de) != 1 {
					return errors.Errorf("unsupported depend entry format")
				}
				type deplist map[string][]DependCondition
				var dl deplist
				if err := json.Unmarshal(dependRaw, &dl); err != nil {
					return err
				}
				if len(dl) != 1 {
					return errors.Errorf("unsupported depend entry format")
				}
				for k, v := range dl {
					depend = &Depend{
						TaskName:   k,
						Conditions: v,
					}
				}
			}

		default:
			return errors.Errorf("unsupported depend entry format")
		}
		depends[i] = depend
	}

	*d = depends

	return nil
}

type ValueType int

const (
	ValueTypeString ValueType = iota
	ValueTypeFromVariable
)

type Value struct {
	Type  ValueType
	Value string
}

func (val *Value) UnmarshalJSON(b []byte) error {
	var ival interface{}
	if err := json.Unmarshal(b, &ival); err != nil {
		return err
	}
	switch valValue := ival.(type) {
	case string:
		val.Type = ValueTypeString
		val.Value = valValue
	case map[string]interface{}:
		for k, v := range valValue {
			if k == "from_variable" {
				switch v.(type) {
				case string:
				default:
					return errors.Errorf("unknown value format: %v", v)
				}
				val.Type = ValueTypeFromVariable
				val.Value = v.(string)
			}
		}
	default:
		return errors.Errorf("unknown value format: %v", ival)
	}
	return nil
}

type When types.When

type when struct {
	Branch interface{} `json:"branch"`
	Tag    interface{} `json:"tag"`
	Ref    interface{} `json:"ref"`
}

func (w *When) ToWhen() *types.When {
	return (*types.When)(w)
}

func (w *When) UnmarshalJSON(b []byte) error {
	var wi *when
	if err := json.Unmarshal(b, &wi); err != nil {
		return err
	}

	var err error

	if wi.Branch != nil {
		w.Branch, err = parseWhenConditions(wi.Branch)
		if err != nil {
			return err
		}
	}

	if wi.Tag != nil {
		w.Tag, err = parseWhenConditions(wi.Tag)
		if err != nil {
			return err
		}
	}

	if wi.Ref != nil {
		w.Ref, err = parseWhenConditions(wi.Ref)
		if err != nil {
			return err
		}
	}

	return nil
}

func parseWhenConditions(wi interface{}) (*types.WhenConditions, error) {
	w := &types.WhenConditions{}

	var err error
	include := []string{}
	exclude := []string{}

	switch c := wi.(type) {
	case string:
		include = []string{c}
	case []interface{}:
		ss, err := parseSliceString(c)
		if err != nil {
			return nil, err
		}
		include = ss
	case map[string]interface{}:
		for k, v := range c {
			switch k {
			case "include":
				include, err = parseStringOrSlice(v)
				if err != nil {
					return nil, err
				}
			case "exclude":
				exclude, err = parseStringOrSlice(v)
				if err != nil {
					return nil, err
				}
			default:
				return nil, errors.Errorf(`expected one of "include" or "exclude", got %s`, k)
			}
		}
	default:
		return nil, errors.Errorf("wrong when format")
	}

	w.Include, err = parseWhenConditionSlice(include)
	if err != nil {
		return nil, err
	}
	w.Exclude, err = parseWhenConditionSlice(exclude)
	if err != nil {
		return nil, err
	}

	return w, nil
}

func parseWhenConditionSlice(conds []string) ([]types.WhenCondition, error) {
	if len(conds) == 0 {
		return nil, nil
	}

	wcs := []types.WhenCondition{}
	for _, cond := range conds {
		wc, err := parseWhenCondition(cond)
		if err != nil {
			return nil, err
		}
		wcs = append(wcs, *wc)
	}

	return wcs, nil
}

func parseWhenCondition(s string) (*types.WhenCondition, error) {
	isRegExp := false
	if len(s) > 2 {
		for _, d := range regExpDelimiters {
			if strings.HasPrefix(s, d) && strings.HasSuffix(s, d) {
				isRegExp = true
				s = s[1 : len(s)-1]
				break
			}
		}
	}

	wc := &types.WhenCondition{Match: s}

	if isRegExp {
		if _, err := regexp.Compile(s); err != nil {
			return nil, errors.Errorf("wrong regular expression: %w", err)
		}
		wc.Type = types.WhenConditionTypeRegExp
	} else {
		wc.Type = types.WhenConditionTypeSimple
	}
	return wc, nil
}

func parseStringOrSlice(si interface{}) ([]string, error) {
	ss := []string{}
	switch c := si.(type) {
	case string:
		ss = []string{c}
	case []interface{}:
		var err error
		ss, err = parseSliceString(c)
		if err != nil {
			return nil, err
		}
	}
	return ss, nil
}

func parseSliceString(si []interface{}) ([]string, error) {
	ss := []string{}
	for _, v := range si {
		switch s := v.(type) {
		case string:
			ss = append(ss, s)
		default:
			return nil, errors.Errorf("expected string")
		}
	}
	return ss, nil
}

func (c *Config) Run(runName string) *Run {
	for _, r := range c.Runs {
		if r.Name == runName {
			return r
		}
	}
	panic(fmt.Sprintf("run %q doesn't exists", runName))
}

func (r *Run) Task(taskName string) *Task {
	for _, t := range r.Tasks {
		if t.Name == taskName {
			return t
		}
	}
	panic(fmt.Sprintf("task %q for run %q doesn't exists", taskName, r.Name))
}

var DefaultConfig = Config{}

// ConfigContext is the context to pass to the config generator. Fields are not marked as omitempty since
// we want to provide all of them with empty value if not existing in such context
// (i.e. pull_request_id will be an empty string when not a pull request)
type ConfigContext struct {
	RefType       itypes.RunRefType `json:"ref_type"`
	Ref           string            `json:"ref"`
	Branch        string            `json:"branch"`
	Tag           string            `json:"tag"`
	PullRequestID string            `json:"pull_request_id"`
	CommitSHA     string            `json:"commit_sha"`
}

func ParseConfig(configData []byte, format ConfigFormat, configContext *ConfigContext) (*Config, error) {
	// TODO(sgotti) execute jsonnet and starlark executor in a
	// separate process to avoid issues with malformat config that
	// could lead to infinite executions and memory exhaustion
	switch format {
	case ConfigFormatJsonnet:
		// Generate json from jsonnet
		var err error
		configData, err = execJsonnet(configData, configContext)
		if err != nil {
			return nil, errors.Errorf("failed to execute jsonnet: %w", err)
		}
	case ConfigFormatStarlark:
		// Generate json from starlark
		var err error
		configData, err = execStarlark(configData, configContext)
		if err != nil {
			return nil, errors.Errorf("failed to execute starlark: %w", err)
		}
	}

	if len(configData) > maxConfigSize {
		return nil, errors.Errorf("config size is greater than allowed max config size: %d > %d", len(configData), maxConfigSize)
	}

	config := DefaultConfig
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return nil, errors.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, checkConfig(&config)
}

func checkConfig(config *Config) error {
	if len(config.Runs) == 0 {
		return errors.Errorf("no runs defined")
	}

	seenRuns := map[string]struct{}{}
	for ri, run := range config.Runs {
		if run == nil {
			return errors.Errorf("run at index %d is empty", ri)
		}

		if run.Name == "" {
			return errors.Errorf("run at index %d has empty name", ri)
		}

		if len(run.Name) > maxRunNameLength {
			return errors.Errorf("run name %q too long", run.Name)
		}

		if _, ok := seenRuns[run.Name]; ok {
			return errors.Errorf("duplicate run name: %s", run.Name)
		}
		seenRuns[run.Name] = struct{}{}

		seenTasks := map[string]struct{}{}
		for ti, task := range run.Tasks {
			if task == nil {
				return errors.Errorf("run %q: task at index %d is empty", run.Name, ti)
			}

			if task.Name == "" {
				return errors.Errorf("run %q: task at index %d has empty name", run.Name, ti)
			}

			if len(task.Name) > maxTaskNameLength {
				return errors.Errorf("task name %q too long", task.Name)
			}

			if _, ok := seenTasks[task.Name]; ok {
				return errors.Errorf("duplicate task name: %s", task.Name)
			}
			seenTasks[task.Name] = struct{}{}

			// check tasks runtime
			if task.Runtime == nil {
				return errors.Errorf("task %q: runtime is not defined", task.Name)
			}

			r := task.Runtime
			if r.Type != "" {
				if r.Type != RuntimeTypePod {
					return errors.Errorf("task %q runtime: wrong type %q", task.Name, r.Type)
				}
			}
			if len(r.Containers) == 0 {
				return errors.Errorf("task %q runtime: at least one container must be defined", task.Name)
			}
			if r.Arch != "" {
				if !types.IsValidArch(r.Arch) {
					return errors.Errorf("task %q runtime: invalid arch %q", task.Name, r.Arch)
				}
			}

			for _, container := range r.Containers {
				for _, vol := range container.Volumes {
					if vol.TmpFS == nil {
						return errors.Errorf("no volume config specified")
					}
				}
			}
		}
	}

	// check broken dependencies
	for _, run := range config.Runs {
		// collect all task names
		allTasks := map[string]struct{}{}
		for _, task := range run.Tasks {
			allTasks[task.Name] = struct{}{}
		}

		for _, task := range run.Tasks {
			for _, dep := range task.Depends {
				if _, ok := allTasks[dep.TaskName]; !ok {
					return errors.Errorf("run task %q needed by task %q doesn't exist", dep.TaskName, task.Name)
				}
			}
		}
	}

	// check circular dependencies
	for _, run := range config.Runs {
		cerrs := &util.Errors{}
		for _, task := range run.Tasks {
			allParents := getAllTaskParents(run, task)
			for _, parent := range allParents {
				if parent.Name == task.Name {
					// TODO(sgotti) get the parent that depends on task to report it
					dep := []string{}
					for _, parent := range allParents {
						pparents := getTaskParents(run, parent)
						for _, pparent := range pparents {
							if pparent.Name == task.Name {
								dep = append(dep, fmt.Sprintf("%q", parent.Name))
							}
						}
					}
					cerrs.Append(errors.Errorf("circular dependency between task %q and tasks %s", task.Name, strings.Join(dep, " ")))
				}
			}
		}
		if cerrs.IsErr() {
			return cerrs
		}
	}

	// check that the task and its parent don't have a common dependency
	for _, run := range config.Runs {
		for _, task := range run.Tasks {
			parents := getTaskParents(run, task)
			for _, parent := range parents {
				allParentParents := getAllTaskParents(run, parent)
				for _, p := range parents {
					for _, pp := range allParentParents {
						if p.Name == pp.Name {
							return errors.Errorf("task %q and its dependency %q have both a dependency on task %q", task.Name, parent.Name, p.Name)
						}
					}
				}
			}
		}
	}

	// check duplicate task dependencies
	for _, run := range config.Runs {
		for _, task := range run.Tasks {
			// check duplicate dependencies in task
			seenDependencies := map[string]struct{}{}
			for _, dep := range task.Depends {
				if _, ok := seenDependencies[dep.TaskName]; ok {
					return errors.Errorf("duplicate task dependency: %s", task.Name)
				}
				seenDependencies[dep.TaskName] = struct{}{}
			}
		}
	}

	for _, run := range config.Runs {
		for _, task := range run.Tasks {
			for i, s := range task.Steps {
				switch step := s.(type) {
				// TODO(sgotti) we could use the run step command as step name but when the
				// command is very long or multi line it doesn't makes sense and will
				// probably be quite unuseful/confusing from an UI point of view
				case *CloneStep:
					if step.Depth != nil && *step.Depth < 1 {
						return errors.Errorf("depth value must be greater than 0 for clone step in task %q", task.Name)
					}
				case *RunStep:
					if step.Command == "" {
						return errors.Errorf("no command defined for step %d (run) in task %q", i, task.Name)
					}

				case *SaveCacheStep:
					if step.Key == "" {
						return errors.Errorf("no key defined for step %d (save_cache) in task %q", i, task.Name)
					}

				case *RestoreCacheStep:
					if len(step.Keys) == 0 {
						return errors.Errorf("no keys defined for step %d (restore_cache) in task %q", i, task.Name)
					}
				}
			}
		}
	}

	// Set defaults
	for _, registryAuth := range config.DockerRegistriesAuth {
		if registryAuth.Type == "" {
			registryAuth.Type = DockerRegistryAuthTypeBasic
		}
	}

	for _, run := range config.Runs {
		// set auth type to basic if not specified
		for _, registryAuth := range run.DockerRegistriesAuth {
			if registryAuth.Type == "" {
				registryAuth.Type = DockerRegistryAuthTypeBasic
			}
		}
		for _, task := range run.Tasks {
			// set auth type to basic if not specified
			for _, registryAuth := range task.DockerRegistriesAuth {
				if registryAuth.Type == "" {
					registryAuth.Type = DockerRegistryAuthTypeBasic
				}
			}

			// set task default working dir
			if task.WorkingDir == "" {
				task.WorkingDir = defaultWorkingDir
			}

			// set task runtime type to pod if empty
			r := task.Runtime
			if r.Type == "" {
				r.Type = RuntimeTypePod
			}

			// set steps defaults
			for i, s := range task.Steps {
				switch step := s.(type) {
				// TODO(sgotti) we could use the run step command as step name but when the
				// command is very long or multi line it doesn't makes sense and will
				// probably be quite unuseful/confusing from an UI point of view
				case *RunStep:
					if step.Name == "" {
						lines, err := util.CountLines(step.Command)
						// if we failed to count the lines (shouldn't happen) or the number of lines is > 1 then a name is requred
						if err != nil || lines > 1 {
							return errors.Errorf("missing step name for step %d (run) in task %q, required since command is more than one line", i, task.Name)
						}
						len := len(step.Command)
						if len > maxStepNameLength {
							len = maxStepNameLength
						}
						step.Name = step.Command[:len]
					}
					// if tty is omitted its default is true
					if step.Tty == nil {
						step.Tty = util.BoolP(true)
					}
				case *SaveCacheStep:
					for _, content := range step.Contents {
						if len(content.Paths) == 0 {
							// default to all files inside the sourceDir
							content.Paths = []string{"**"}
						}
					}
				}
			}
		}
	}

	return nil
}

// getTaskParents returns direct parents of task.
func getTaskParents(run *Run, task *Task) []*Task {
	parents := []*Task{}
	for _, el := range run.Tasks {
		isParent := false
		for _, d := range task.Depends {
			if d.TaskName == el.Name {
				isParent = true
			}
		}
		if isParent {
			parents = append(parents, el)
		}
	}
	return parents
}

// getAllTaskParents returns all the parents (both direct and ancestors) of a task.
// In case of circular dependency it won't loop forever but will also return
// the task as parent of itself
func getAllTaskParents(run *Run, task *Task) []*Task {
	pMap := map[string]*Task{}
	nextParents := getTaskParents(run, task)

	for len(nextParents) > 0 {
		parents := nextParents
		nextParents = []*Task{}
		for _, parent := range parents {
			if _, ok := pMap[parent.Name]; ok {
				continue
			}
			pMap[parent.Name] = parent
			nextParents = append(nextParents, getTaskParents(run, parent)...)
		}
	}

	parents := make([]*Task, 0, len(pMap))
	for _, v := range pMap {
		parents = append(parents, v)
	}
	return parents
}
