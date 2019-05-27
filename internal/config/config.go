// This file is part of Agola
//
// Copyright (C) 2019 Sorint.lab
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package config

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/sorintlab/agola/internal/common"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/ghodss/yaml"
	"github.com/google/go-jsonnet"
	"github.com/pkg/errors"
)

const (
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
)

var (
	regExpDelimiters = []string{"/", "#"}
)

type Config struct {
	Runs []*Run `json:"runs"`
}

type RuntimeType string

const (
	RuntimeTypePod RuntimeType = "pod"
)

type RegistryAuthType string

const (
	RegistryAuthTypeDefault RegistryAuthType = "default"
)

type RegistryAuth struct {
	Type RegistryAuthType `json:"type"`

	// default auth
	Username Value `json:"username"`
	Password Value `json:"password"`
}

type Runtime struct {
	Type       RuntimeType   `json:"type,omitempty"`
	Auth       *RegistryAuth `json:"auth"`
	Arch       common.Arch   `json:"arch,omitempty"`
	Containers []*Container  `json:"containers,omitempty"`
}

type Container struct {
	Image       string           `json:"image,omitempty"`
	Auth        *RegistryAuth    `json:"auth"`
	Environment map[string]Value `json:"environment,omitempty"`
	User        string           `json:"user"`
	Privileged  bool             `json:"privileged"`
	Entrypoint  string           `json:"entrypoint"`
}

type Run struct {
	Name  string  `json:"name"`
	Tasks []*Task `json:"tasks"`
}

type Task struct {
	Name          string           `json:"name"`
	Runtime       *Runtime         `json:"runtime"`
	Environment   map[string]Value `json:"environment,omitempty"`
	WorkingDir    string           `json:"working_dir"`
	Shell         string           `json:"shell"`
	User          string           `json:"user"`
	Steps         []interface{}    `json:"steps"`
	Depends       []*Depend        `json:"depends"`
	IgnoreFailure bool             `json:"ignore_failure"`
	Approval      bool             `json:"approval"`
	When          *types.When      `json:"when"`
}

type DependCondition string

const (
	DependConditionOnSuccess DependCondition = "on_success"
	DependConditionOnFailure DependCondition = "on_failure"
	DependConditionOnSkipped DependCondition = "on_skipped"
)

type Depend struct {
	TaskName   string            `json:"task"`
	Conditions []DependCondition `json:"conditions"`
}

type Step struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type CloneStep struct {
	Step `json:",inline"`
}

type RunStep struct {
	Step        `json:",inline"`
	Command     string           `json:"command"`
	Environment map[string]Value `json:"environment,omitempty"`
	WorkingDir  string           `json:"working_dir"`
	Shell       string           `json:"shell"`
	User        string           `json:"user"`
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

type SaveContent struct {
	SourceDir string   `json:"source_dir"`
	DestDir   string   `json:"dest_dir"`
	Paths     []string `json:"paths"`
}

type SaveToWorkspaceStep struct {
	Step     `json:",inline"`
	Contents []*SaveContent `json:"contents"`
}

type RestoreWorkspaceStep struct {
	Step    `json:",inline"`
	DestDir string `json:"dest_dir"`
}

type SaveCacheStep struct {
	Step     `json:",inline"`
	Key      string         `json:"key"`
	Contents []*SaveContent `json:"contents"`
}

type RestoreCacheStep struct {
	Step    `json:",inline"`
	Keys    []string `json:"keys"`
	DestDir string   `json:"dest_dir"`
}

func (t *Task) UnmarshalJSON(b []byte) error {
	type when struct {
		Branch interface{} `json:"branch"`
		Tag    interface{} `json:"tag"`
		Ref    interface{} `json:"ref"`
	}

	type runtask struct {
		Name          string                   `json:"name"`
		Runtime       *Runtime                 `json:"runtime"`
		Environment   map[string]Value         `json:"environment,omitempty"`
		WorkingDir    string                   `json:"working_dir"`
		Shell         string                   `json:"shell"`
		User          string                   `json:"user"`
		Steps         []map[string]interface{} `json:"steps"`
		Depends       []interface{}            `json:"depends"`
		IgnoreFailure bool                     `json:"ignore_failure"`
		Approval      bool                     `json:"approval"`
		When          *when                    `json:"when"`
	}

	var tr *runtask

	if err := json.Unmarshal(b, &tr); err != nil {
		return err
	}

	t.Name = tr.Name
	t.Runtime = tr.Runtime
	t.Environment = tr.Environment
	t.WorkingDir = tr.WorkingDir
	t.Shell = tr.Shell
	t.User = tr.User
	t.IgnoreFailure = tr.IgnoreFailure
	t.Approval = tr.Approval

	steps := make([]interface{}, len(tr.Steps))
	for i, stepEntry := range tr.Steps {
		if _, ok := stepEntry["type"]; ok {
			// handle default step definition using format { type: "steptype", other steps fields }
			stepType, ok := stepEntry["type"].(string)
			if !ok {
				return errors.Errorf("step type at index %d must be a string", i)
			}
			o, err := json.Marshal(stepEntry)
			if err != nil {
				return err
			}
			switch stepType {
			case "clone":
				var s CloneStep
				s.Type = stepType
				steps[i] = &s

			case "run":
				var s RunStep
				if err := json.Unmarshal(o, &s); err != nil {
					return err
				}
				s.Type = stepType
				steps[i] = &s

			case "save_to_workspace":
				var s SaveToWorkspaceStep
				if err := json.Unmarshal(o, &s); err != nil {
					return err
				}
				s.Type = stepType
				steps[i] = &s

			case "restore_workspace":
				var s RestoreWorkspaceStep
				if err := json.Unmarshal(o, &s); err != nil {
					return err
				}
				s.Type = stepType
				steps[i] = &s

			case "save_cache":
				var s SaveCacheStep
				if err := json.Unmarshal(o, &s); err != nil {
					return err
				}
				s.Type = stepType
				steps[i] = &s

			case "restore_cache":
				var s RestoreCacheStep
				if err := json.Unmarshal(o, &s); err != nil {
					return err
				}
				s.Type = stepType
				steps[i] = &s
			default:
				return errors.Errorf("unknown step type: %s", stepType)
			}
		} else {
			// handle simpler (for yaml not for json) steps definition using format "steptype": { stepSpecification }
			if len(stepEntry) > 1 {
				return errors.Errorf("wrong steps description at index %d: more than one step name per list entry", i)
			}
			for stepType, stepSpec := range stepEntry {
				o, err := json.Marshal(stepSpec)
				if err != nil {
					return err
				}
				switch stepType {
				case "clone":
					var s CloneStep
					s.Type = stepType
					steps[i] = &s

				case "run":
					var s RunStep
					switch stepSpec.(type) {
					case string:
						s.Command = stepSpec.(string)
					default:
						if err := json.Unmarshal(o, &s); err != nil {
							return err
						}
					}
					s.Type = stepType
					steps[i] = &s

				case "save_to_workspace":
					var s SaveToWorkspaceStep
					if err := json.Unmarshal(o, &s); err != nil {
						return err
					}
					s.Type = stepType
					steps[i] = &s

				case "restore_workspace":
					var s RestoreWorkspaceStep
					if err := json.Unmarshal(o, &s); err != nil {
						return err
					}
					s.Type = stepType
					steps[i] = &s

				case "save_cache":
					var s SaveCacheStep
					if err := json.Unmarshal(o, &s); err != nil {
						return err
					}
					s.Type = stepType
					steps[i] = &s

				case "restore_cache":
					var s RestoreCacheStep
					if err := json.Unmarshal(o, &s); err != nil {
						return err
					}
					s.Type = stepType
					steps[i] = &s
				default:
					return errors.Errorf("unknown step type: %s", stepType)
				}
			}
		}
	}

	t.Steps = steps

	depends := make([]*Depend, len(tr.Depends))
	for i, dependEntry := range tr.Depends {
		var depend *Depend
		isSimpler := false
		switch de := dependEntry.(type) {
		// handle simpler (for yaml) depends definition using format "taskname":
		case string:
			depend = &Depend{
				TaskName: dependEntry.(string),
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
				o, err := json.Marshal(dependEntry)
				if err != nil {
					return err
				}
				if err := json.Unmarshal(o, &depend); err != nil {
					return err
				}
			} else {
				// handle simpler (for yaml) depends definition using format "taskname": [ list of conditions ]
				if len(de) != 1 {
					return errors.Errorf("unsupported depend entry format")
				}
				type deplist map[string][]DependCondition
				var dl deplist
				o, err := json.Marshal(dependEntry)
				if err != nil {
					return err
				}
				if err := json.Unmarshal(o, &dl); err != nil {
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

	t.Depends = depends

	if tr.When != nil {
		w := &types.When{}

		var err error

		if tr.When.Branch != nil {
			w.Branch, err = parseWhenConditions(tr.When.Branch)
			if err != nil {
				return err
			}
		}

		if tr.When.Tag != nil {
			w.Tag, err = parseWhenConditions(tr.When.Tag)
			if err != nil {
				return err
			}
		}

		if tr.When.Ref != nil {
			w.Ref, err = parseWhenConditions(tr.When.Ref)
			if err != nil {
				return err
			}
		}

		t.When = w
	}

	return nil
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
	wc := &types.WhenCondition{Match: s}

	if isRegExp(s) {
		if _, err := regexp.Compile(s); err != nil {
			return nil, errors.Wrapf(err, "wrong regular expression")
		}
		wc.Type = types.WhenConditionTypeRegExp
	} else {
		wc.Type = types.WhenConditionTypeSimple
	}
	return wc, nil
}

func isRegExp(s string) bool {
	for _, d := range regExpDelimiters {
		if strings.HasPrefix(s, d) && strings.HasSuffix(s, d) {
			return true
		}
	}
	return false
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

func ParseConfig(configData []byte, format ConfigFormat) (*Config, error) {
	// Generate json from jsonnet
	if format == ConfigFormatJsonnet {
		// TODO(sgotti) support custom import files inside the configdir ???
		vm := jsonnet.MakeVM()
		out, err := vm.EvaluateSnippet("", string(configData))
		if err != nil {
			return nil, errors.Wrapf(err, "failed to evaluate jsonnet config")
		}
		configData = []byte(out)
	}

	config := DefaultConfig
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal config")
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
			if r.Type != RuntimeTypePod {
				return errors.Errorf("task %q runtime: wrong type %q", task.Name, r.Type)
			}
			if len(r.Containers) == 0 {
				return errors.Errorf("task %q runtime: at least one container must be defined", task.Name)
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
				allParents := getAllTaskParents(run, task)
				allParentParents := getAllTaskParents(run, parent)
				for _, p := range allParents {
					for _, pp := range allParentParents {
						if p.Name == pp.Name {
							return errors.Errorf("task %s and its dependency %s have both a dependency on task %s", task.Name, parent.Name, p.Name)
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

	// Set defaults
	for _, run := range config.Runs {
		for _, task := range run.Tasks {
			// set task default working dir
			if task.WorkingDir == "" {
				task.WorkingDir = defaultWorkingDir
			}

			// set auth type to default if not specified
			runtime := task.Runtime
			if runtime.Auth != nil {
				if runtime.Auth.Type == "" {
					runtime.Auth.Type = RegistryAuthTypeDefault
				}
			}
			for _, container := range runtime.Containers {
				if container.Auth != nil {
					if container.Auth.Type == "" {
						container.Auth.Type = RegistryAuthTypeDefault
					}
				}
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
