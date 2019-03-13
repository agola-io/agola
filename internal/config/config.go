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
	"fmt"
	"regexp"
	"strings"

	"github.com/sorintlab/agola/internal/common"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v2"
)

const (
	maxPipelineNameLength = 100
	maxTaskNameLength     = 100
	maxStepNameLength     = 100
)

var (
	regExpDelimiters = []string{"/", "#"}
)

type Config struct {
	Runtimes  map[string]*Runtime  `yaml:"runtimes"`
	Tasks     map[string]*Task     `yaml:"tasks"`
	Pipelines map[string]*Pipeline `yaml:"pipelines"`
}

type Task struct {
	Name        string            `yaml:"name"`
	Runtime     string            `yaml:"runtime"`
	Environment map[string]string `yaml:"environment"`
	WorkingDir  string            `yaml:"working_dir"`
	Shell       string            `yaml:"shell"`
	User        string            `yaml:"user"`
	Steps       []interface{}     `yaml:"steps"`
}

type RuntimeType string

const (
	RuntimeTypePod RuntimeType = "pod"
)

type Runtime struct {
	Name       string       `yaml:"name"`
	Type       RuntimeType  `yaml:"type,omitempty"`
	Arch       common.Arch  `yaml:"arch,omitempty"`
	Containers []*Container `yaml:"containers,omitempty"`
}

type Container struct {
	Image       string            `yaml:"image,omitempty"`
	Environment map[string]string `yaml:"environment,omitempty"`
	User        string            `yaml:"user"`
	Privileged  bool              `yaml:"privileged"`
}

type Pipeline struct {
	Name     string              `yaml:"name"`
	Elements map[string]*Element `yaml:"elements"`
}

type Element struct {
	Name          string      `yaml:"name"`
	Task          string      `yaml:"task"`
	Depends       []*Depend   `yaml:"depends"`
	IgnoreFailure bool        `yaml:"ignore_failure"`
	Approval      bool        `yaml:"approval"`
	When          *types.When `yaml:"when"`
}

type DependCondition string

const (
	DependConditionOnSuccess DependCondition = "on_success"
	DependConditionOnFailure DependCondition = "on_failure"
)

type Depend struct {
	ElementName string            `yaml:"name"`
	Conditions  []DependCondition `yaml:"conditions"`
}

type Step struct {
	Type string `yaml:"type"`
	Name string `yaml:"name"`
}

type CloneStep struct {
	Step `yaml:",inline"`
}

type RunStep struct {
	Step        `yaml:",inline"`
	Command     string            `yaml:"command"`
	Environment map[string]string `yaml:"environment,omitempty"`
	WorkingDir  string            `yaml:"working_dir"`
	Shell       string            `yaml:"shell"`
	User        string            `yaml:"user"`
}

type SaveToWorkspaceContent struct {
	SourceDir string   `yaml:"source_dir"`
	DestDir   string   `yaml:"dest_dir"`
	Paths     []string `yaml:"paths"`
}

type SaveToWorkspaceStep struct {
	Step     `yaml:",inline"`
	Contents []SaveToWorkspaceContent
}

type RestoreWorkspaceStep struct {
	Step    `yaml:",inline"`
	DestDir string `yaml:"dest_dir"`
}

func (t *Task) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type task Task
	type tasksteps struct {
		Steps []map[string]interface{} `yaml:"steps"`
	}
	tt := (*task)(t)
	if err := unmarshal(&tt); err != nil {
		return err
	}

	var st tasksteps
	if err := unmarshal(&st); err != nil {
		return err
	}

	steps := make([]interface{}, len(tt.Steps))
	for i, stepEntry := range st.Steps {
		if len(stepEntry) > 1 {
			return errors.Errorf("wrong steps description at index %d: more than one step name per list entry", i)
		}
		for stepType, stepSpec := range stepEntry {
			o, err := yaml.Marshal(stepSpec)
			if err != nil {
				return err
			}
			switch stepType {
			case "clone":
				var cs CloneStep
				cs.Type = stepType
				steps[i] = &cs

			case "run":
				var rs RunStep
				rs.Type = stepType
				switch stepSpec.(type) {
				case string:
					rs.Command = stepSpec.(string)
				default:
					if err := yaml.Unmarshal(o, &rs); err != nil {
						return err
					}
				}
				steps[i] = &rs

			case "save_to_workspace":
				var sws SaveToWorkspaceStep
				sws.Type = stepType
				if err := yaml.Unmarshal(o, &sws); err != nil {
					return err
				}
				steps[i] = &sws

			case "restore_workspace":
				var rws RestoreWorkspaceStep
				rws.Type = stepType
				if err := yaml.Unmarshal(o, &rws); err != nil {
					return err
				}
				steps[i] = &rws
			default:
				return errors.Errorf("unknown step type: %s", stepType)
			}
		}
	}

	t.Steps = steps

	return nil
}

func (e *Element) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type when struct {
		Branch interface{} `yaml:"branch"`
		Tag    interface{} `yaml:"tag"`
		Ref    interface{} `yaml:"ref"`
	}

	type element struct {
		Name          string        `yaml:"name"`
		Task          string        `yaml:"task"`
		Depends       []interface{} `yaml:"depends"`
		IgnoreFailure bool          `yaml:"ignore_failure"`
		When          *when         `yaml:"when"`
	}

	var te *element

	if err := unmarshal(&te); err != nil {
		return err
	}

	e.Name = te.Name
	e.Task = te.Task
	e.IgnoreFailure = te.IgnoreFailure

	depends := make([]*Depend, len(te.Depends))
	for i, dependEntry := range te.Depends {
		var depend *Depend
		switch dependEntry.(type) {
		case string:
			depend = &Depend{
				ElementName: dependEntry.(string),
			}
		case map[interface{}]interface{}:
			type deplist map[string][]DependCondition
			var dl deplist
			o, err := yaml.Marshal(dependEntry)
			if err != nil {
				return err
			}
			if err := yaml.Unmarshal(o, &dl); err != nil {
				return err
			}
			if len(dl) != 1 {
				return errors.Errorf("unsupported depend format. Must be a string or a list")
			}
			for k, v := range dl {
				depend = &Depend{
					ElementName: k,
					Conditions:  v,
				}
			}

		default:
			return errors.Errorf("unsupported depend format. Must be a string or a list")
		}
		depends[i] = depend
	}

	e.Depends = depends

	if te.When != nil {
		w := &types.When{}

		var err error

		if te.When.Branch != nil {
			w.Branch, err = parseWhenConditions(te.When.Branch)
			if err != nil {
				return err
			}
		}

		if te.When.Tag != nil {
			w.Tag, err = parseWhenConditions(te.When.Tag)
			if err != nil {
				return err
			}
		}

		if te.When.Ref != nil {
			w.Ref, err = parseWhenConditions(te.When.Ref)
			if err != nil {
				return err
			}
		}

		e.When = w
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
	case map[interface{}]interface{}:
		for k, v := range c {
			ks, ok := k.(string)
			if !ok {
				return nil, errors.Errorf(`expected one of "include" or "exclude", got %s`, ks)
			}
			switch ks {
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
				return nil, errors.Errorf(`expected one of "include" or "exclude", got %s`, ks)
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
			return nil, errors.Wrapf(err, "wrong regular expression")
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

func (c *Config) Runtime(runtimeName string) *Runtime {
	for n, r := range c.Runtimes {
		if n == runtimeName {
			return r
		}
	}
	panic(fmt.Sprintf("runtime %q doesn't exists", runtimeName))
}

func (c *Config) Task(taskName string) *Task {
	for n, t := range c.Tasks {
		if n == taskName {
			return t
		}
	}
	panic(fmt.Sprintf("task %q doesn't exists", taskName))
}

func (c *Config) Pipeline(pipelineName string) *Pipeline {
	for n, p := range c.Pipelines {
		if n == pipelineName {
			return p
		}
	}
	panic(fmt.Sprintf("pipeline %q doesn't exists", pipelineName))
}

var DefaultConfig = Config{}

func ParseConfig(configData []byte) (*Config, error) {
	config := DefaultConfig
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return nil, err
	}

	if len(config.Pipelines) == 0 {
		return nil, errors.Errorf("no pipelines defined")
	}

	// Set names from maps keys
	for n, runtime := range config.Runtimes {
		if runtime == nil {
			return nil, errors.Errorf("runtime %q is empty", n)
		}
		runtime.Name = n
	}

	for n, task := range config.Tasks {
		if task == nil {
			return nil, errors.Errorf("task %q is empty", n)
		}
		task.Name = n
	}

	for n, pipeline := range config.Pipelines {
		if pipeline == nil {
			return nil, errors.Errorf("pipeline %q is empty", n)
		}
		pipeline.Name = n
	}

	for _, pipeline := range config.Pipelines {
		for n, element := range pipeline.Elements {
			if element == nil {
				return nil, errors.Errorf("pipeline %q: element %q is empty", pipeline.Name, n)
			}
			element.Name = n
		}
	}

	return &config, checkConfig(&config)
}

func checkConfig(config *Config) error {
	// check broken dependencies
	for _, pipeline := range config.Pipelines {
		// collect all task names
		allElements := map[string]struct{}{}
		for _, element := range pipeline.Elements {
			allElements[element.Name] = struct{}{}
		}

		for _, element := range pipeline.Elements {
			for _, dep := range element.Depends {
				if _, ok := allElements[dep.ElementName]; !ok {
					return errors.Errorf("pipeline element %q needed by element %q doesn't exist", dep.ElementName, element.Name)
				}
			}
		}
	}

	// check circular dependencies
	for _, pipeline := range config.Pipelines {
		cerrs := &util.Errors{}
		for _, element := range pipeline.Elements {
			allParents := getAllElementParents(pipeline, element)
			for _, parent := range allParents {
				if parent.Name == element.Name {
					// TODO(sgotti) get the parent that depends on task to report it
					dep := []string{}
					for _, parent := range allParents {
						pparents := getElementParents(pipeline, parent)
						for _, pparent := range pparents {
							if pparent.Name == element.Name {
								dep = append(dep, fmt.Sprintf("%q", parent.Name))
							}
						}
					}
					cerrs.Append(errors.Errorf("circular dependency between element %q and elements %s", element.Name, strings.Join(dep, " ")))
				}
			}
		}
		if cerrs.IsErr() {
			return cerrs
		}
	}

	// check that the task and its parent don't have a common dependency
	for _, pipeline := range config.Pipelines {
		for _, element := range pipeline.Elements {
			parents := getElementParents(pipeline, element)
			for _, parent := range parents {
				allParents := getAllElementParents(pipeline, element)
				allParentParents := getAllElementParents(pipeline, parent)
				for _, p := range allParents {
					for _, pp := range allParentParents {
						if p.Name == pp.Name {
							return errors.Errorf("element %s and its dependency %s have both a dependency on element %s", element.Name, parent.Name, p.Name)
						}
					}
				}
			}
		}
	}

	for _, r := range config.Runtimes {
		if r.Type != RuntimeTypePod {
			return errors.Errorf("runtime %q: wrong type %q", r.Name, r.Type)
		}
		if len(r.Containers) == 0 {
			return errors.Errorf("runtime %q: at least one container must be defined", r.Name)
		}
	}

	for _, t := range config.Tasks {
		if len(t.Name) > maxTaskNameLength {
			return errors.Errorf("task name %q too long", t.Name)
		}
		if t.Runtime == "" {
			return errors.Errorf("task %q: undefined runtime", t.Name)
		}
		if _, ok := config.Runtimes[t.Runtime]; !ok {
			return errors.Errorf("runtime %q needed by task %q doesn't exist", t.Runtime, t.Name)
		}
		for i, s := range t.Steps {
			switch step := s.(type) {
			// TODO(sgotti) we could use the run step command as step name but when the
			// command is very long or multi line it doesn't makes sense and will
			// probably be quite unuseful/confusing from an UI point of view
			case *RunStep:
				if step.Name == "" {
					lines, err := util.CountLines(step.Command)
					// if we failed to count the lines (shouldn't happen) or the number of lines is > 1 then a name is requred
					if err != nil || lines > 1 {
						return errors.Errorf("missing step name for step %d in task %q, required since command is more than one line", i, t.Name)
					}
					len := len(step.Command)
					if len > maxStepNameLength {
						len = maxStepNameLength
					}
					step.Name = step.Command[:len]
				}
			}
		}
	}

	for _, pipeline := range config.Pipelines {
		if len(pipeline.Name) > maxPipelineNameLength {
			return errors.Errorf("pipeline name %q too long", pipeline.Name)
		}
		for _, element := range pipeline.Elements {
			// check missing tasks reference
			if element.Task == "" {
				return errors.Errorf("no task defined for pipeline element %q", element.Name)
			}
			if _, ok := config.Tasks[element.Task]; !ok {
				return errors.Errorf("task %q needed by pipeline element %q doesn't exist", element.Task, element.Name)
			}
			// check duplicate dependencies in task
			seenDependencies := map[string]struct{}{}
			for _, dep := range element.Depends {
				if _, ok := seenDependencies[dep.ElementName]; ok {
					return errors.Errorf("duplicate task dependency: %s", element.Name)
				}
				seenDependencies[dep.ElementName] = struct{}{}
			}
		}
	}

	return nil
}

// getElementParents returns direct parents of element.
func getElementParents(pipeline *Pipeline, element *Element) []*Element {
	parents := []*Element{}
	for _, el := range pipeline.Elements {
		isParent := false
		for _, d := range element.Depends {
			if d.ElementName == el.Name {
				isParent = true
			}
		}
		if isParent {
			parents = append(parents, el)
		}
	}
	return parents
}

// getAllElementParents returns all the parents (both direct and ancestors) of an element.
// In case of circular dependency it won't loop forever but will also return
// the element as parent of itself
func getAllElementParents(pipeline *Pipeline, element *Element) []*Element {
	pMap := map[string]*Element{}
	nextParents := getElementParents(pipeline, element)

	for len(nextParents) > 0 {
		parents := nextParents
		nextParents = []*Element{}
		for _, parent := range parents {
			if _, ok := pMap[parent.Name]; ok {
				continue
			}
			pMap[parent.Name] = parent
			nextParents = append(nextParents, getElementParents(pipeline, parent)...)
		}
	}

	parents := make([]*Element, 0, len(pMap))
	for _, v := range pMap {
		parents = append(parents, v)
	}
	return parents
}
