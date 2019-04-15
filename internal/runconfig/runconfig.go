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

package runconfig

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/sorintlab/agola/internal/config"
	rstypes "github.com/sorintlab/agola/internal/services/runservice/types"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"
)

func genRuntime(c *config.Config, runtimeName string, variables map[string]string) *rstypes.Runtime {
	ce := c.Runtime(runtimeName)

	containers := []*rstypes.Container{}
	for _, cc := range ce.Containers {
		env := genEnv(cc.Environment, variables)
		container := &rstypes.Container{
			Image:       cc.Image,
			Environment: env,
			User:        cc.User,
			Privileged:  cc.Privileged,
			Entrypoint:  cc.Entrypoint,
		}

		// Set container auth
		if cc.Auth != nil {
			container.Auth = &rstypes.RegistryAuth{
				Type:     rstypes.RegistryAuthType(cc.Auth.Type),
				Username: genValue(cc.Auth.Username, variables),
				Password: genValue(cc.Auth.Password, variables),
			}
		}
		// if container auth is nil use runtime auth
		if container.Auth == nil && ce.Auth != nil {
			container.Auth = &rstypes.RegistryAuth{
				Type:     rstypes.RegistryAuthType(ce.Auth.Type),
				Username: genValue(ce.Auth.Username, variables),
				Password: genValue(ce.Auth.Password, variables),
			}
		}

		containers = append(containers, container)
	}

	return &rstypes.Runtime{
		Type:       rstypes.RuntimeType(ce.Type),
		Containers: containers,
	}
}

func stepFromConfigStep(csi interface{}, variables map[string]string) interface{} {
	switch cs := csi.(type) {
	case *config.CloneStep:
		// transform a "clone" step in a "run" step command
		rs := &config.RunStep{}

		rs.Type = "run"
		rs.Name = "Clone repository and checkout code"
		rs.Command = `
set -x

mkdir ~/.ssh
chmod 700 ~/.ssh
touch ~/.ssh/id_rsa
chmod 600 ~/.ssh/id_rsa

# Add repository deploy key
(cat <<EOF > ~/.ssh/id_rsa
$AGOLA_SSHPRIVKEY
EOF
)

if [ -n "$AGOLA_SKIPSSHHOSTKEYCHECK" ]; then
	# Disable git host key verification
	(cat <<EOF > ~/.ssh/config
Host $AGOLA_GIT_HOST
	HostName $AGOLA_GIT_HOST
	Port $AGOLA_GIT_PORT
	StrictHostKeyChecking no
	UserKnownHostsFile /dev/null
EOF
	)
fi

git clone $AGOLA_REPOSITORY_URL .
git fetch origin $AGOLA_GIT_REF

if [ -n "$AGOLA_GIT_COMMITSHA" ]; then
	git checkout $AGOLA_GIT_COMMITSHA
else
	git checkout FETCH_HEAD
fi
`

		return rs

	case *config.RunStep:
		rs := &rstypes.RunStep{}

		env := genEnv(cs.Environment, variables)

		rs.Type = cs.Type
		rs.Name = cs.Name
		rs.Command = cs.Command
		rs.Environment = env
		rs.WorkingDir = cs.WorkingDir
		rs.Shell = cs.Shell
		rs.User = cs.User
		return rs

	case *config.SaveToWorkspaceStep:
		sws := &rstypes.SaveToWorkspaceStep{}

		sws.Type = cs.Type
		sws.Name = cs.Name

		sws.Contents = make([]rstypes.SaveContent, len(cs.Contents))
		for i, csc := range cs.Contents {
			sc := rstypes.SaveContent{}
			sc.SourceDir = csc.SourceDir
			sc.DestDir = csc.DestDir
			sc.Paths = csc.Paths

			sws.Contents[i] = sc
		}
		return sws

	case *config.RestoreWorkspaceStep:
		rws := &rstypes.RestoreWorkspaceStep{}
		rws.Name = cs.Name
		rws.Type = cs.Type
		rws.DestDir = cs.DestDir

		return rws

	case *config.SaveCacheStep:
		sws := &rstypes.SaveCacheStep{}

		sws.Type = cs.Type
		sws.Name = cs.Name
		sws.Key = cs.Key

		sws.Contents = make([]rstypes.SaveContent, len(cs.Contents))
		for i, csc := range cs.Contents {
			sc := rstypes.SaveContent{}
			sc.SourceDir = csc.SourceDir
			sc.DestDir = csc.DestDir
			sc.Paths = csc.Paths

			sws.Contents[i] = sc
		}
		return sws

	case *config.RestoreCacheStep:
		rws := &rstypes.RestoreCacheStep{}
		rws.Name = cs.Name
		rws.Type = cs.Type
		rws.Keys = cs.Keys
		rws.DestDir = cs.DestDir

		return rws

	default:
		panic(fmt.Errorf("unknown config step type: %s", util.Dump(cs)))
	}
}

// GenRunConfigTasks generates a run config tasks from a run in the config, expanding all the references to tasks
// this functions assumes that the config is already checked for possible errors (i.e referenced task must exits)
func GenRunConfigTasks(uuid util.UUIDGenerator, c *config.Config, runName string, variables map[string]string, branch, tag, ref string) map[string]*rstypes.RunConfigTask {
	cr := c.Run(runName)

	rcts := map[string]*rstypes.RunConfigTask{}

	for _, cre := range cr.Elements {
		include := types.MatchWhen(cre.When, branch, tag, ref)

		// resolve referenced task
		ct := c.Task(cre.Task)

		steps := make([]interface{}, len(ct.Steps))
		for i, cpts := range ct.Steps {
			steps[i] = stepFromConfigStep(cpts, variables)
		}

		tEnv := genEnv(ct.Environment, variables)

		t := &rstypes.RunConfigTask{
			ID: uuid.New(cre.Name).String(),
			// use the element name from the config as the task name
			Name:          cre.Name,
			Runtime:       genRuntime(c, ct.Runtime, variables),
			Environment:   tEnv,
			WorkingDir:    ct.WorkingDir,
			Shell:         ct.Shell,
			User:          ct.User,
			Steps:         steps,
			IgnoreFailure: cre.IgnoreFailure,
			Skip:          !include,
			NeedsApproval: cre.Approval,
		}

		rcts[t.ID] = t
	}

	// populate depends, needs to be done after having created all the tasks so we can resolve their id
	for _, rct := range rcts {
		cre := cr.Elements[rct.Name]

		depends := make(map[string]*rstypes.RunConfigTaskDepend, len(cre.Depends))
		for _, d := range cre.Depends {
			conditions := make([]rstypes.RunConfigTaskDependCondition, len(d.Conditions))
			// when no conditions are defined default to on_success
			if len(d.Conditions) == 0 {
				conditions = append(conditions, rstypes.RunConfigTaskDependConditionOnSuccess)
			} else {
				for ic, c := range d.Conditions {
					var condition rstypes.RunConfigTaskDependCondition
					switch c {
					case config.DependConditionOnSuccess:
						condition = rstypes.RunConfigTaskDependConditionOnSuccess
					case config.DependConditionOnFailure:
						condition = rstypes.RunConfigTaskDependConditionOnFailure
					}
					conditions[ic] = condition
				}
			}

			drct := getRunConfigTaskByName(rcts, d.ElementName)
			depends[drct.ID] = &rstypes.RunConfigTaskDepend{
				TaskID:     drct.ID,
				Conditions: conditions,
			}
		}

		rct.Depends = depends
	}

	return rcts
}

func getRunConfigTaskByName(rcts map[string]*rstypes.RunConfigTask, name string) *rstypes.RunConfigTask {
	for _, rct := range rcts {
		if rct.Name == name {
			return rct
		}
	}
	return nil
}

func CheckRunConfigTasks(rcts map[string]*rstypes.RunConfigTask) error {
	// check circular dependencies
	cerrs := &util.Errors{}
	for _, t := range rcts {
		allParents := GetAllParents(rcts, t)
		for _, parent := range allParents {
			if parent.ID == t.ID {
				// TODO(sgotti) get the parent that depends on task to report it
				dep := []string{}
				for _, parent := range allParents {
					pparents := GetParents(rcts, parent)
					for _, pparent := range pparents {
						if pparent.ID == t.ID {
							dep = append(dep, fmt.Sprintf("%q", parent.Name))
						}
					}
				}
				cerrs.Append(errors.Errorf("circular dependency between task %q and tasks %s", t.Name, strings.Join(dep, " ")))
			}
		}
	}
	if cerrs.IsErr() {
		return cerrs
	}

	// check that the task and its parent don't have a common dependency
	for _, t := range rcts {
		parents := GetParents(rcts, t)
		for _, parent := range parents {
			allParents := GetAllParents(rcts, t)
			allParentParents := GetAllParents(rcts, parent)
			for _, p := range allParents {
				for _, pp := range allParentParents {
					if p.ID == pp.ID {
						return errors.Errorf("task %s and its parent %s have both a dependency on task %s", t.Name, parent.Name, p.Name)
					}
				}
			}
		}
	}

	return nil
}

func GenTasksLevels(rcts map[string]*rstypes.RunConfigTask) error {
	// reset all task level
	for _, t := range rcts {
		t.Level = -1
	}

	level := 0
	for {
		c := 0
		for _, t := range rcts {
			// skip tasks with the level already set
			if t.Level != -1 {
				continue
			}

			parents := GetParents(rcts, t)
			ok := true
			for _, p := range parents {
				// * skip if the parent doesn't have a level yet
				// * skip if the parent has a level equal than the current one (this happens when
				// we have just set a level to a task in this same level loop)
				if p.Level == -1 || p.Level >= level {
					ok = false
				}
			}
			if ok {
				t.Level = level
				c++
			}
		}

		// if no tasks were updated in this level we can stop here
		if c == 0 {
			break
		}
		level++
	}
	for _, t := range rcts {
		if t.Level == -1 {
			return errors.Errorf("circular dependency detected")
		}
	}
	return nil
}

// GetParents returns direct parents of task.
func GetParents(rcts map[string]*rstypes.RunConfigTask, task *rstypes.RunConfigTask) []*rstypes.RunConfigTask {
	parents := []*rstypes.RunConfigTask{}
	for _, t := range rcts {
		if _, ok := task.Depends[t.ID]; ok {
			parents = append(parents, t)
		}
	}
	return parents
}

// GetAllParents returns all the parents (both direct and ancestors) of task.
// In case of circular dependency it won't loop forever but will also return
// task as parent of itself
func GetAllParents(rcts map[string]*rstypes.RunConfigTask, task *rstypes.RunConfigTask) []*rstypes.RunConfigTask {
	pMap := map[string]*rstypes.RunConfigTask{}
	nextParents := GetParents(rcts, task)

	for len(nextParents) > 0 {
		parents := nextParents
		nextParents = []*rstypes.RunConfigTask{}
		for _, parent := range parents {
			if _, ok := pMap[parent.ID]; ok {
				continue
			}
			pMap[parent.ID] = parent
			nextParents = append(nextParents, GetParents(rcts, parent)...)
		}
	}

	parents := make([]*rstypes.RunConfigTask, 0, len(pMap))
	for _, v := range pMap {
		parents = append(parents, v)
	}
	return parents
}

func GetParentDependConditions(t, pt *rstypes.RunConfigTask) []rstypes.RunConfigTaskDependCondition {
	if dt, ok := t.Depends[pt.ID]; ok {
		return dt.Conditions
	}
	return nil
}

func genEnv(cenv map[string]config.Value, variables map[string]string) map[string]string {
	env := map[string]string{}
	for envName, envVar := range cenv {
		env[envName] = genValue(envVar, variables)
	}
	return env
}

func genValue(val config.Value, variables map[string]string) string {
	switch val.Type {
	case config.ValueTypeString:
		return val.Value
	case config.ValueTypeFromVariable:
		return variables[val.Value]
	default:
		panic(fmt.Errorf("wrong value type: %q", val.Value))
	}
}
