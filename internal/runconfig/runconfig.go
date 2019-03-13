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

	uuid "github.com/satori/go.uuid"
)

func genRuntime(c *config.Config, runtimeName string) *rstypes.Runtime {
	ce := c.Runtime(runtimeName)

	containers := []*rstypes.Container{}
	for _, cc := range ce.Containers {
		containers = append(containers, &rstypes.Container{
			Image:       cc.Image,
			Environment: cc.Environment,
			User:        cc.User,
			Privileged:  cc.Privileged,
			Entrypoint:  cc.Entrypoint,
		})
	}
	return &rstypes.Runtime{
		Type:       rstypes.RuntimeType(ce.Type),
		Containers: containers,
	}
}

func stepFromConfigStep(csi interface{}) interface{} {
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

		rs.Type = cs.Type
		rs.Name = cs.Name
		rs.Command = cs.Command
		rs.Environment = cs.Environment
		rs.WorkingDir = cs.WorkingDir
		rs.Shell = cs.Shell
		rs.User = cs.User
		return rs

	case *config.SaveToWorkspaceStep:
		sws := &rstypes.SaveToWorkspaceStep{}

		sws.Type = cs.Type
		sws.Name = cs.Name

		sws.Contents = make([]rstypes.SaveToWorkspaceContent, len(cs.Contents))
		for i, csc := range cs.Contents {
			sc := rstypes.SaveToWorkspaceContent{}
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

	default:
		panic(fmt.Errorf("unknown config step type: %s", util.Dump(cs)))
	}
}

// GenRunConfig generates a run config from a pipeline in the config, expanding all the references to tasks
// this functions assumes that the config is already checked for possible errors (i.e referenced task must exits)
func GenRunConfig(c *config.Config, pipelineName string, env map[string]string, branch, tag, ref string) *rstypes.RunConfig {
	cp := c.Pipeline(pipelineName)

	rc := &rstypes.RunConfig{
		Name:        cp.Name,
		Tasks:       make(map[string]*rstypes.RunConfigTask),
		Environment: env,
	}

	for _, cpe := range cp.Elements {
		include := types.MatchWhen(cpe.When, branch, tag, ref)

		// resolve referenced task
		cpt := c.Task(cpe.Task)

		steps := make([]interface{}, len(cpt.Steps))
		for i, cpts := range cpt.Steps {
			steps[i] = stepFromConfigStep(cpts)
		}

		t := &rstypes.RunConfigTask{
			ID: uuid.NewV4().String(),
			// use the element name from the config as the task name
			Name:          cpe.Name,
			Runtime:       genRuntime(c, cpt.Runtime),
			Environment:   cpt.Environment,
			WorkingDir:    cpt.WorkingDir,
			Shell:         cpt.Shell,
			User:          cpt.User,
			Steps:         steps,
			IgnoreFailure: cpe.IgnoreFailure,
			Skip:          !include,
		}

		rc.Tasks[t.ID] = t
	}

	// populate depends, needs to be done after having created all the tasks so we can resolve their id
	for _, rct := range rc.Tasks {
		cpe := cp.Elements[rct.Name]

		depends := make([]*rstypes.RunConfigTaskDepend, len(cpe.Depends))
		for id, d := range cpe.Depends {
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

			drct := getRunConfigTaskByName(rc, d.ElementName)
			depends[id] = &rstypes.RunConfigTaskDepend{
				TaskID:     drct.ID,
				Conditions: conditions,
			}
		}

		rct.Depends = depends
	}

	return rc
}

func getRunConfigTaskByName(rc *rstypes.RunConfig, name string) *rstypes.RunConfigTask {
	for _, rct := range rc.Tasks {
		if rct.Name == name {
			return rct
		}
	}
	return nil
}

func CheckRunConfig(rc *rstypes.RunConfig) error {
	// check circular dependencies
	cerrs := &util.Errors{}
	for _, t := range rc.Tasks {
		allParents := GetAllParents(rc, t)
		for _, parent := range allParents {
			if parent.ID == t.ID {
				// TODO(sgotti) get the parent that depends on task to report it
				dep := []string{}
				for _, parent := range allParents {
					pparents := GetParents(rc, parent)
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
	for _, t := range rc.Tasks {
		parents := GetParents(rc, t)
		for _, parent := range parents {
			allParents := GetAllParents(rc, t)
			allParentParents := GetAllParents(rc, parent)
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

func GenTasksLevels(rc *rstypes.RunConfig) error {
	// reset all task level
	for _, t := range rc.Tasks {
		t.Level = -1
	}

	level := 0
	for {
		c := 0
		for _, t := range rc.Tasks {
			// skip tasks with the level already set
			if t.Level != -1 {
				continue
			}

			parents := GetParents(rc, t)
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
	for _, t := range rc.Tasks {
		if t.Level == -1 {
			return errors.Errorf("circular dependency detected")
		}
	}
	return nil
}

// GetParents returns direct parents of task.
func GetParents(rc *rstypes.RunConfig, task *rstypes.RunConfigTask) []*rstypes.RunConfigTask {
	parents := []*rstypes.RunConfigTask{}
	for _, t := range rc.Tasks {
		isParent := false
		for _, d := range task.Depends {
			if d.TaskID == t.ID {
				isParent = true
			}
		}
		if isParent {
			parents = append(parents, t)
		}
	}
	return parents
}

// GetAllParents returns all the parents (both direct and ancestors) of task.
// In case of circular dependency it won't loop forever but will also return
// task as parent of itself
func GetAllParents(rc *rstypes.RunConfig, task *rstypes.RunConfigTask) []*rstypes.RunConfigTask {
	pMap := map[string]*rstypes.RunConfigTask{}
	nextParents := GetParents(rc, task)

	for len(nextParents) > 0 {
		parents := nextParents
		nextParents = []*rstypes.RunConfigTask{}
		for _, parent := range parents {
			if _, ok := pMap[parent.ID]; ok {
				continue
			}
			pMap[parent.ID] = parent
			nextParents = append(nextParents, GetParents(rc, parent)...)
		}
	}

	parents := make([]*rstypes.RunConfigTask, 0, len(pMap))
	for _, v := range pMap {
		parents = append(parents, v)
	}
	return parents
}
