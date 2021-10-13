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

	"agola.io/agola/internal/config"
	itypes "agola.io/agola/internal/services/types"
	"agola.io/agola/internal/util"
	rstypes "agola.io/agola/services/runservice/types"
	"agola.io/agola/services/types"

	errors "golang.org/x/xerrors"
)

const (
	defaultShell = "/bin/sh -e"
)

func genRuntime(c *config.Config, ce *config.Runtime, variables map[string]string) *rstypes.Runtime {
	containers := []*rstypes.Container{}
	for _, cc := range ce.Containers {
		env := genEnv(cc.Environment, variables)
		container := &rstypes.Container{
			Image:       cc.Image,
			Environment: env,
			User:        cc.User,
			Privileged:  cc.Privileged,
			Entrypoint:  cc.Entrypoint,
			Volumes:     make([]rstypes.Volume, len(cc.Volumes)),
		}

		for i, ccVol := range cc.Volumes {
			container.Volumes[i] = rstypes.Volume{
				Path: ccVol.Path,
			}

			if ccVol.TmpFS != nil {
				var size int64
				if ccVol.TmpFS.Size != nil {
					size = ccVol.TmpFS.Size.Value()
				}
				container.Volumes[i].TmpFS = &rstypes.VolumeTmpFS{
					Size: size,
				}
			}
		}
		containers = append(containers, container)
	}

	return &rstypes.Runtime{
		Type:       rstypes.RuntimeType(ce.Type),
		Arch:       ce.Arch,
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
		rs.Command = fmt.Sprintf(`
set -x

mkdir ~/.ssh
chmod 700 ~/.ssh
touch ~/.ssh/id_rsa
chmod 600 ~/.ssh/id_rsa
touch ~/.ssh/known_hosts
chmod 600 ~/.ssh/known_hosts

# Add public ssh host key
if [ -n "$AGOLA_SSHHOSTKEY" ]; then
    echo "$AGOLA_SSHHOSTKEY" >> ~/.ssh/known_hosts
fi

# Add repository deploy key
(cat <<EOF > ~/.ssh/id_rsa
$AGOLA_SSHPRIVKEY
EOF
)

STRICT_HOST_KEY_CHECKING="yes"

if [ -n "$AGOLA_SKIPSSHHOSTKEYCHECK" ]; then
	# Disable git host key verification
	STRICT_HOST_KEY_CHECKING="no"
fi

(cat <<EOF > ~/.ssh/config
Host $AGOLA_GIT_HOST
	HostName $AGOLA_GIT_HOST
	Port $AGOLA_GIT_PORT
	StrictHostKeyChecking ${STRICT_HOST_KEY_CHECKING}
	PasswordAuthentication no
EOF
)

git clone %s $AGOLA_REPOSITORY_URL .
git fetch origin $AGOLA_GIT_REF

if [ -n "$AGOLA_GIT_COMMITSHA" ]; then
	git checkout $AGOLA_GIT_COMMITSHA
else
	git checkout FETCH_HEAD
fi
`, genCloneOptions(cs))

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
		rs.Tty = cs.Tty
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

// GenRunConfigTaskGroups generates a run config task groups from a run in the config, expanding all the references to task groups
// this functions assumes that the config is already checked for possible errors (i.e referenced task group must exits)
func GenRunConfigTaskGroups(uuid util.UUIDGenerator, c *config.Config, runName string) map[string]*rstypes.RunConfigTaskGroup {
	cr := c.Run(runName)

	rctgs := map[string]*rstypes.RunConfigTaskGroup{}

	for _, ctg := range cr.TaskGroups {

		tg := &rstypes.RunConfigTaskGroup{
			Name:          ctg.Name,
			IgnoreFailure: ctg.IgnoreFailure,
		}

		rctgs[tg.Name] = tg
	}

	// populate task groups depends
	for _, rctg := range rctgs {
		ctg := cr.TaskGroup(rctg.Name)

		depends := make(map[string]*rstypes.RunConfigTaskGroupDepend, len(ctg.Depends))
		for _, d := range ctg.Depends {
			conditions := make([]rstypes.RunConfigDependCondition, len(d.Conditions))
			// when no conditions are defined default to on_success
			if len(d.Conditions) == 0 {
				conditions = append(conditions, rstypes.RunConfigDependConditionOnSuccess)
			} else {
				for ic, c := range d.Conditions {
					var condition rstypes.RunConfigDependCondition
					switch c {
					case config.DependConditionOnSuccess:
						condition = rstypes.RunConfigDependConditionOnSuccess
					case config.DependConditionOnFailure:
						condition = rstypes.RunConfigDependConditionOnFailure
					}
					conditions[ic] = condition
				}
			}

			depends[d.TaskGroupName] = &rstypes.RunConfigTaskGroupDepend{
				TaskGroupName: d.TaskGroupName,
				Conditions:    conditions,
			}
		}

		rctg.Depends = depends
	}

	return rctgs
}

// GenRunConfigTasks generates a run config tasks from a run in the config, expanding all the references to tasks
// this functions assumes that the config is already checked for possible errors (i.e referenced task must exits)
func GenRunConfigTasks(uuid util.UUIDGenerator, c *config.Config, runName string, variables map[string]string, refType itypes.RunRefType, branch, tag, ref string) map[string]*rstypes.RunConfigTask {
	cr := c.Run(runName)

	rcts := map[string]*rstypes.RunConfigTask{}

	for _, ct := range cr.Tasks {
		include := types.MatchWhen(ct.When.ToWhen(), refType, branch, tag, ref)

		steps := make(rstypes.Steps, len(ct.Steps))
		for i, cpts := range ct.Steps {
			steps[i] = stepFromConfigStep(cpts, variables)
		}

		tEnv := genEnv(ct.Environment, variables)

		t := &rstypes.RunConfigTask{
			ID:                   uuid.New(ct.Name).String(),
			Name:                 ct.Name,
			TaskGroup:            ct.TaskGroup,
			Runtime:              genRuntime(c, ct.Runtime, variables),
			Environment:          tEnv,
			WorkingDir:           ct.WorkingDir,
			Shell:                ct.Shell,
			User:                 ct.User,
			Steps:                steps,
			IgnoreFailure:        ct.IgnoreFailure,
			Skip:                 !include,
			NeedsApproval:        ct.Approval,
			DockerRegistriesAuth: make(map[string]rstypes.DockerRegistryAuth),
		}

		if t.Shell == "" {
			t.Shell = defaultShell
		}

		if c.DockerRegistriesAuth != nil {
			for regname, auth := range c.DockerRegistriesAuth {
				t.DockerRegistriesAuth[regname] = rstypes.DockerRegistryAuth{
					Type:     rstypes.DockerRegistryAuthType(auth.Type),
					Username: genValue(auth.Username, variables),
					Password: genValue(auth.Password, variables),
				}
			}
		}

		// override with per run docker registry auth
		if cr.DockerRegistriesAuth != nil {
			for regname, auth := range cr.DockerRegistriesAuth {
				t.DockerRegistriesAuth[regname] = rstypes.DockerRegistryAuth{
					Type:     rstypes.DockerRegistryAuthType(auth.Type),
					Username: genValue(auth.Username, variables),
					Password: genValue(auth.Password, variables),
				}
			}
		}

		// override with per task docker registry auth
		if ct.DockerRegistriesAuth != nil {
			for regname, auth := range ct.DockerRegistriesAuth {
				t.DockerRegistriesAuth[regname] = rstypes.DockerRegistryAuth{
					Type:     rstypes.DockerRegistryAuthType(auth.Type),
					Username: genValue(auth.Username, variables),
					Password: genValue(auth.Password, variables),
				}
			}
		}

		rcts[t.ID] = t
	}

	// populate depends, needs to be done after having created all the tasks so we can resolve their id
	for _, rct := range rcts {
		ct := cr.Task(rct.Name)

		depends := make(map[string]*rstypes.RunConfigTaskDepend, len(ct.Depends))
		for _, d := range ct.Depends {
			conditions := make([]rstypes.RunConfigDependCondition, len(d.Conditions))
			// when no conditions are defined default to on_success
			if len(d.Conditions) == 0 {
				conditions = append(conditions, rstypes.RunConfigDependConditionOnSuccess)
			} else {
				for ic, c := range d.Conditions {
					var condition rstypes.RunConfigDependCondition
					switch c {
					case config.DependConditionOnSuccess:
						condition = rstypes.RunConfigDependConditionOnSuccess
					case config.DependConditionOnFailure:
						condition = rstypes.RunConfigDependConditionOnFailure
					}
					conditions[ic] = condition
				}
			}

			drct := runConfigTaskByName(rcts, d.TaskName)
			depends[drct.ID] = &rstypes.RunConfigTaskDepend{
				TaskID:     drct.ID,
				Conditions: conditions,
			}
		}

		rct.Depends = depends
	}

	return rcts
}

func runConfigTaskByName(rcts map[string]*rstypes.RunConfigTask, name string) *rstypes.RunConfigTask {
	for _, rct := range rcts {
		if rct.Name == name {
			return rct
		}
	}
	return nil
}

func CheckRunConfig(rctgs map[string]*rstypes.RunConfigTaskGroup, rcts map[string]*rstypes.RunConfigTask) error {
	if err := checkRunConfigTasks(rcts); err != nil {
		return errors.Errorf("check run config tasks failed: %w", err)
	}
	if err := checkRunConfigTaskGroups(rctgs); err != nil {
		return errors.Errorf("check run config tasks failed: %w", err)
	}

	return nil
}

func checkRunConfigTaskGroups(rctgs map[string]*rstypes.RunConfigTaskGroup) error {
	cerrs := &util.Errors{}

	// check broken dependencies between task groups
	// collect all task names
	allTaskGroups := map[string]struct{}{}
	for _, tg := range rctgs {
		allTaskGroups[tg.Name] = struct{}{}
	}

	for _, tg := range rctgs {
		for _, dep := range tg.Depends {
			if _, ok := allTaskGroups[dep.TaskGroupName]; !ok {
				cerrs.Append(errors.Errorf("task group %q needed by task group %q doesn't exist", dep.TaskGroupName, tg.Name))
			}
		}
	}

	// check circular dependencies
	for _, tg := range rctgs {
		allParents := TaskGroupAllParents(rctgs, tg)
		for _, parent := range allParents {
			if parent.Name == tg.Name {
				// TODO(sgotti) get the parent that depends on task to report it
				dep := []string{}
				for _, parent := range allParents {
					pparents := TaskGroupParents(rctgs, parent)
					for _, pparent := range pparents {
						if pparent.Name == tg.Name {
							dep = append(dep, fmt.Sprintf("%q", parent.Name))
						}
					}
				}
				cerrs.Append(errors.Errorf("circular dependency between task group %q and task groups %s", tg.Name, strings.Join(dep, " ")))
			}
		}
	}

	// check that the task and its parent don't have a common dependency
	for _, tg := range rctgs {
		parents := TaskGroupParents(rctgs, tg)
		for _, parent := range parents {
			allParentParents := TaskGroupAllParents(rctgs, parent)
			for _, p := range parents {
				for _, pp := range allParentParents {
					if p.Name == pp.Name {
						cerrs.Append(errors.Errorf("task group %q and its parent %q have both a dependency on task group %q", tg.Name, parent.Name, p.Name))
					}
				}
			}
		}
	}

	// check duplicate task group dependencies
	for _, tg := range rctgs {
		// check duplicate dependencies in task
		seenDependencies := map[string]struct{}{}
		for _, dep := range tg.Depends {
			if _, ok := seenDependencies[dep.TaskGroupName]; ok {
				cerrs.Append(errors.Errorf("task group %q have a duplicate dependency on task group %q", tg.Name, dep.TaskGroupName))
			}
			seenDependencies[dep.TaskGroupName] = struct{}{}
		}
	}

	if cerrs.IsErr() {
		return cerrs
	}

	return nil
}

func checkRunConfigTasks(rcts map[string]*rstypes.RunConfigTask) error {

	// check broken dependencies between tasks
	// collect all task names
	allTasks := map[string]struct{}{}
	for _, t := range rcts {
		allTasks[t.ID] = struct{}{}
	}

	cerrs := &util.Errors{}
	for _, t := range rcts {
		for _, dep := range t.Depends {
			if _, ok := allTasks[dep.TaskID]; !ok {
				cerrs.Append(errors.Errorf("run task %q needed by task %q doesn't exist", dep.TaskID, t.ID))
			}
		}
	}
	if cerrs.IsErr() {
		return cerrs
	}

	// check circular dependencies
	cerrs = &util.Errors{}
	for _, t := range rcts {
		allParents := TaskAllParents(rcts, t)
		for _, parent := range allParents {
			if parent.ID == t.ID {
				// TODO(sgotti) get the parent that depends on task to report it
				dep := []string{}
				for _, parent := range allParents {
					pparents := TaskParents(rcts, parent)
					for _, pparent := range pparents {
						if pparent.ID == t.ID {
							dep = append(dep, fmt.Sprintf("%q", parent.ID))
						}
					}
				}
				cerrs.Append(errors.Errorf("circular dependency between task %q and tasks %s", t.ID, strings.Join(dep, " ")))
			}
		}
	}
	if cerrs.IsErr() {
		return cerrs
	}

	// check that the task and its parent don't have a common dependency
	cerrs = &util.Errors{}
	for _, t := range rcts {
		parents := TaskParents(rcts, t)
		for _, parent := range parents {
			allParentParents := TaskAllParents(rcts, parent)
			for _, p := range parents {
				for _, pp := range allParentParents {
					if p.ID == pp.ID {
						cerrs.Append(errors.Errorf("task %q and its parent %q have both a dependency on task %q", t.ID, parent.ID, p.ID))
					}
				}
			}
		}
	}
	if cerrs.IsErr() {
		return cerrs
	}

	// check duplicate task dependencies
	cerrs = &util.Errors{}
	for _, t := range rcts {
		// check duplicate dependencies in task
		seenDependencies := map[string]struct{}{}
		for _, dep := range t.Depends {
			if _, ok := seenDependencies[dep.TaskID]; ok {
				cerrs.Append(errors.Errorf("task %q have a duplicate dependency on task %q", t.ID, dep.TaskID))
			}
			seenDependencies[dep.TaskID] = struct{}{}
		}
	}
	if cerrs.IsErr() {
		return cerrs
	}

	// check task and all parent tasks have the same task group
	cerrs = &util.Errors{}
	for _, t := range rcts {
		allParents := TaskAllParents(rcts, t)
		for _, parent := range allParents {
			if parent.TaskGroup != t.TaskGroup {
				cerrs.Append(errors.Errorf("task %q and its dependency %q have different task group", t.ID, parent.ID))
			}
		}
	}
	if cerrs.IsErr() {
		return cerrs
	}

	return nil
}

func GenLevels(rctgs map[string]*rstypes.RunConfigTaskGroup, rcts map[string]*rstypes.RunConfigTask) error {
	if err := genTaskGroupsLevels(rctgs); err != nil {
		return errors.Errorf("gen task groups levels failed: %w", err)
	}
	if err := genTasksLevels(rcts); err != nil {
		return errors.Errorf("gen tasks levels failed: %w", err)
	}
	if err := genTasksGlobalLevels(rctgs, rcts); err != nil {
		return errors.Errorf("gen tasks global levels failed: %w", err)
	}

	return nil
}

func genTaskGroupsLevels(rctgs map[string]*rstypes.RunConfigTaskGroup) error {
	// reset task groups levels
	for _, tg := range rctgs {
		tg.Level = -1
	}

	level := 0
	for {
		c := 0
		for _, tg := range rctgs {
			// skip tasks with the level already set
			if tg.Level != -1 {
				continue
			}

			parents := TaskGroupParents(rctgs, tg)
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
				tg.Level = level
				c++
			}
		}

		// if no tasks were updated in this level we can stop here
		if c == 0 {
			break
		}
		level++
	}
	for _, tg := range rctgs {
		if tg.Level == -1 {
			return errors.Errorf("circular dependency detected")
		}
	}
	return nil
}

func genTasksLevels(rcts map[string]*rstypes.RunConfigTask) error {
	// reset tasks levels
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

			parents := TaskParents(rcts, t)
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

func genTasksGlobalLevels(rctgs map[string]*rstypes.RunConfigTaskGroup, rcts map[string]*rstypes.RunConfigTask) error {
	tgMaxTasksLevelByLevel := map[int]int{}
	for _, tg := range rctgs {
		maxTasksLevel := 0
		for _, t := range rcts {
			if t.TaskGroup != tg.Name {
				continue
			}
			if t.Level > maxTasksLevel {
				maxTasksLevel = t.Level
			}
		}
		if _, ok := tgMaxTasksLevelByLevel[tg.Level]; !ok {
			tgMaxTasksLevelByLevel[tg.Level] = maxTasksLevel
		} else {
			if maxTasksLevel > tgMaxTasksLevelByLevel[tg.Level] {
				tgMaxTasksLevelByLevel[tg.Level] = maxTasksLevel
			}
		}
	}

	// calculate the level of the parents task group
	for _, t := range rcts {
		tg := rctgs[t.TaskGroup]
		gl := 0
		for i := 0; i < tg.Level; i++ {
			gl += tgMaxTasksLevelByLevel[i] + 1
		}
		t.GlobalLevel = t.Level + gl
	}

	return nil
}

// TaskGroupParents returns direct parents of task.
func TaskGroupParents(rctgs map[string]*rstypes.RunConfigTaskGroup, taskGroup *rstypes.RunConfigTaskGroup) []*rstypes.RunConfigTaskGroup {
	parents := []*rstypes.RunConfigTaskGroup{}
	for _, tg := range rctgs {
		if _, ok := taskGroup.Depends[tg.Name]; ok {
			parents = append(parents, tg)
		}
	}
	return parents
}

// TaskParents returns direct parents of task.
func TaskParents(rcts map[string]*rstypes.RunConfigTask, task *rstypes.RunConfigTask) []*rstypes.RunConfigTask {
	parents := []*rstypes.RunConfigTask{}
	for _, t := range rcts {
		if _, ok := task.Depends[t.ID]; ok {
			parents = append(parents, t)
		}
	}
	return parents
}

// TaskGroupAllParents returns all the parents of the same task group (both
// direct and ancestors) of task.
// In case of circular dependency it won't loop forever but will also
// return task as parent of itself
func TaskGroupAllParents(rctgs map[string]*rstypes.RunConfigTaskGroup, tg *rstypes.RunConfigTaskGroup) []*rstypes.RunConfigTaskGroup {
	pMap := map[string]*rstypes.RunConfigTaskGroup{}
	nextParents := TaskGroupParents(rctgs, tg)

	for len(nextParents) > 0 {
		parents := nextParents
		nextParents = []*rstypes.RunConfigTaskGroup{}
		for _, parent := range parents {
			if _, ok := pMap[parent.Name]; ok {
				continue
			}
			pMap[parent.Name] = parent
			nextParents = append(nextParents, TaskGroupParents(rctgs, parent)...)
		}
	}

	parents := make([]*rstypes.RunConfigTaskGroup, 0, len(pMap))
	for _, v := range pMap {
		parents = append(parents, v)
	}
	return parents
}

// TaskAllParents returns all the parents of the same task group (both
// direct and ancestors) of task.
// In case of circular dependency it won't loop forever but will also
// return task as parent of itself
func TaskAllParents(rcts map[string]*rstypes.RunConfigTask, task *rstypes.RunConfigTask) []*rstypes.RunConfigTask {
	pMap := map[string]*rstypes.RunConfigTask{}
	nextParents := TaskParents(rcts, task)

	for len(nextParents) > 0 {
		parents := nextParents
		nextParents = []*rstypes.RunConfigTask{}
		for _, parent := range parents {
			if _, ok := pMap[parent.ID]; ok {
				continue
			}
			pMap[parent.ID] = parent
			nextParents = append(nextParents, TaskParents(rcts, parent)...)
		}
	}

	parents := make([]*rstypes.RunConfigTask, 0, len(pMap))
	for _, v := range pMap {
		parents = append(parents, v)
	}
	return parents
}

// TaskAllParents returns all the global parents (both direct and
// ancestors also from parent task groups) of task.
// In case of circular dependency it won't loop forever but will also
// return task as parent of itself
func TaskAllGlobalParents(rctgs map[string]*rstypes.RunConfigTaskGroup, rcts map[string]*rstypes.RunConfigTask, task *rstypes.RunConfigTask) []*rstypes.RunConfigTask {
	parents := TaskAllParents(rcts, task)

	tgParents := TaskGroupParents(rctgs, rctgs[task.TaskGroup])

	for _, tgParent := range tgParents {
		for _, t := range rcts {
			if t.TaskGroup == tgParent.Name {
				parents = append(parents, t)
			}
		}
	}
	return parents
}

func TaskGroupParentDependConditions(tg, ptg *rstypes.RunConfigTaskGroup) []rstypes.RunConfigDependCondition {
	if dt, ok := tg.Depends[ptg.Name]; ok {
		return dt.Conditions
	}
	return nil
}

func TaskParentDependConditions(t, pt *rstypes.RunConfigTask) []rstypes.RunConfigDependCondition {
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

func genCloneOptions(c *config.CloneStep) string {
	cloneoptions := []string{}
	if c.Depth != nil {
		cloneoptions = append(cloneoptions, fmt.Sprintf("--depth %d", *c.Depth))
	}
	if c.RecurseSubmodules {
		cloneoptions = append(cloneoptions, "--recurse-submodules")
	}
	return strings.Join(cloneoptions, " ")
}
