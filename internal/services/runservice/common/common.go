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

package common

import (
	"path"
	"sort"

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/runconfig"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/runservice/types"
)

const (
	MaxCacheKeyLength = 200
)

type DataType string

const (
	DataTypeRun        DataType = "run"
	DataTypeRunConfig  DataType = "runconfig"
	DataTypeRunCounter DataType = "runcounter"

	CacheCleanerLockKey     = "cachecleaner"
	WorkspaceCleanerLockKey = "workspacecleaner"
	TaskUpdaterLockKey      = "taskupdater"
)

func TaskFetcherLockKey(taskID string) string {
	return path.Join("taskfetcher", taskID)
}

func OSTSubGroupsAndGroupTypes(group string) []string {
	h := util.PathHierarchy(group)
	if len(h)%2 != 1 {
		panic(errors.Errorf("wrong group path %q", group))
	}

	return h
}

func OSTRootGroup(group string) string {
	pl := util.PathList(group)
	if len(pl) < 2 {
		panic(errors.Errorf("cannot determine root group name, wrong group path %q", group))
	}

	return pl[1]
}

func OSTSubGroups(group string) []string {
	h := util.PathHierarchy(group)
	if len(h)%2 != 1 {
		panic(errors.Errorf("wrong group path %q", group))
	}

	// remove group types
	sg := []string{}
	for i, g := range h {
		if i%2 == 0 {
			sg = append(sg, g)
		}
	}

	return sg
}

func OSTSubGroupTypes(group string) []string {
	h := util.PathHierarchy(group)
	if len(h)%2 != 1 {
		panic(errors.Errorf("wrong group path %q", group))
	}

	// remove group names
	sg := []string{}
	for i, g := range h {
		if i%2 == 1 {
			sg = append(sg, g)
		}
	}

	return sg
}

type parentsByLevelName []*types.RunConfigTask

func (p parentsByLevelName) Len() int { return len(p) }
func (p parentsByLevelName) Less(i, j int) bool {
	if p[i].Level != p[j].Level {
		return p[i].Level < p[j].Level
	}
	return p[i].Name < p[j].Name
}
func (p parentsByLevelName) Swap(i, j int) { p[i], p[j] = p[j], p[i] }

func mergeEnv(dest, src map[string]string) {
	for k, v := range src {
		dest[k] = v
	}
}

func GenExecutorTaskSpecData(r *types.Run, rt *types.RunTask, rc *types.RunConfig) *types.ExecutorTaskSpecData {
	rct := rc.Tasks[rt.ID]

	environment := map[string]string{}
	if rct.Environment != nil {
		environment = rct.Environment
	}
	mergeEnv(environment, rc.StaticEnvironment)
	// run config Environment variables ovverride every other environment variable
	mergeEnv(environment, rc.Environment)

	cachePrefix := OSTRootGroup(r.Group)
	if rc.CacheGroup != "" {
		cachePrefix = rc.CacheGroup
	}

	data := &types.ExecutorTaskSpecData{
		// The executorTask ID must be the same as the runTask ID so we can detect if
		// there's already an executorTask scheduled for that run task and we can get
		// at most once task execution
		TaskName:             rct.Name,
		Arch:                 rct.Runtime.Arch,
		Containers:           rct.Runtime.Containers,
		Environment:          environment,
		WorkingDir:           rct.WorkingDir,
		Shell:                rct.Shell,
		User:                 rct.User,
		Steps:                rct.Steps,
		CachePrefix:          cachePrefix,
		DockerRegistriesAuth: rct.DockerRegistriesAuth,
	}

	// calculate workspace operations
	// TODO(sgotti) right now we don't support duplicated files. So it's not currently possibile to overwrite a file in a upper layer.
	// this simplifies the workspaces extractions since they could be extracted in any order. We make them ordered just for reproducibility
	wsops := []types.WorkspaceOperation{}
	rctAllParents := runconfig.GetAllParents(rc.Tasks, rct)

	// sort parents by level and name just for reproducibility
	sort.Sort(parentsByLevelName(rctAllParents))

	for _, rctParent := range rctAllParents {
		for _, archiveStep := range r.Tasks[rctParent.ID].WorkspaceArchives {
			wsop := types.WorkspaceOperation{TaskID: rctParent.ID, Step: archiveStep}
			wsops = append(wsops, wsop)
		}
	}

	data.WorkspaceOperations = wsops

	return data
}

func GenExecutorTask(r *types.Run, rt *types.RunTask, rc *types.RunConfig, executor *types.Executor) *types.ExecutorTask {
	rct := rc.Tasks[rt.ID]

	et := types.NewExecutorTask()
	et.Spec = types.ExecutorTaskSpec{
		ExecutorID: executor.ExecutorID,
		RunID:      r.ID,
		RunTaskID:  rt.ID,
		// ExecutorTaskSpecData is currently not saved in the database to keep
		// size smaller but is generated everytime the executor task is sent to
		// the executor
	}
	et.Status = types.ExecutorTaskStatus{
		Phase: types.ExecutorTaskPhaseNotStarted,
		Steps: make([]*types.ExecutorTaskStepStatus, len(rct.Steps)),
	}

	for i := range et.Status.Steps {
		et.Status.Steps[i] = &types.ExecutorTaskStepStatus{
			Phase: types.ExecutorTaskPhaseNotStarted,
		}
	}

	return et
}
