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

package command

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/sorintlab/agola/internal/services/runservice/types"
	"github.com/sorintlab/agola/internal/util"
)

func TestRecreateRun(t *testing.T) {

	inuuid := func(s string) string {
		u := &util.TestPrefixUUIDGenerator{Prefix: "in"}
		return u.New(s).String()
	}

	outuuid := func(s string) string {
		u := &util.TestPrefixUUIDGenerator{Prefix: "out"}
		return u.New(s).String()
	}

	// a global run config for all tests
	rc := &types.RunConfig{
		ID: inuuid("old"),
		Tasks: map[string]*types.RunConfigTask{
			inuuid("task01"): &types.RunConfigTask{
				ID:      inuuid("task01"),
				Name:    "task01",
				Depends: map[string]*types.RunConfigTaskDepend{},
				Runtime: &types.Runtime{Type: types.RuntimeType("pod"),
					Containers: []*types.Container{{Image: "image01"}},
				},
				Environment: map[string]string{},
				Steps:       []interface{}{},
				Skip:        false,
			},
			inuuid("task02"): &types.RunConfigTask{
				ID:   inuuid("task02"),
				Name: "task02",
				Depends: map[string]*types.RunConfigTaskDepend{
					inuuid("task01"): &types.RunConfigTaskDepend{TaskID: inuuid("task01"), Conditions: []types.RunConfigTaskDependCondition{types.RunConfigTaskDependConditionOnSuccess}},
				},
				Runtime: &types.Runtime{Type: types.RuntimeType("pod"),
					Containers: []*types.Container{{Image: "image01"}},
				},
				Environment: map[string]string{},
				Steps:       []interface{}{},
				Skip:        false,
			},
			inuuid("task03"): &types.RunConfigTask{
				ID:      inuuid("task03"),
				Name:    "task03",
				Depends: map[string]*types.RunConfigTaskDepend{},
				Runtime: &types.Runtime{Type: types.RuntimeType("pod"),
					Containers: []*types.Container{{Image: "image01"}},
				},
				Environment: map[string]string{},
				Steps:       []interface{}{},
				Skip:        false,
			},
			inuuid("task04"): &types.RunConfigTask{
				ID:   inuuid("task04"),
				Name: "task04",
				Runtime: &types.Runtime{Type: types.RuntimeType("pod"),
					Containers: []*types.Container{{Image: "image01"}},
				},
				Environment: map[string]string{},
				Steps:       []interface{}{},
				Skip:        false,
			},
			inuuid("task05"): &types.RunConfigTask{
				ID:   inuuid("task05"),
				Name: "task05",
				Depends: map[string]*types.RunConfigTaskDepend{
					inuuid("task03"): &types.RunConfigTaskDepend{TaskID: inuuid("task03"), Conditions: []types.RunConfigTaskDependCondition{types.RunConfigTaskDependConditionOnSuccess}},
					inuuid("task04"): &types.RunConfigTaskDepend{TaskID: inuuid("task04"), Conditions: []types.RunConfigTaskDependCondition{types.RunConfigTaskDependConditionOnSuccess}},
				},
				Runtime: &types.Runtime{Type: types.RuntimeType("pod"),
					Containers: []*types.Container{{Image: "image01"}},
				},
				Environment: map[string]string{},
				Steps:       []interface{}{},
				Skip:        false,
			},
		},
	}

	outrc := &types.RunConfig{
		ID: outuuid("new"),
		Tasks: map[string]*types.RunConfigTask{
			outuuid("task01"): &types.RunConfigTask{
				ID:      outuuid("task01"),
				Name:    "task01",
				Depends: map[string]*types.RunConfigTaskDepend{},
				Runtime: &types.Runtime{Type: types.RuntimeType("pod"),
					Containers: []*types.Container{{Image: "image01"}},
				},
				Environment: map[string]string{},
				Steps:       []interface{}{},
				Skip:        false,
			},
			outuuid("task02"): &types.RunConfigTask{
				ID:   outuuid("task02"),
				Name: "task02",
				Depends: map[string]*types.RunConfigTaskDepend{
					outuuid("task01"): &types.RunConfigTaskDepend{TaskID: outuuid("task01"), Conditions: []types.RunConfigTaskDependCondition{types.RunConfigTaskDependConditionOnSuccess}},
				},
				Runtime: &types.Runtime{Type: types.RuntimeType("pod"),
					Containers: []*types.Container{{Image: "image01"}},
				},
				Environment: map[string]string{},
				Steps:       []interface{}{},
				Skip:        false,
			},
			outuuid("task03"): &types.RunConfigTask{
				ID:      outuuid("task03"),
				Name:    "task03",
				Depends: map[string]*types.RunConfigTaskDepend{},
				Runtime: &types.Runtime{Type: types.RuntimeType("pod"),
					Containers: []*types.Container{{Image: "image01"}},
				},
				Environment: map[string]string{},
				Steps:       []interface{}{},
				Skip:        false,
			},
			outuuid("task04"): &types.RunConfigTask{
				ID:   outuuid("task04"),
				Name: "task04",
				Runtime: &types.Runtime{Type: types.RuntimeType("pod"),
					Containers: []*types.Container{{Image: "image01"}},
				},
				Environment: map[string]string{},
				Steps:       []interface{}{},
				Skip:        false,
			},
			outuuid("task05"): &types.RunConfigTask{
				ID:   outuuid("task05"),
				Name: "task05",
				Depends: map[string]*types.RunConfigTaskDepend{
					outuuid("task03"): &types.RunConfigTaskDepend{TaskID: outuuid("task03"), Conditions: []types.RunConfigTaskDependCondition{types.RunConfigTaskDependConditionOnSuccess}},
					outuuid("task04"): &types.RunConfigTaskDepend{TaskID: outuuid("task04"), Conditions: []types.RunConfigTaskDependCondition{types.RunConfigTaskDependConditionOnSuccess}},
				},
				Runtime: &types.Runtime{Type: types.RuntimeType("pod"),
					Containers: []*types.Container{{Image: "image01"}},
				},
				Environment: map[string]string{},
				Steps:       []interface{}{},
				Skip:        false,
			},
		},
	}

	// initial run that matched the runconfig, all tasks are not started or skipped
	// (if the runconfig task as Skip == true). This must match the status
	// generated by command.genRun()
	run := genRun(rc)
	outrun := genRun(outrc)

	tests := []struct {
		name  string
		rc    *types.RunConfig
		r     *types.Run
		req   *RunCreateRequest
		outrc *types.RunConfig
		outr  *types.Run
		err   error
	}{
		{
			name:  "test recreate run from start with all not start tasks",
			rc:    rc.DeepCopy(),
			r:     run.DeepCopy(),
			outrc: outrc.DeepCopy(),
			outr:  outrun.DeepCopy(),
			req:   &RunCreateRequest{FromStart: true},
		},
		{
			name:  "test recreate run from failed tasks with all not start tasks",
			rc:    rc.DeepCopy(),
			r:     run.DeepCopy(),
			outrc: outrc.DeepCopy(),
			outr:  outrun.DeepCopy(),
			req:   &RunCreateRequest{FromStart: false},
		},
		{
			name: "test recreate run from start tasks with task01 failed and child task02 successful (should recreate all tasks)",
			rc:   rc.DeepCopy(),
			r: func() *types.Run {
				run := run.DeepCopy()
				run.RunTasks[inuuid("task01")].Status = types.RunTaskStatusFailed
				run.RunTasks[inuuid("task02")].Status = types.RunTaskStatusSuccess
				run.RunTasks[inuuid("task03")].Status = types.RunTaskStatusSuccess
				run.RunTasks[inuuid("task04")].Status = types.RunTaskStatusSuccess
				run.RunTasks[inuuid("task05")].Status = types.RunTaskStatusSuccess
				return run
			}(),
			outrc: outrc.DeepCopy(),
			outr:  outrun.DeepCopy(),
			req:   &RunCreateRequest{FromStart: true},
		},
		{
			name: "test recreate run from failed tasks with task01 failed and child task02 successful (should recreate task01 and task02)",
			rc:   rc.DeepCopy(),
			r: func() *types.Run {
				run := run.DeepCopy()
				run.RunTasks[inuuid("task01")].Status = types.RunTaskStatusFailed
				run.RunTasks[inuuid("task02")].Status = types.RunTaskStatusSuccess
				run.RunTasks[inuuid("task03")].Status = types.RunTaskStatusSuccess
				run.RunTasks[inuuid("task04")].Status = types.RunTaskStatusSuccess
				run.RunTasks[inuuid("task05")].Status = types.RunTaskStatusSuccess
				return run
			}(),
			// task01 and task02 recreated
			outrc: func() *types.RunConfig {
				rc := rc.DeepCopy()
				outrc := outrc.DeepCopy()

				nrc := rc.DeepCopy()
				nrc.ID = outuuid("new")
				nrc.Tasks = map[string]*types.RunConfigTask{
					outuuid("task01"): outrc.Tasks[outuuid("task01")],
					outuuid("task02"): outrc.Tasks[outuuid("task02")],
					inuuid("task03"):  rc.Tasks[inuuid("task03")],
					inuuid("task04"):  rc.Tasks[inuuid("task04")],
					inuuid("task05"):  rc.Tasks[inuuid("task05")],
				}
				return nrc
			}(),
			// task01 and task02 recreated and status reset to NotStarted
			outr: func() *types.Run {
				run := run.DeepCopy()
				outrun := outrun.DeepCopy()
				nrun := run.DeepCopy()
				nrun.ID = outuuid("new")
				nrun.RunTasks = map[string]*types.RunTask{
					outuuid("task01"): outrun.RunTasks[outuuid("task01")],
					outuuid("task02"): outrun.RunTasks[outuuid("task02")],
					inuuid("task03"):  run.RunTasks[inuuid("task03")],
					inuuid("task04"):  run.RunTasks[inuuid("task04")],
					inuuid("task05"):  run.RunTasks[inuuid("task05")],
				}

				nrun.RunTasks[inuuid("task03")].Status = types.RunTaskStatusSuccess
				nrun.RunTasks[inuuid("task04")].Status = types.RunTaskStatusSuccess
				nrun.RunTasks[inuuid("task05")].Status = types.RunTaskStatusSuccess

				return nrun
			}(),
			req: &RunCreateRequest{FromStart: false},
		},
	}

	u := &util.TestPrefixUUIDGenerator{Prefix: "out"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newID := outuuid("new")
			rb := recreateRun(u, tt.r, tt.rc, newID, tt.req)
			if diff := cmp.Diff(tt.outrc, rb.Rc); diff != "" {
				t.Error(diff)
			}
			if diff := cmp.Diff(tt.outr, rb.Run); diff != "" {
				t.Error(diff)
			}
		})
	}
}
