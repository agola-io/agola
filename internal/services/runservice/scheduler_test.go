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

package runservice

import (
	"context"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/sorintlab/agola/internal/services/runservice/types"
)

func TestAdvanceRunTasks(t *testing.T) {
	// a global run config for all tests
	rc := &types.RunConfig{
		Tasks: map[string]*types.RunConfigTask{
			"task01": &types.RunConfigTask{
				ID:      "task01",
				Name:    "task01",
				Depends: map[string]*types.RunConfigTaskDepend{},
				Runtime: &types.Runtime{Type: types.RuntimeType("pod"),
					Containers: []*types.Container{{Image: "image01"}},
				},
				Environment: map[string]string{},
				Steps:       []interface{}{},
				Skip:        false,
			},
			"task02": &types.RunConfigTask{
				ID:   "task02",
				Name: "task02",
				Depends: map[string]*types.RunConfigTaskDepend{
					"task01": &types.RunConfigTaskDepend{TaskID: "task01", Conditions: []types.RunConfigTaskDependCondition{types.RunConfigTaskDependConditionOnSuccess}},
				},
				Runtime: &types.Runtime{Type: types.RuntimeType("pod"),
					Containers: []*types.Container{{Image: "image01"}},
				},
				Environment: map[string]string{},
				Steps:       []interface{}{},
				Skip:        false,
			},
			"task03": &types.RunConfigTask{
				ID:      "task03",
				Name:    "task03",
				Depends: map[string]*types.RunConfigTaskDepend{},
				Runtime: &types.Runtime{Type: types.RuntimeType("pod"),
					Containers: []*types.Container{{Image: "image01"}},
				},
				Environment: map[string]string{},
				Steps:       []interface{}{},
				Skip:        false,
			},
			"task04": &types.RunConfigTask{
				ID:   "task04",
				Name: "task04",
				Runtime: &types.Runtime{Type: types.RuntimeType("pod"),
					Containers: []*types.Container{{Image: "image01"}},
				},
				Environment: map[string]string{},
				Steps:       []interface{}{},
				Skip:        false,
			},
			"task05": &types.RunConfigTask{
				ID:   "task05",
				Name: "task05",
				Depends: map[string]*types.RunConfigTaskDepend{
					"task03": &types.RunConfigTaskDepend{TaskID: "task03", Conditions: []types.RunConfigTaskDependCondition{types.RunConfigTaskDependConditionOnSuccess}},
					"task04": &types.RunConfigTaskDepend{TaskID: "task04", Conditions: []types.RunConfigTaskDependCondition{types.RunConfigTaskDependConditionOnSuccess}},
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

	// initial run that matched the runconfig:
	// * the run is in phase running with result unknown
	// * all tasks are not started or skipped
	// (if the runconfig task as Skip == true). This must match the status
	// generated by command.genRun()
	run := &types.Run{
		Phase:  types.RunPhaseRunning,
		Result: types.RunResultUnknown,
		Tasks: map[string]*types.RunTask{
			"task01": &types.RunTask{
				ID:     "task01",
				Status: types.RunTaskStatusNotStarted,
			},
			"task02": &types.RunTask{
				ID:     "task02",
				Status: types.RunTaskStatusNotStarted,
			},
			"task03": &types.RunTask{
				ID:     "task03",
				Status: types.RunTaskStatusNotStarted,
			},
			"task04": &types.RunTask{
				ID:     "task04",
				Status: types.RunTaskStatusNotStarted,
			},
			"task05": &types.RunTask{
				ID:     "task05",
				Status: types.RunTaskStatusNotStarted,
			},
		},
	}

	tests := []struct {
		name                string
		rc                  *types.RunConfig
		r                   *types.Run
		activeExecutorTasks []*types.ExecutorTask
		out                 *types.Run
		err                 error
	}{
		{
			name: "test top level task not started",
			rc:   rc,
			r:    run.DeepCopy(),
			out:  run.DeepCopy(),
		},
		{
			name: "test task status set to skipped when parent status is skipped",
			rc: func() *types.RunConfig {
				rc := rc.DeepCopy()
				rc.Tasks["task01"].Skip = true
				return rc
			}(),
			r: func() *types.Run {
				run := run.DeepCopy()
				run.Tasks["task01"].Status = types.RunTaskStatusSkipped
				return run
			}(),
			out: func() *types.Run {
				run := run.DeepCopy()
				run.Tasks["task01"].Status = types.RunTaskStatusSkipped
				run.Tasks["task02"].Status = types.RunTaskStatusSkipped
				return run
			}(),
		},
		{
			name: "test task status set to skipped when all parent status is skipped",
			rc: func() *types.RunConfig {
				rc := rc.DeepCopy()
				rc.Tasks["task03"].Skip = true
				rc.Tasks["task04"].Skip = true
				return rc
			}(),
			r: func() *types.Run {
				run := run.DeepCopy()
				run.Tasks["task03"].Status = types.RunTaskStatusSkipped
				run.Tasks["task04"].Status = types.RunTaskStatusSkipped
				return run
			}(),
			out: func() *types.Run {
				run := run.DeepCopy()
				run.Tasks["task03"].Status = types.RunTaskStatusSkipped
				run.Tasks["task04"].Status = types.RunTaskStatusSkipped
				run.Tasks["task05"].Status = types.RunTaskStatusSkipped
				return run
			}(),
		},
		{
			name: "test task set to skipped when only some parents status is skipped",
			rc: func() *types.RunConfig {
				rc := rc.DeepCopy()
				rc.Tasks["task03"].Skip = true
				return rc
			}(),
			r: func() *types.Run {
				run := run.DeepCopy()
				run.Tasks["task03"].Status = types.RunTaskStatusSkipped
				run.Tasks["task04"].Status = types.RunTaskStatusSuccess
				return run
			}(),
			out: func() *types.Run {
				run := run.DeepCopy()
				run.Tasks["task03"].Status = types.RunTaskStatusSkipped
				run.Tasks["task04"].Status = types.RunTaskStatusSuccess
				run.Tasks["task05"].Status = types.RunTaskStatusSkipped
				return run
			}(),
		},
		{
			name: "test task set to skipped when one of the parents doesn't match default conditions (on_success)",
			rc: func() *types.RunConfig {
				rc := rc.DeepCopy()
				rc.Tasks["task03"].Skip = true
				return rc
			}(),
			r: func() *types.Run {
				run := run.DeepCopy()
				run.Tasks["task03"].Status = types.RunTaskStatusSkipped
				run.Tasks["task04"].Status = types.RunTaskStatusSuccess
				return run
			}(),
			out: func() *types.Run {
				run := run.DeepCopy()
				run.Tasks["task03"].Status = types.RunTaskStatusSkipped
				run.Tasks["task04"].Status = types.RunTaskStatusSuccess
				run.Tasks["task05"].Status = types.RunTaskStatusSkipped
				return run
			}(),
		},
		{
			name: "test task set to skipped when one of the parents doesn't match custom conditions",
			rc: func() *types.RunConfig {
				rc := rc.DeepCopy()
				rc.Tasks["task03"].Skip = true
				rc.Tasks["task05"].Depends["task03"].Conditions = []types.RunConfigTaskDependCondition{types.RunConfigTaskDependConditionOnFailure}
				return rc
			}(),
			r: func() *types.Run {
				run := run.DeepCopy()
				run.Tasks["task03"].Status = types.RunTaskStatusSkipped
				run.Tasks["task04"].Status = types.RunTaskStatusSuccess
				return run
			}(),
			out: func() *types.Run {
				run := run.DeepCopy()
				run.Tasks["task03"].Status = types.RunTaskStatusSkipped
				run.Tasks["task04"].Status = types.RunTaskStatusSuccess
				run.Tasks["task05"].Status = types.RunTaskStatusSkipped
				return run
			}(),
		},
		{
			name: "test task set to not skipped when one of the parent is skipped and task condition is on_skipped",
			rc: func() *types.RunConfig {
				rc := rc.DeepCopy()
				rc.Tasks["task03"].Skip = true
				rc.Tasks["task05"].Depends["task03"].Conditions = []types.RunConfigTaskDependCondition{types.RunConfigTaskDependConditionOnSkipped}
				return rc
			}(),
			r: func() *types.Run {
				run := run.DeepCopy()
				run.Tasks["task03"].Status = types.RunTaskStatusSkipped
				run.Tasks["task04"].Status = types.RunTaskStatusSuccess
				return run
			}(),
			out: func() *types.Run {
				run := run.DeepCopy()
				run.Tasks["task03"].Status = types.RunTaskStatusSkipped
				run.Tasks["task04"].Status = types.RunTaskStatusSuccess
				return run
			}(),
		},
		{
			name: "test task not set to waiting approval when task is skipped",
			rc: func() *types.RunConfig {
				rc := rc.DeepCopy()
				rc.Tasks["task03"].Skip = true
				rc.Tasks["task05"].NeedsApproval = true
				return rc
			}(),
			r: func() *types.Run {
				run := run.DeepCopy()
				run.Tasks["task03"].Status = types.RunTaskStatusSkipped
				run.Tasks["task04"].Status = types.RunTaskStatusSuccess
				return run
			}(),
			out: func() *types.Run {
				run := run.DeepCopy()
				run.Tasks["task03"].Status = types.RunTaskStatusSkipped
				run.Tasks["task04"].Status = types.RunTaskStatusSuccess
				run.Tasks["task05"].Status = types.RunTaskStatusSkipped
				return run
			}(),
		},
		{
			name: "test task set to waiting approval when all the parents are finished and task is not skipped",
			rc: func() *types.RunConfig {
				rc := rc.DeepCopy()
				rc.Tasks["task03"].Skip = true
				rc.Tasks["task05"].NeedsApproval = true
				rc.Tasks["task05"].Depends["task03"].Conditions = []types.RunConfigTaskDependCondition{types.RunConfigTaskDependConditionOnSkipped}
				return rc
			}(),
			r: func() *types.Run {
				run := run.DeepCopy()
				run.Tasks["task03"].Status = types.RunTaskStatusSkipped
				run.Tasks["task04"].Status = types.RunTaskStatusSuccess
				return run
			}(),
			out: func() *types.Run {
				run := run.DeepCopy()
				run.Tasks["task03"].Status = types.RunTaskStatusSkipped
				run.Tasks["task04"].Status = types.RunTaskStatusSuccess
				run.Tasks["task05"].WaitingApproval = true
				return run
			}(),
		},
		{
			name: "cancel all root not started tasks when run has a result set",
			rc: func() *types.RunConfig {
				rc := rc.DeepCopy()
				return rc
			}(),
			r: func() *types.Run {
				run := run.DeepCopy()
				run.Result = types.RunResultSuccess
				run.Tasks["task04"].Status = types.RunTaskStatusSuccess
				return run
			}(),
			out: func() *types.Run {
				run := run.DeepCopy()
				run.Result = types.RunResultSuccess
				run.Tasks["task01"].Status = types.RunTaskStatusCancelled
				run.Tasks["task02"].Status = types.RunTaskStatusNotStarted
				run.Tasks["task03"].Status = types.RunTaskStatusCancelled
				run.Tasks["task04"].Status = types.RunTaskStatusSuccess
				run.Tasks["task05"].Status = types.RunTaskStatusNotStarted
				return run
			}(),
		},
		{
			name: "cancel all root not started tasks when run has a result set (task01 is already scheduled)",
			rc: func() *types.RunConfig {
				rc := rc.DeepCopy()
				return rc
			}(),
			r: func() *types.Run {
				run := run.DeepCopy()
				run.Result = types.RunResultSuccess
				run.Tasks["task04"].Status = types.RunTaskStatusSuccess
				return run
			}(),
			activeExecutorTasks: []*types.ExecutorTask{
				&types.ExecutorTask{ID: "task01"},
			},
			out: func() *types.Run {
				run := run.DeepCopy()
				run.Result = types.RunResultSuccess
				run.Tasks["task01"].Status = types.RunTaskStatusNotStarted
				run.Tasks["task02"].Status = types.RunTaskStatusNotStarted
				run.Tasks["task03"].Status = types.RunTaskStatusCancelled
				run.Tasks["task04"].Status = types.RunTaskStatusSuccess
				run.Tasks["task05"].Status = types.RunTaskStatusNotStarted
				return run
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			r, err := advanceRunTasks(ctx, tt.r, tt.rc, tt.activeExecutorTasks)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.out, r); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestGetTasksToRun(t *testing.T) {
	// a global run config for all tests
	rc := &types.RunConfig{
		Tasks: map[string]*types.RunConfigTask{
			"task01": &types.RunConfigTask{
				ID:      "task01",
				Name:    "task01",
				Depends: map[string]*types.RunConfigTaskDepend{},
				Runtime: &types.Runtime{Type: types.RuntimeType("pod"),
					Containers: []*types.Container{{Image: "image01"}},
				},
				Environment: map[string]string{},
				Steps:       []interface{}{},
				Skip:        false,
			},
			"task02": &types.RunConfigTask{
				ID:   "task02",
				Name: "task02",
				Depends: map[string]*types.RunConfigTaskDepend{
					"task01": &types.RunConfigTaskDepend{TaskID: "task01", Conditions: []types.RunConfigTaskDependCondition{types.RunConfigTaskDependConditionOnSuccess}},
				},
				Runtime: &types.Runtime{Type: types.RuntimeType("pod"),
					Containers: []*types.Container{{Image: "image01"}},
				},
				Environment: map[string]string{},
				Steps:       []interface{}{},
				Skip:        false,
			},
			"task03": &types.RunConfigTask{
				ID:      "task03",
				Name:    "task03",
				Depends: map[string]*types.RunConfigTaskDepend{},
				Runtime: &types.Runtime{Type: types.RuntimeType("pod"),
					Containers: []*types.Container{{Image: "image01"}},
				},
				Environment: map[string]string{},
				Steps:       []interface{}{},
				Skip:        false,
			},
			"task04": &types.RunConfigTask{
				ID:   "task04",
				Name: "task04",
				Runtime: &types.Runtime{Type: types.RuntimeType("pod"),
					Containers: []*types.Container{{Image: "image01"}},
				},
				Environment: map[string]string{},
				Steps:       []interface{}{},
				Skip:        false,
			},
			"task05": &types.RunConfigTask{
				ID:   "task05",
				Name: "task05",
				Depends: map[string]*types.RunConfigTaskDepend{
					"task03": &types.RunConfigTaskDepend{TaskID: "task03", Conditions: []types.RunConfigTaskDependCondition{types.RunConfigTaskDependConditionOnSuccess}},
					"task04": &types.RunConfigTaskDepend{TaskID: "task04", Conditions: []types.RunConfigTaskDependCondition{types.RunConfigTaskDependConditionOnSuccess}},
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
	run := &types.Run{
		Tasks: map[string]*types.RunTask{
			"task01": &types.RunTask{
				ID:     "task01",
				Status: types.RunTaskStatusNotStarted,
			},
			"task02": &types.RunTask{
				ID:     "task02",
				Status: types.RunTaskStatusNotStarted,
			},
			"task03": &types.RunTask{
				ID:     "task03",
				Status: types.RunTaskStatusNotStarted,
			},
			"task04": &types.RunTask{
				ID:     "task04",
				Status: types.RunTaskStatusNotStarted,
			},
			"task05": &types.RunTask{
				ID:     "task05",
				Status: types.RunTaskStatusNotStarted,
			},
		},
	}

	tests := []struct {
		name string
		rc   *types.RunConfig
		r    *types.Run
		out  []string
		err  error
	}{
		{
			name: "test run top level tasks",
			rc:   rc,
			r:    run.DeepCopy(),
			out:  []string{"task01", "task03", "task04"},
		},
		{
			name: "test don't run skipped tasks",
			rc: func() *types.RunConfig {
				rc := rc.DeepCopy()
				rc.Tasks["task01"].Skip = true
				return rc
			}(),
			r: func() *types.Run {
				run := run.DeepCopy()
				run.Tasks["task01"].Status = types.RunTaskStatusSkipped
				run.Tasks["task02"].Status = types.RunTaskStatusSkipped
				return run
			}(),
			out: []string{"task03", "task04"},
		},
		{
			name: "test don't run if needs approval but not approved",
			rc: func() *types.RunConfig {
				rc := rc.DeepCopy()
				rc.Tasks["task01"].NeedsApproval = true
				return rc
			}(),
			r:   run.DeepCopy(),
			out: []string{"task03", "task04"},
		},
		{
			name: "test run if needs approval and approved",
			rc: func() *types.RunConfig {
				rc := rc.DeepCopy()
				rc.Tasks["task01"].NeedsApproval = true
				return rc
			}(),
			r: func() *types.Run {
				run := run.DeepCopy()
				run.Tasks["task01"].Approved = true
				return run
			}(),
			out: []string{"task01", "task03", "task04"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			tasks, err := getTasksToRun(ctx, tt.r, tt.rc)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			outTasks := []string{}
			for _, t := range tasks {
				outTasks = append(outTasks, t.ID)
			}
			sort.Sort(sort.StringSlice(tt.out))
			sort.Sort(sort.StringSlice(outTasks))

			if diff := cmp.Diff(tt.out, outTasks); diff != "" {
				t.Error(diff)
			}
		})
	}
}