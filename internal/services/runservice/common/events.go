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
	"agola.io/agola/internal/services/runservice/db"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/services/runservice/types"
)

func NewRunEvent(d *db.DB, tx *sql.Tx, run *types.Run, runConfig *types.RunConfig, runEventType types.RunEventType) (*types.RunEvent, error) {
	runEvent := types.NewRunEvent(tx)
	runEvent.RunID = run.ID
	runEvent.Phase = run.Phase
	runEvent.Result = run.Result
	runEvent.RunEventType = runEventType
	runEvent.DataVersion = types.RunEventDataVersion

	data := &types.RunEventData{}

	data.ID = run.ID
	data.Name = run.Name
	data.Counter = run.Counter
	data.SetupErrors = runConfig.SetupErrors
	data.Phase = string(run.Phase)
	data.Result = string(run.Result)
	data.StartTime = run.StartTime
	data.EndTime = run.EndTime
	data.EnqueueTime = run.EnqueueTime
	data.Annotations = run.Annotations

	data.Tasks = make(map[string]*types.RunEventDataRunTask)
	for id, t := range run.Tasks {
		task := &types.RunEventDataRunTask{}
		task.ID = t.ID
		task.Name = runConfig.Tasks[id].Name
		task.Level = runConfig.Tasks[id].Level
		task.Depends = make(map[string]*types.RunEventDataRunTaskDepend)
		for tdID, td := range runConfig.Tasks[id].Depends {
			taskDepend := &types.RunEventDataRunTaskDepend{
				TaskID:     td.TaskID,
				Conditions: make([]string, len(td.Conditions)),
			}
			for i, c := range td.Conditions {
				taskDepend.Conditions[i] = string(c)
			}
			task.Depends[tdID] = taskDepend
		}
		task.Status = string(t.Status)
		task.Timedout = t.Timedout
		task.Skip = t.Skip
		task.WaitingApproval = t.WaitingApproval
		task.Approved = t.Approved
		task.StartTime = t.StartTime
		task.EndTime = t.EndTime
		task.SetupStep = types.RunEventDataRunTaskStep{
			Phase:      string(t.SetupStep.Phase),
			ExitStatus: t.SetupStep.ExitStatus,
			StartTime:  t.SetupStep.StartTime,
			EndTime:    t.SetupStep.EndTime,
		}

		steps := make([]*types.RunEventDataRunTaskStep, len(t.Steps))
		for i, s := range t.Steps {
			step := &types.RunEventDataRunTaskStep{
				Phase:      string(s.Phase),
				ExitStatus: s.ExitStatus,
				StartTime:  s.StartTime,
				EndTime:    s.EndTime,
			}
			steps[i] = step
		}
		task.Steps = steps

		data.Tasks[id] = task
	}

	runEvent.Data = data

	return runEvent, nil
}
