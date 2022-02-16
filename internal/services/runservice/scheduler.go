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

package runservice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/objectstorage"
	"agola.io/agola/internal/runconfig"
	"agola.io/agola/internal/services/runservice/common"
	"agola.io/agola/internal/services/runservice/store"
	"agola.io/agola/internal/sql"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/runservice/types"

	"github.com/rs/zerolog"
)

const (
	changeGroupCompactorInterval = 1 * time.Minute
	cacheCleanerInterval         = 1 * 24 * time.Hour
	workspaceCleanerInterval     = 1 * 24 * time.Hour

	defaultExecutorNotAliveInterval = 60 * time.Second

	changeGroupMinDuration = 5 * time.Minute
)

func taskMatchesParentDependCondition(rt *types.RunTask, r *types.Run, rc *types.RunConfig) bool {
	rct := rc.Tasks[rt.ID]
	parents := runconfig.GetParents(rc.Tasks, rct)

	matchedNum := 0
	for _, p := range parents {
		matched := false
		rp := r.Tasks[p.ID]
		conds := runconfig.GetParentDependConditions(rct, p)
		for _, cond := range conds {
			switch cond {
			case types.RunConfigTaskDependConditionOnSuccess:
				if rp.Status == types.RunTaskStatusSuccess {
					matched = true
				}
			case types.RunConfigTaskDependConditionOnFailure:
				if rp.Status == types.RunTaskStatusFailed {
					matched = true
				}
			case types.RunConfigTaskDependConditionOnSkipped:
				if rp.Status == types.RunTaskStatusSkipped {
					matched = true
				}
			}
		}
		if matched {
			matchedNum++
		}
	}

	return len(parents) == matchedNum
}

func advanceRunTasks(log zerolog.Logger, curRun *types.Run, rc *types.RunConfig, scheduledExecutorTasks []*types.ExecutorTask) (*types.Run, error) {
	log.Debug().Msgf("run: %s", util.Dump(curRun))
	log.Debug().Msgf("rc: %s", util.Dump(rc))

	// take a deepcopy of r so we do logic only on fixed status and not affected by current changes (due to random map iteration)
	newRun := curRun.DeepCopy()

	if newRun.Stop {
		// if the run is set to stop, skip all not running tasks
		for _, rt := range newRun.Tasks {
			isScheduled := false
			for _, et := range scheduledExecutorTasks {
				if rt.ID == et.Spec.RunTaskID {
					isScheduled = true
				}
			}
			if isScheduled {
				continue
			}
			if rt.Status == types.RunTaskStatusNotStarted {
				rt.Status = types.RunTaskStatusSkipped
			}
		}
	}

	// handle root tasks
	for _, rt := range newRun.Tasks {
		if rt.Skip {
			continue
		}
		if rt.Status != types.RunTaskStatusNotStarted {
			continue
		}

		rct := rc.Tasks[rt.ID]
		parents := runconfig.GetParents(rc.Tasks, rct)
		if len(parents) > 0 {
			continue
		}

		// cancel task if the run has a result set and is not yet scheduled
		if curRun.Result.IsSet() {
			isScheduled := false
			for _, et := range scheduledExecutorTasks {
				if rt.ID == et.Spec.RunTaskID {
					isScheduled = true
				}
			}
			if isScheduled {
				continue
			}

			if rt.Status == types.RunTaskStatusNotStarted {
				rt.Status = types.RunTaskStatusCancelled
			}
		}
	}

	// handle all tasks
	// TODO(sgotti) process tasks by their level (from 0) so we'll calculate the
	// final state in just one loop. Currently the call to this function won't
	// calculate a deterministic final state since we could process the tasks in
	// any order
	for _, rt := range newRun.Tasks {
		if rt.Skip {
			continue
		}
		if rt.Status != types.RunTaskStatusNotStarted {
			continue
		}

		rct := rc.Tasks[rt.ID]
		parents := runconfig.GetParents(rc.Tasks, rct)
		finishedParents := 0
		for _, p := range parents {
			// use current run status to not be affected by previous changes to to random map iteration
			rp := curRun.Tasks[p.ID]
			if rp.Status.IsFinished() && rp.ArchivesFetchFinished() {
				finishedParents++
			}
		}

		allParentsFinished := finishedParents == len(parents)

		// if all parents are finished check if the task could be executed or be skipped
		if allParentsFinished {
			matched := taskMatchesParentDependCondition(rt, curRun, rc)

			// if all parents are matched then we can start it, otherwise we mark the step to be skipped
			skip := !matched
			if skip {
				rt.Status = types.RunTaskStatusSkipped
				continue
			}

			// now that the task can run set it to waiting approval if needed
			if rct.NeedsApproval && !rt.WaitingApproval && !rt.Approved {
				rt.WaitingApproval = true
			}
		}
	}

	return newRun, nil
}

func getTasksToRun(log zerolog.Logger, r *types.Run, rc *types.RunConfig) ([]*types.RunTask, error) {
	log.Debug().Msgf("run: %s", util.Dump(r))
	log.Debug().Msgf("rc: %s", util.Dump(rc))

	tasksToRun := []*types.RunTask{}
	// get tasks that can be executed
	for _, rt := range r.Tasks {
		if rt.Skip {
			continue
		}
		if rt.Status != types.RunTaskStatusNotStarted {
			continue
		}

		rct := rc.Tasks[rt.ID]
		parents := runconfig.GetParents(rc.Tasks, rct)
		finishedParents := 0
		for _, p := range parents {
			rp := r.Tasks[p.ID]
			if rp.Status.IsFinished() && rp.ArchivesFetchFinished() {
				finishedParents++
			}
		}

		allParentsFinished := finishedParents == len(parents)

		if allParentsFinished {
			// TODO(sgotti) This could be removed when advanceRunTasks will calculate the
			// state in a deterministic a complete way in one loop (see the related TODO)
			if !taskMatchesParentDependCondition(rt, r, rc) {
				continue
			}

			// Run only if approved (when needs approval)
			if !rct.NeedsApproval || (rct.NeedsApproval && rt.Approved) {
				tasksToRun = append(tasksToRun, rt)
			}
		}
	}

	return tasksToRun, nil
}

func (s *Runservice) submitRunTasks(ctx context.Context, r *types.Run, rc *types.RunConfig, tasks []*types.RunTask) error {
	s.log.Debug().Msgf("tasksToRun: %s", util.Dump(tasks))

	for _, rt := range tasks {
		rct := rc.Tasks[rt.ID]

		// check that the executorTask for this runTask id wasn't already scheduled
		var executorTask *types.ExecutorTask
		err := s.d.Do(ctx, func(tx *sql.Tx) error {
			var err error

			executorTask, err = s.d.GetExecutorTaskByRunTask(tx, r.ID, rt.ID)
			if err != nil {
				return errors.WithStack(err)
			}

			return nil
		})
		if err != nil {
			return errors.WithStack(err)
		}

		if executorTask != nil {
			continue
		}

		executor, err := s.chooseExecutor(ctx, rct)
		if err != nil {
			return errors.WithStack(err)
		}
		if executor == nil {
			s.log.Warn().Msgf("cannot choose an executor")
			return nil
		}

		executorTask = common.GenExecutorTask(r, rt, rc, executor)
		s.log.Debug().Msgf("et: %s", util.Dump(executorTask))

		// check again that the executorTask for this runTask id wasn't already scheduled
		// if not existing, save and submit it
		var shouldSend bool
		err = s.d.Do(ctx, func(tx *sql.Tx) error {
			curExecutorTask, err := s.d.GetExecutorTaskByRunTask(tx, r.ID, rt.ID)
			if err != nil {
				return errors.WithStack(err)
			}

			if curExecutorTask != nil {
				return nil
			}

			if err := s.d.InsertExecutorTask(tx, executorTask); err != nil {
				return errors.WithStack(err)
			}

			shouldSend = true

			return nil
		})
		if err != nil {
			return errors.WithStack(err)
		}

		if shouldSend {
			if err := s.sendExecutorTask(ctx, executorTask); err != nil {
				return errors.WithStack(err)
			}
		}
	}

	return nil
}

// chooseExecutor chooses the executor to schedule the task on. Now it's a very simple/dumb selection
// TODO(sgotti) improve this to use executor statistic, labels (arch type) etc...
func (s *Runservice) chooseExecutor(ctx context.Context, rct *types.RunConfigTask) (*types.Executor, error) {
	var executors []*types.Executor
	executorTasksCount := map[string]int{}
	err := s.d.Do(ctx, func(tx *sql.Tx) error {
		var err error

		executors, err = s.d.GetExecutors(tx)
		if err != nil {
			return errors.WithStack(err)
		}

		// TODO(sgotti) implement a db method that just returns the count
		for _, executor := range executors {
			executorTasks, err := s.d.GetExecutorTasksByExecutor(tx, executor.ExecutorID)
			if err != nil {
				return errors.WithStack(err)
			}

			executorTasksCount[executor.ExecutorID] = len(executorTasks)
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return chooseExecutor(executors, executorTasksCount, rct), nil
}

func chooseExecutor(executors []*types.Executor, executorTasksCount map[string]int, rct *types.RunConfigTask) *types.Executor {
	requiresPrivilegedContainers := false
	for _, c := range rct.Runtime.Containers {
		if c.Privileged {
			requiresPrivilegedContainers = true
			break
		}
	}

	for _, e := range executors {
		if time.Since(e.UpdateTime) > defaultExecutorNotAliveInterval {
			continue
		}

		// skip executor provileged containers are required but not allowed
		if requiresPrivilegedContainers && !e.AllowPrivilegedContainers {
			continue
		}

		// if arch is not defined use any executor arch
		if rct.Runtime.Arch != "" {
			hasArch := false
			for _, arch := range e.Archs {
				if arch == rct.Runtime.Arch {
					hasArch = true
				}
			}
			if !hasArch {
				continue
			}
		}

		if e.ActiveTasksLimit != 0 {
			// will be 0 when executorTasksCount[e.ExecutorID] doesn't exist
			activeTasks := executorTasksCount[e.ExecutorID]
			if e.ActiveTasks > activeTasks {
				activeTasks = e.ActiveTasks
			}
			// calculate the active tasks by the max between the current scheduled
			// tasks in the store and the executor reported tasks
			if activeTasks >= e.ActiveTasksLimit {
				continue
			}
		}

		return e
	}

	return nil
}

// sendExecutorTask sends executor task to executor, if this fails the executor
// will periodically fetch the executortask anyway
func (s *Runservice) sendExecutorTask(ctx context.Context, et *types.ExecutorTask) error {
	var executor *types.Executor
	var r *types.Run
	var rc *types.RunConfig
	err := s.d.Do(ctx, func(tx *sql.Tx) error {
		var err error

		executor, err = s.d.GetExecutorByExecutorID(tx, et.Spec.ExecutorID)
		if err != nil {
			return errors.WithStack(err)
		}

		r, err = s.d.GetRun(tx, et.Spec.RunID)
		if err != nil {
			return errors.WithStack(err)
		}

		if r == nil {
			return errors.Errorf("run with id %q doesn't exist", et.Spec.RunID)
		}

		rc, err = s.d.GetRunConfig(tx, r.RunConfigID)
		if err != nil {
			return errors.WithStack(err)
		}

		if rc == nil {
			return errors.Errorf("runconfig with id %q doesn't exist", r.RunConfigID)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	if executor == nil {
		s.log.Warn().Msgf("executor with id %q doesn't exist", et.Spec.ExecutorID)
		return nil
	}

	rt, ok := r.Tasks[et.Spec.RunTaskID]
	if !ok {
		return errors.Errorf("no such run task with id %s for run %s", et.Spec.RunTaskID, r.ID)
	}

	// take a copy to not change the input executorTask
	et = et.DeepCopy()

	// generate ExecutorTaskSpecData
	et.Spec.ExecutorTaskSpecData = common.GenExecutorTaskSpecData(r, rt, rc)

	etj, err := json.Marshal(et)
	if err != nil {
		return errors.WithStack(err)
	}

	req, err := http.Post(executor.ListenURL+"/api/v1alpha/executor", "", bytes.NewReader(etj))
	if err != nil {
		return errors.WithStack(err)
	}
	if req.StatusCode != http.StatusOK {
		return errors.Errorf("received http status: %d", req.StatusCode)
	}

	return nil
}

func (s *Runservice) compactChangeGroupsLoop(ctx context.Context) {
	for {
		if err := s.compactChangeGroups(ctx); err != nil {
			s.log.Err(err).Send()
		}
		sleepCh := time.NewTimer(changeGroupCompactorInterval).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
	}
}

func (s *Runservice) compactChangeGroups(ctx context.Context) error {
	// TODO(sgotti) do this in batches of N changegroups and/or filter by update time directly in the query
	err := s.d.Do(ctx, func(tx *sql.Tx) error {
		changeGroups, err := s.d.GetChangeGroups(tx)
		if err != nil {
			return errors.WithStack(err)
		}

		for _, changeGroup := range changeGroups {
			if time.Since(changeGroup.UpdateTime) < changeGroupMinDuration {
				continue
			}
			if err := s.d.DeleteChangeGroup(tx, changeGroup.ID); err != nil {
				return errors.WithStack(err)
			}
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (s *Runservice) scheduleRun(ctx context.Context, runID string) error {
	// we use multiple transactions to split the logic in multiple steps and
	// rely on optimistic object locking.
	// We could probably also use a single transaction without many issues
	// (perhaps more serializable transaction errors) since it should be quite
	// faster.
	var shouldSubmitRunTasks bool
	var etsToSend []*types.ExecutorTask

	var r *types.Run
	var rc *types.RunConfig
	var scheduledExecutorTasks []*types.ExecutorTask
	err := s.d.Do(ctx, func(tx *sql.Tx) error {
		var err error

		r, err = s.d.GetRun(tx, runID)
		if err != nil {
			return errors.WithStack(err)
		}

		if r == nil {
			return errors.Errorf("run with id %q doesn't exist", runID)
		}

		rc, err = s.d.GetRunConfig(tx, r.RunConfigID)
		if err != nil {
			return errors.WithStack(err)
		}

		if rc == nil {
			return errors.Errorf("runconfig with id %q doesn't exist", r.RunConfigID)
		}

		// the real source of active tasks is the number of executor tasks in the db
		// we can't rely on RunTask.Status since it's only updated when receiveing
		// updated from the executor so it could be in a NotStarted state but have an
		// executor tasks scheduled and running
		scheduledExecutorTasks, err = s.d.GetExecutorTasksByRun(tx, r.ID)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	s.log.Debug().Msgf("r: %s", util.Dump(r))

	prevPhase := r.Phase
	prevResult := r.Result

	if err := advanceRun(s.log, r, rc, scheduledExecutorTasks); err != nil {
		return errors.WithStack(err)
	}

	err = s.d.Do(ctx, func(tx *sql.Tx) error {
		// if the run is set to stop, stop all active tasks
		if r.Stop {
			for _, et := range scheduledExecutorTasks {
				et.Spec.Stop = true
				if err := s.d.UpdateExecutorTask(tx, et); err != nil {
					return errors.WithStack(err)
				}
				etsToSend = append(etsToSend, et)
			}
		}

		// advance tasks
		if r.Phase == types.RunPhaseRunning {
			r, err = advanceRunTasks(s.log, r, rc, scheduledExecutorTasks)
			if err != nil {
				return errors.WithStack(err)
			}

			shouldSubmitRunTasks = true
		}

		if err := s.d.UpdateRun(tx, r); err != nil {
			return errors.WithStack(err)
		}

		// detect changes to phase and result and set related events
		if prevPhase != r.Phase || prevResult != r.Result {
			runEvent, err := common.NewRunEvent(s.d, tx, r.ID, r.Phase, r.Result)
			if err != nil {
				return errors.WithStack(err)
			}
			if err := s.d.InsertRunEvent(tx, runEvent); err != nil {
				return errors.WithStack(err)
			}
		}
		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	for _, et := range etsToSend {
		if err := s.sendExecutorTask(ctx, et); err != nil {
			return errors.WithStack(err)
		}
	}
	if shouldSubmitRunTasks {
		tasksToRun, err := getTasksToRun(s.log, r, rc)
		if err != nil {
			return errors.WithStack(err)
		}

		if err := s.submitRunTasks(ctx, r, rc, tasksToRun); err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

// advanceRun updates the run result and phase. It must be the unique function that
// should update them.
func advanceRun(log zerolog.Logger, r *types.Run, rc *types.RunConfig, scheduledExecutorTasks []*types.ExecutorTask) error {
	log.Debug().Msgf("run: %s", util.Dump(r))
	hasScheduledTasks := len(scheduledExecutorTasks) > 0

	// fail run if a task is failed
	if !r.Result.IsSet() && r.Phase == types.RunPhaseRunning {
		for _, rt := range r.Tasks {
			rct, ok := rc.Tasks[rt.ID]
			log.Debug().Msgf("rct: %s", util.Dump(rct))
			if !ok {
				return errors.Errorf("no such run config task with id %s for run config %s", rt.ID, rc.ID)
			}
			if rt.Status == types.RunTaskStatusFailed {
				if !rct.IgnoreFailure {
					log.Debug().Msgf("marking run %q as failed is task %q is failed", r.ID, rt.ID)
					r.Result = types.RunResultFailed
					break
				}
			}
		}
	}

	// see if run could be marked as success
	if !r.Result.IsSet() && r.Phase == types.RunPhaseRunning {
		finished := true
		for _, rt := range r.Tasks {
			if !rt.Status.IsFinished() {
				finished = false
			}
		}
		if finished {
			r.Result = types.RunResultSuccess
			return nil
		}
	}

	// if run is set to stop set result as stopped
	if !r.Result.IsSet() && r.Phase == types.RunPhaseRunning {
		if r.Stop {
			r.Result = types.RunResultStopped
		}
	}

	// if the run has a result defined AND all tasks are finished AND there're no executor tasks scheduled we can mark
	// the run phase as finished
	if r.Result.IsSet() {
		finished := true
		for _, rt := range r.Tasks {
			if !rt.Status.IsFinished() {
				finished = false
			}
		}

		if finished && !r.Phase.IsFinished() {
			if !hasScheduledTasks {
				r.ChangePhase(types.RunPhaseFinished)
			}
		}

		// if the run is finished AND there're no executor tasks scheduled we can mark
		// all not started runtasks' fetch phases (setup step, logs and archives) as finished
		if r.Phase.IsFinished() {
			for _, rt := range r.Tasks {
				log.Debug().Msgf("rt: %s", util.Dump(rt))
				if rt.Status == types.RunTaskStatusNotStarted {
					rt.SetupStep.LogPhase = types.RunTaskFetchPhaseFinished
					for _, s := range rt.Steps {
						s.LogPhase = types.RunTaskFetchPhaseFinished
					}
					for i := range rt.WorkspaceArchivesPhase {
						rt.WorkspaceArchivesPhase[i] = types.RunTaskFetchPhaseFinished
					}
				}
			}
		}
	}

	return nil
}

func (s *Runservice) handleExecutorTaskUpdate(ctx context.Context, executorTaskID string) error {
	var r *types.Run
	err := s.d.Do(ctx, func(tx *sql.Tx) error {
		et, err := s.d.GetExecutorTask(tx, executorTaskID)
		if err != nil {
			return errors.WithStack(err)
		}

		if et == nil {
			return errors.Errorf("executor task with id %q doesn't exist", executorTaskID)
		}

		r, err = s.d.GetRun(tx, et.Spec.RunID)
		if err != nil {
			return errors.WithStack(err)
		}

		if r == nil {
			return errors.Errorf("run with id %q doesn't exist", et.Spec.RunID)
		}

		if err := s.updateRunTaskStatus(et, r); err != nil {
			return errors.WithStack(err)
		}

		if err = s.d.UpdateRun(tx, r); err != nil {
			return errors.WithStack(err)
		}
		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return s.scheduleRun(ctx, r.ID)
}

func (s *Runservice) updateRunTaskStatus(et *types.ExecutorTask, r *types.Run) error {
	s.log.Debug().Msgf("et: %s", util.Dump(et))

	rt, ok := r.Tasks[et.Spec.RunTaskID]
	if !ok {
		return errors.Errorf("no such run task with id %s for run %s", et.Spec.RunTaskID, r.ID)
	}

	rt.StartTime = et.Status.StartTime
	rt.EndTime = et.Status.EndTime

	wrongstatus := false
	switch et.Status.Phase {
	case types.ExecutorTaskPhaseNotStarted:
		if rt.Status != types.RunTaskStatusNotStarted {
			wrongstatus = true
		}
	case types.ExecutorTaskPhaseCancelled:
		if rt.Status != types.RunTaskStatusCancelled &&
			rt.Status != types.RunTaskStatusNotStarted {
			wrongstatus = true
		}
	case types.ExecutorTaskPhaseRunning:
		if rt.Status != types.RunTaskStatusRunning &&
			rt.Status != types.RunTaskStatusNotStarted {
			wrongstatus = true
		}
	case types.ExecutorTaskPhaseStopped:
		if rt.Status != types.RunTaskStatusStopped &&
			rt.Status != types.RunTaskStatusNotStarted &&
			rt.Status != types.RunTaskStatusRunning {
			wrongstatus = true
		}
	case types.ExecutorTaskPhaseSuccess:
		if rt.Status != types.RunTaskStatusSuccess &&
			rt.Status != types.RunTaskStatusNotStarted &&
			rt.Status != types.RunTaskStatusRunning {
			wrongstatus = true
		}
	case types.ExecutorTaskPhaseFailed:
		if rt.Status != types.RunTaskStatusFailed &&
			rt.Status != types.RunTaskStatusNotStarted &&
			rt.Status != types.RunTaskStatusRunning {
			wrongstatus = true
		}
	}
	if wrongstatus {
		s.log.Warn().Msgf("ignoring wrong executor task %q status: %q, rt status: %q", et.ID, et.Status.Phase, rt.Status)
		return nil
	}

	switch et.Status.Phase {
	case types.ExecutorTaskPhaseNotStarted:
		rt.Status = types.RunTaskStatusNotStarted
	case types.ExecutorTaskPhaseCancelled:
		rt.Status = types.RunTaskStatusCancelled
	case types.ExecutorTaskPhaseRunning:
		rt.Status = types.RunTaskStatusRunning
	case types.ExecutorTaskPhaseStopped:
		rt.Status = types.RunTaskStatusStopped
	case types.ExecutorTaskPhaseSuccess:
		rt.Status = types.RunTaskStatusSuccess
	case types.ExecutorTaskPhaseFailed:
		rt.Status = types.RunTaskStatusFailed
	}

	rt.SetupStep.Phase = et.Status.SetupStep.Phase
	rt.SetupStep.StartTime = et.Status.SetupStep.StartTime
	rt.SetupStep.EndTime = et.Status.SetupStep.EndTime

	for i, s := range et.Status.Steps {
		rt.Steps[i].Phase = s.Phase
		rt.Steps[i].ExitStatus = s.ExitStatus
		rt.Steps[i].StartTime = s.StartTime
		rt.Steps[i].EndTime = s.EndTime
	}

	return nil
}

func (s *Runservice) executorTaskUpdateHandler(ctx context.Context, c <-chan string) {
	for {
		select {
		case <-ctx.Done():
			return
		case etID := <-c:
			go func() {
				if err := s.handleExecutorTaskUpdate(ctx, etID); err != nil {
					// TODO(sgotti) improve logging to not return "run modified errors" since
					// they are normal
					s.log.Warn().Msgf("err: %+v", err)
				}
			}()
		}
	}
}

func (s *Runservice) executorTasksCleanerLoop(ctx context.Context) {
	for {
		s.log.Debug().Msgf("executorTasksCleaner")

		if err := s.executorTasksCleaner(ctx); err != nil {
			s.log.Err(err).Send()
		}

		sleepCh := time.NewTimer(1 * time.Second).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
	}
}

func (s *Runservice) executorTasksCleaner(ctx context.Context) error {
	// TODO(sgotti) use paged List or get only the executor tasks id
	var executorTasks []*types.ExecutorTask
	err := s.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		executorTasks, err = s.d.GetExecutorTasks(tx)
		if err != nil {
			return errors.WithStack(err)
		}
		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	for _, et := range executorTasks {
		if err := s.executorTaskCleaner(ctx, et.ID); err != nil {
			s.log.Err(err).Send()
		}
	}

	return nil
}

func (s *Runservice) executorTaskCleaner(ctx context.Context, executorTaskID string) error {
	var shouldSend bool

	var et *types.ExecutorTask
	err := s.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		et, err = s.d.GetExecutorTask(tx, executorTaskID)
		if err != nil {
			return errors.WithStack(err)
		}
		s.log.Debug().Msgf("et: %s", util.Dump(et))

		if et == nil {
			return nil
		}

		if et.Status.Phase.IsFinished() {
			r, err := s.d.GetRun(tx, et.Spec.RunID)
			if err != nil {
				return errors.WithStack(err)
			}
			if r == nil {
				// run doesn't exists, remove executor task
				s.log.Warn().Msgf("deleting executor task %q since run %q doesn't exist", et.ID, et.Spec.RunID)
				if err := s.d.DeleteExecutorTask(tx, et.ID); err != nil {
					s.log.Err(err).Send()
					return errors.WithStack(err)
				}
				return nil
			}

			if r.Phase.IsFinished() {
				// if the run is finished mark the executor tasks to stop
				if !et.Spec.Stop {
					et.Spec.Stop = true
					if err := s.d.UpdateExecutorTask(tx, et); err != nil {
						return errors.WithStack(err)
					}
					shouldSend = true
				}
			}
		}

		if !et.Status.Phase.IsFinished() {
			// if the executor doesn't exists anymore mark the not finished executor tasks as failed
			executor, err := s.d.GetExecutorByExecutorID(tx, et.Spec.ExecutorID)
			if err != nil {
				return errors.WithStack(err)
			}
			if executor == nil {
				s.log.Warn().Msgf("executor with id %q doesn't exist. marking executor task %q as failed", et.Spec.ExecutorID, et.ID)
				et.Status.FailError = "executor deleted"
				et.Status.Phase = types.ExecutorTaskPhaseFailed
				et.Status.EndTime = util.TimeP(time.Now())
				for _, s := range et.Status.Steps {
					if s.Phase == types.ExecutorTaskPhaseRunning {
						s.Phase = types.ExecutorTaskPhaseFailed
						s.EndTime = util.TimeP(time.Now())
					}
				}
				if err := s.d.UpdateExecutorTask(tx, et); err != nil {
					return errors.WithStack(err)
				}
			}
		}
		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	if shouldSend {
		if err := s.sendExecutorTask(ctx, et); err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

func (s *Runservice) runTasksUpdaterLoop(ctx context.Context) {
	for {
		s.log.Debug().Msgf("runTasksUpdater")

		if err := s.runTasksUpdater(ctx); err != nil {
			s.log.Err(err).Send()
		}

		sleepCh := time.NewTimer(10 * time.Second).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
	}
}

func (s *Runservice) runTasksUpdater(ctx context.Context) error {
	s.log.Debug().Msgf("runTasksUpdater")

	l := s.lf.NewLock(common.TaskUpdaterLockKey)
	if err := l.Lock(ctx); err != nil {
		return errors.Wrap(err, "failed to acquire task updater lock")
	}
	defer func() { _ = l.Unlock() }()

	// TODO(sgotti) use paged List or get only the executor tasks id
	var executorTasks []*types.ExecutorTask
	err := s.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		executorTasks, err = s.d.GetExecutorTasks(tx)
		if err != nil {
			return errors.WithStack(err)
		}
		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	for _, et := range executorTasks {
		if err := s.handleExecutorTaskUpdate(ctx, et.ID); err != nil {
			s.log.Err(err).Send()
		}
	}

	return nil
}

func (s *Runservice) OSTFileExists(path string) (bool, error) {
	_, err := s.ost.Stat(path)
	if err != nil && !objectstorage.IsNotExist(err) {
		return false, errors.WithStack(err)
	}
	return err == nil, nil
}

func (s *Runservice) fetchLog(ctx context.Context, runID string, rt *types.RunTask, setup bool, stepnum int) error {
	var et *types.ExecutorTask
	var executor *types.Executor
	err := s.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		et, err = s.d.GetExecutorTaskByRunTask(tx, runID, rt.ID)
		if err != nil {
			return errors.WithStack(err)
		}
		if et == nil {
			return nil
		}
		executor, err = s.d.GetExecutorByExecutorID(tx, et.Spec.ExecutorID)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	if et == nil {
		if rt.Status != types.RunTaskStatusSkipped {
			s.log.Error().Msgf("executor task for run task with id %q doesn't exist. This shouldn't happen. Skipping fetching", rt.ID)
		}
		return nil
	}

	if executor == nil {
		s.log.Warn().Msgf("executor with id %q doesn't exist. Skipping fetching", et.Spec.ExecutorID)
		return nil
	}

	var logPath string
	if setup {
		logPath = store.OSTRunTaskSetupLogPath(rt.ID)
	} else {
		logPath = store.OSTRunTaskStepLogPath(rt.ID, stepnum)
	}
	ok, err := s.OSTFileExists(logPath)
	if err != nil {
		return errors.WithStack(err)
	}
	if ok {
		return nil
	}

	var u string
	if setup {
		u = fmt.Sprintf(executor.ListenURL+"/api/v1alpha/executor/logs?taskid=%s&setup", et.ID)
	} else {
		u = fmt.Sprintf(executor.ListenURL+"/api/v1alpha/executor/logs?taskid=%s&step=%d", et.ID, stepnum)
	}
	r, err := http.Get(u)
	if err != nil {
		return errors.WithStack(err)
	}
	defer r.Body.Close()

	// ignore if not found
	if r.StatusCode == http.StatusNotFound {
		return nil
	}
	if r.StatusCode != http.StatusOK {
		return errors.Errorf("received http status: %d", r.StatusCode)
	}

	size := int64(-1)
	sizeStr := r.Header.Get("Content-Length")
	if sizeStr != "" {
		size, err = strconv.ParseInt(sizeStr, 10, 64)
		if err != nil {
			return errors.Errorf("failed to parse content length %q", sizeStr)
		}
	}

	return errors.WithStack(s.ost.WriteObject(logPath, r.Body, size, false))
}

func (s *Runservice) finishSetupLogPhase(ctx context.Context, runID, runTaskID string) error {
	err := s.d.Do(ctx, func(tx *sql.Tx) error {
		r, err := s.d.GetRun(tx, runID)
		if err != nil {
			return errors.WithStack(err)
		}
		if r == nil {
			return nil
		}

		rt, ok := r.Tasks[runTaskID]
		if !ok {
			return errors.Errorf("no such task with ID %s in run %s", runTaskID, runID)
		}

		rt.SetupStep.LogPhase = types.RunTaskFetchPhaseFinished
		if err := s.d.UpdateRun(tx, r); err != nil {
			return errors.WithStack(err)
		}
		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (s *Runservice) finishStepLogPhase(ctx context.Context, runID, runTaskID string, stepnum int) error {
	err := s.d.Do(ctx, func(tx *sql.Tx) error {
		r, err := s.d.GetRun(tx, runID)
		if err != nil {
			return errors.WithStack(err)
		}
		if r == nil {
			return nil
		}

		rt, ok := r.Tasks[runTaskID]
		if !ok {
			return errors.Errorf("no such task with ID %s in run %s", runTaskID, runID)
		}
		if len(rt.Steps) <= stepnum {
			return errors.Errorf("no such step for task %s in run %s", runTaskID, runID)
		}

		rt.Steps[stepnum].LogPhase = types.RunTaskFetchPhaseFinished
		if err := s.d.UpdateRun(tx, r); err != nil {
			return errors.WithStack(err)
		}
		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (s *Runservice) finishArchivePhase(ctx context.Context, runID, runTaskID string, stepnum int) error {
	err := s.d.Do(ctx, func(tx *sql.Tx) error {
		r, err := s.d.GetRun(tx, runID)
		if err != nil {
			return errors.WithStack(err)
		}
		if r == nil {
			return nil
		}

		rt, ok := r.Tasks[runTaskID]
		if !ok {
			return errors.Errorf("no such task with ID %s in run %s", runTaskID, runID)
		}
		if len(rt.Steps) <= stepnum {
			return errors.Errorf("no such step for task %s in run %s", runTaskID, runID)
		}
		found := false
		for i, sn := range rt.WorkspaceArchives {
			if stepnum == sn {
				found = true
				rt.WorkspaceArchivesPhase[i] = types.RunTaskFetchPhaseFinished
				break
			}
		}
		if !found {
			return errors.Errorf("no workspace archive for task %s, step %d in run %s", runTaskID, stepnum, runID)
		}

		if err := s.d.UpdateRun(tx, r); err != nil {
			return errors.WithStack(err)
		}
		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (s *Runservice) fetchTaskLogs(ctx context.Context, runID string, rt *types.RunTask) {
	s.log.Debug().Msgf("fetchTaskLogs")

	// fetch setup log
	if rt.SetupStep.LogPhase == types.RunTaskFetchPhaseNotStarted {
		if err := s.fetchLog(ctx, runID, rt, true, 0); err != nil {
			s.log.Err(err).Send()
		} else {
			if err := s.finishSetupLogPhase(ctx, runID, rt.ID); err != nil {
				s.log.Err(err).Send()
			}
		}
	}

	// fetch steps logs
	for i, rts := range rt.Steps {
		lp := rts.LogPhase
		if lp == types.RunTaskFetchPhaseNotStarted {
			if err := s.fetchLog(ctx, runID, rt, false, i); err != nil {
				s.log.Err(err).Send()
				continue
			}
			if err := s.finishStepLogPhase(ctx, runID, rt.ID, i); err != nil {
				s.log.Err(err).Send()
				continue
			}
		}
	}
}

func (s *Runservice) fetchArchive(ctx context.Context, runID string, rt *types.RunTask, stepnum int) error {
	var et *types.ExecutorTask
	var executor *types.Executor
	err := s.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		et, err = s.d.GetExecutorTaskByRunTask(tx, runID, rt.ID)
		if err != nil {
			return errors.WithStack(err)
		}
		if et == nil {
			return nil
		}
		executor, err = s.d.GetExecutorByExecutorID(tx, et.Spec.ExecutorID)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	if et == nil {
		if rt.Status != types.RunTaskStatusSkipped {
			s.log.Error().Msgf("executor task for run task with id %q doesn't exist. This shouldn't happen. Skipping fetching", rt.ID)
		}
		return nil
	}

	if executor == nil {
		s.log.Warn().Msgf("executor with id %q doesn't exist. Skipping fetching", et.Spec.ExecutorID)
		return nil
	}

	path := store.OSTRunTaskArchivePath(rt.ID, stepnum)
	ok, err := s.OSTFileExists(path)
	if err != nil {
		return errors.WithStack(err)
	}
	if ok {
		return nil
	}

	u := fmt.Sprintf(executor.ListenURL+"/api/v1alpha/executor/archives?taskid=%s&step=%d", et.ID, stepnum)
	s.log.Debug().Msgf("fetchArchive: %s", u)
	r, err := http.Get(u)
	if err != nil {
		return errors.WithStack(err)
	}
	defer r.Body.Close()

	// ignore if not found
	if r.StatusCode == http.StatusNotFound {
		return nil
	}
	if r.StatusCode != http.StatusOK {
		return errors.Errorf("received http status: %d", r.StatusCode)
	}

	size := int64(-1)
	sizeStr := r.Header.Get("Content-Length")
	if sizeStr != "" {
		size, err = strconv.ParseInt(sizeStr, 10, 64)
		if err != nil {
			return errors.Errorf("failed to parse content length %q", sizeStr)
		}
	}

	return errors.WithStack(s.ost.WriteObject(path, r.Body, size, false))
}

func (s *Runservice) fetchTaskArchives(ctx context.Context, runID string, rt *types.RunTask) {
	s.log.Debug().Msgf("fetchTaskArchives")

	for i, stepnum := range rt.WorkspaceArchives {
		phase := rt.WorkspaceArchivesPhase[i]
		if phase == types.RunTaskFetchPhaseNotStarted {
			if err := s.fetchArchive(ctx, runID, rt, stepnum); err != nil {
				s.log.Err(err).Send()
				continue
			}
			if err := s.finishArchivePhase(ctx, runID, rt.ID, stepnum); err != nil {
				s.log.Err(err).Send()
				continue
			}
		}
	}
}

func (s *Runservice) fetcherLoop(ctx context.Context) {
	for {
		s.log.Debug().Msgf("fetcher")

		if err := s.fetcher(ctx); err != nil {
			s.log.Err(err).Send()
		}

		sleepCh := time.NewTimer(2 * time.Second).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
	}
}

func (s *Runservice) fetcher(ctx context.Context) error {
	s.log.Debug().Msgf("fetcher")

	var runs []*types.Run
	err := s.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		runs, err = s.d.GetUnarchivedRuns(tx)
		if err != nil {
			return errors.WithStack(err)
		}
		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	for _, r := range runs {
		s.log.Debug().Msgf("r: %s", util.Dump(r))
		for _, rt := range r.Tasks {
			s.log.Debug().Msgf("rt: %s", util.Dump(rt))
			if err := s.taskFetcher(ctx, r, rt); err != nil {
				return errors.WithStack(err)
			}
		}
	}

	return nil
}

func (s *Runservice) taskFetcher(ctx context.Context, r *types.Run, rt *types.RunTask) error {
	if !rt.Status.IsFinished() {
		return nil
	}

	l := s.lf.NewLock(common.TaskFetcherLockKey(rt.ID))
	if err := l.Lock(ctx); err != nil {
		return errors.Wrap(err, "failed to acquire task fetcher lock")
	}
	defer func() { _ = l.Unlock() }()

	// write related logs runID
	runIDPath := store.OSTRunTaskLogsRunPath(rt.ID, r.ID)
	exists, err := s.OSTFileExists(runIDPath)
	if err != nil {
		s.log.Err(err).Send()
	} else if !exists {
		if err := s.ost.WriteObject(runIDPath, bytes.NewReader([]byte{}), 0, false); err != nil {
			s.log.Err(err).Send()
		}
	}

	// write related archives runID
	runIDPath = store.OSTRunTaskArchivesRunPath(rt.ID, r.ID)
	exists, err = s.OSTFileExists(runIDPath)
	if err != nil {
		s.log.Err(err).Send()
	} else if !exists {
		if err := s.ost.WriteObject(runIDPath, bytes.NewReader([]byte{}), 0, false); err != nil {
			s.log.Err(err).Send()
		}
	}

	s.fetchTaskLogs(ctx, r.ID, rt)
	s.fetchTaskArchives(ctx, r.ID, rt)

	// if the fetching is finished we can remove the executor tasks. We cannot
	// remove it before since it contains the reference to the executor where we
	// should fetch the data
	if rt.LogsFetchFinished() && rt.ArchivesFetchFinished() {
		err := s.d.Do(ctx, func(tx *sql.Tx) error {
			et, err := s.d.GetExecutorTaskByRunTask(tx, r.ID, rt.ID)
			if err != nil {
				return errors.WithStack(err)
			}
			if et == nil {
				return nil
			}
			s.log.Warn().Msgf("deleting executor task %q since logs/archive fetch finished", et.ID)
			return errors.WithStack(s.d.DeleteExecutorTask(tx, et.ID))
		})
		if err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

func (s *Runservice) runsSchedulerLoop(ctx context.Context) {
	for {
		s.log.Debug().Msgf("runsSchedulerLoop")

		if err := s.runsScheduler(ctx); err != nil {
			s.log.Err(err).Send()
		}

		sleepCh := time.NewTimer(2 * time.Second).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
	}
}

func (s *Runservice) runsScheduler(ctx context.Context) error {
	s.log.Debug().Msgf("runsScheduler")
	var runs []*types.Run
	err := s.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		runs, err = s.d.GetUnarchivedRuns(tx)
		if err != nil {
			return errors.WithStack(err)
		}
		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	for _, r := range runs {
		if err := s.runScheduler(ctx, r); err != nil {
			s.log.Err(err).Send()
		}
	}

	return nil
}

func (s *Runservice) runScheduler(ctx context.Context, r *types.Run) error {
	return s.scheduleRun(ctx, r.ID)
}

func (s *Runservice) finishedRunsArchiverLoop(ctx context.Context) {
	for {
		s.log.Debug().Msgf("finished run archiver loop")

		if err := s.finishedRunsArchiver(ctx); err != nil {
			s.log.Err(err).Send()
		}

		sleepCh := time.NewTimer(2 * time.Second).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
	}
}

func (s *Runservice) finishedRunsArchiver(ctx context.Context) error {
	s.log.Debug().Msgf("finished run archiver")
	var runs []*types.Run
	err := s.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		runs, err = s.d.GetUnarchivedRuns(tx)
		if err != nil {
			return errors.WithStack(err)
		}
		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	for _, r := range runs {
		if err := s.finishedRunArchiver(ctx, r.ID); err != nil {
			s.log.Err(err).Send()
		}
	}

	return nil
}

// finishedRunArchiver archives a run if it's finished and all the fetching
// phases (logs and archives) are marked as finished
func (s *Runservice) finishedRunArchiver(ctx context.Context, runID string) error {
	err := s.d.Do(ctx, func(tx *sql.Tx) error {
		r, err := s.d.GetRun(tx, runID)
		if err != nil {
			return errors.WithStack(err)
		}

		if r == nil {
			return errors.Errorf("run with id %q doesn't exist", runID)
		}

		if !r.Phase.IsFinished() {
			return nil
		}

		done := true
		for _, rt := range r.Tasks {
			// check that all logs are fetched
			if !rt.LogsFetchFinished() {
				done = false
				break
			}
			// check that all archives are fetched
			if !rt.ArchivesFetchFinished() {
				done = false
				break
			}
		}
		if !done {
			return nil
		}
		s.log.Info().Msgf("run %q archiving completed", r.ID)

		r.Archived = true
		if err := s.d.UpdateRun(tx, r); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (s *Runservice) cacheCleanerLoop(ctx context.Context, cacheExpireInterval time.Duration) {
	for {
		if err := s.cacheCleaner(ctx, cacheExpireInterval); err != nil {
			s.log.Err(err).Send()
		}

		sleepCh := time.NewTimer(cacheCleanerInterval).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
	}
}

func (s *Runservice) cacheCleaner(ctx context.Context, cacheExpireInterval time.Duration) error {
	s.log.Debug().Msgf("cacheCleaner")

	l := s.lf.NewLock(common.CacheCleanerLockKey)
	if err := l.Lock(ctx); err != nil {
		return errors.Wrap(err, "failed to acquire cache cleaner lock")
	}
	defer func() { _ = l.Unlock() }()

	doneCh := make(chan struct{})
	defer close(doneCh)
	for object := range s.ost.List(store.OSTCacheDir()+"/", "", true, doneCh) {
		if object.Err != nil {
			return object.Err
		}
		if object.LastModified.Add(cacheExpireInterval).Before(time.Now()) {
			if err := s.ost.DeleteObject(object.Path); err != nil {
				if !objectstorage.IsNotExist(err) {
					s.log.Warn().Msgf("failed to delete cache object %q: %v", object.Path, err)
				}
			}
		}
	}

	return nil
}

func (s *Runservice) workspaceCleanerLoop(ctx context.Context, workspaceExpireInterval time.Duration) {
	for {
		if err := s.workspaceCleaner(ctx, workspaceExpireInterval); err != nil {
			s.log.Err(err).Send()
		}

		sleepCh := time.NewTimer(workspaceCleanerInterval).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
	}
}

func (s *Runservice) workspaceCleaner(ctx context.Context, workspaceExpireInterval time.Duration) error {
	s.log.Debug().Msgf("workspaceCleaner")

	l := s.lf.NewLock(common.WorkspaceCleanerLockKey)
	if err := l.Lock(ctx); err != nil {
		return errors.Wrap(err, "failed to acquire workspace cleaner lock")
	}
	defer func() { _ = l.Unlock() }()

	doneCh := make(chan struct{})
	defer close(doneCh)
	for object := range s.ost.List(store.OSTArchivesBaseDir()+"/", "", true, doneCh) {
		if object.Err != nil {
			return object.Err
		}
		if object.LastModified.Add(workspaceExpireInterval).Before(time.Now()) {
			if err := s.ost.DeleteObject(object.Path); err != nil {
				if !objectstorage.IsNotExist(err) {
					s.log.Warn().Msgf("failed to delete workspace object %q: %v", object.Path, err)
				}
			}
		}
	}

	return nil
}
