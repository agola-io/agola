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

	"agola.io/agola/internal/datamanager"
	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/etcd"
	"agola.io/agola/internal/objectstorage"
	"agola.io/agola/internal/runconfig"
	"agola.io/agola/internal/services/runservice/common"
	"agola.io/agola/internal/services/runservice/store"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/runservice/types"
	"github.com/rs/zerolog"

	etcdclientv3 "go.etcd.io/etcd/clientv3"
	"go.etcd.io/etcd/clientv3/concurrency"
)

const (
	cacheCleanerInterval     = 1 * 24 * time.Hour
	workspaceCleanerInterval = 1 * 24 * time.Hour

	defaultExecutorNotAliveInterval = 60 * time.Second
)

func taskMatchesParentDependCondition(ctx context.Context, rt *types.RunTask, r *types.Run, rc *types.RunConfig) bool {
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

func advanceRunTasks(ctx context.Context, log zerolog.Logger, curRun *types.Run, rc *types.RunConfig, scheduledExecutorTasks []*types.ExecutorTask) (*types.Run, error) {
	log.Debug().Msgf("run: %s", util.Dump(curRun))
	log.Debug().Msgf("rc: %s", util.Dump(rc))

	// take a deepcopy of r so we do logic only on fixed status and not affeccted by current changes (due to random map iteration)
	newRun := curRun.DeepCopy()

	if newRun.Stop {
		// if the run is set to stop, skip all not running tasks
		for _, rt := range newRun.Tasks {
			isScheduled := false
			for _, et := range scheduledExecutorTasks {
				if rt.ID == et.ID {
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
				if rt.ID == et.ID {
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
			matched := taskMatchesParentDependCondition(ctx, rt, curRun, rc)

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

func getTasksToRun(ctx context.Context, log zerolog.Logger, r *types.Run, rc *types.RunConfig) ([]*types.RunTask, error) {
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
			if !taskMatchesParentDependCondition(ctx, rt, r, rc) {
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

		executor, err := s.chooseExecutor(ctx, rct)
		if err != nil {
			return errors.WithStack(err)
		}
		if executor == nil {
			s.log.Warn().Msgf("cannot choose an executor")
			return nil
		}

		et := common.GenExecutorTask(r, rt, rc, executor)
		s.log.Debug().Msgf("et: %s", util.Dump(et))

		// check that the executorTask wasn't already scheduled
		// just a check but it's not really needed since the call to
		// atomicPutExecutorTask will fail if it already exists
		tet, err := store.GetExecutorTask(ctx, s.e, et.ID)
		if err != nil && !errors.Is(err, etcd.ErrKeyNotFound) {
			return errors.WithStack(err)
		}
		if tet != nil {
			continue
		}
		if _, err := store.AtomicPutExecutorTask(ctx, s.e, et); err != nil {
			return errors.WithStack(err)
		}
		if err := s.sendExecutorTask(ctx, et); err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

// chooseExecutor chooses the executor to schedule the task on. Now it's a very simple/dumb selection
// TODO(sgotti) improve this to use executor statistic, labels (arch type) etc...
func (s *Runservice) chooseExecutor(ctx context.Context, rct *types.RunConfigTask) (*types.Executor, error) {
	executors, err := store.GetExecutors(ctx, s.e)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	// TODO(sgotti) find a way to avoid retrieving this for every chooseExecutor
	// invocation (i.e. use an etcd watcher to keep this value updated)
	executorTasksCount, err := store.GetExecutorTasksCountByExecutor(ctx, s.e)
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
		if e.LastStatusUpdateTime.Add(defaultExecutorNotAliveInterval).Before(time.Now()) {
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
			// will be 0 when executorTasksCount[e.ID] doesn't exist
			activeTasks := executorTasksCount[e.ID]
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
	executor, err := store.GetExecutor(ctx, s.e, et.Spec.ExecutorID)
	if err != nil && !errors.Is(err, etcd.ErrKeyNotFound) {
		return errors.WithStack(err)
	}
	if executor == nil {
		s.log.Warn().Msgf("executor with id %q doesn't exist", et.Spec.ExecutorID)
		return nil
	}

	r, _, err := store.GetRun(ctx, s.e, et.Spec.RunID)
	if err != nil {
		return errors.WithStack(err)
	}
	rc, err := store.OSTGetRunConfig(s.dm, r.ID)
	if err != nil {
		return errors.Wrapf(err, "cannot get run config %q", r.ID)
	}
	rt, ok := r.Tasks[et.ID]
	if !ok {
		return errors.Errorf("no such run task with id %s for run %s", et.ID, r.ID)
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

		sleepCh := time.NewTimer(1 * time.Second).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
	}
}

func (s *Runservice) compactChangeGroups(ctx context.Context) error {
	session, err := concurrency.NewSession(s.e.Client(), concurrency.WithTTL(5), concurrency.WithContext(ctx))
	if err != nil {
		return errors.WithStack(err)
	}
	defer session.Close()

	m := etcd.NewMutex(session, common.EtcdCompactChangeGroupsLockKey)

	if err := m.TryLock(ctx); err != nil {
		if errors.Is(err, etcd.ErrLocked) {
			return nil
		}
		return errors.WithStack(err)
	}
	defer func() { _ = m.Unlock(ctx) }()

	resp, err := s.e.Client().Get(ctx, common.EtcdChangeGroupMinRevisionKey)
	if err != nil {
		return errors.WithStack(err)
	}

	revision := resp.Kvs[0].ModRevision

	// first update minrevision
	cmp := etcdclientv3.Compare(etcdclientv3.ModRevision(common.EtcdChangeGroupMinRevisionKey), "=", revision)
	then := etcdclientv3.OpPut(common.EtcdChangeGroupMinRevisionKey, "")
	txn := s.e.Client().Txn(ctx).If(cmp).Then(then)
	tresp, err := txn.Commit()
	if err != nil {
		return errors.WithStack(etcd.FromEtcdError(err))
	}
	if !tresp.Succeeded {
		return errors.Errorf("failed to update change group min revision key due to concurrent update")
	}

	revision = tresp.Header.Revision

	// then remove all the groups keys with modrevision < minrevision
	// remove old groups

	resp, err = s.e.List(ctx, common.EtcdChangeGroupsDir, "", 0)
	if err != nil {
		return errors.WithStack(err)
	}
	for _, kv := range resp.Kvs {
		if kv.ModRevision < revision-common.EtcdChangeGroupMinRevisionRange {
			cmp := etcdclientv3.Compare(etcdclientv3.ModRevision(string(kv.Key)), "=", kv.ModRevision)
			then := etcdclientv3.OpDelete(string(kv.Key))
			txn := s.e.Client().Txn(ctx).If(cmp).Then(then)
			tresp, err := txn.Commit()
			if err != nil {
				return errors.WithStack(etcd.FromEtcdError(err))
			}
			if !tresp.Succeeded {
				s.log.Error().Msgf("failed to update change group min revision key due to concurrent update")
			}
		}
	}
	return nil
}

func (s *Runservice) scheduleRun(ctx context.Context, r *types.Run, rc *types.RunConfig) error {
	s.log.Debug().Msgf("r: %s", util.Dump(r))

	prevPhase := r.Phase
	prevResult := r.Result

	// the real source of active tasks is the number of executor tasks in etcd
	// we can't rely on RunTask.Status since it's only updated when receiveing
	// updated from the executor so it could be in a NotStarted state but have an
	// executor tasks scheduled and running
	scheduledExecutorTasks, err := store.GetExecutorTasksForRun(ctx, s.e, r.ID)
	if err != nil {
		return errors.WithStack(err)
	}

	if err := advanceRun(ctx, s.log, r, rc, scheduledExecutorTasks); err != nil {
		return errors.WithStack(err)
	}

	var runEvent *types.RunEvent
	// detect changes to phase and result and set related events
	if prevPhase != r.Phase || prevResult != r.Result {
		var err error
		runEvent, err = common.NewRunEvent(ctx, s.e, r.ID, r.Phase, r.Result)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	r, err = store.AtomicPutRun(ctx, s.e, r, runEvent, nil)
	if err != nil {
		return errors.WithStack(err)
	}

	// if the run is set to stop, stop all active tasks
	if r.Stop {
		for _, et := range scheduledExecutorTasks {
			et.Spec.Stop = true
			if _, err := store.AtomicPutExecutorTask(ctx, s.e, et); err != nil {
				return errors.WithStack(err)
			}
			if err := s.sendExecutorTask(ctx, et); err != nil {
				return errors.WithStack(err)
			}
		}
	}

	// advance tasks
	if r.Phase == types.RunPhaseRunning {
		r, err := advanceRunTasks(ctx, s.log, r, rc, scheduledExecutorTasks)
		if err != nil {
			return errors.WithStack(err)
		}
		r, err = store.AtomicPutRun(ctx, s.e, r, nil, nil)
		if err != nil {
			return errors.WithStack(err)
		}

		tasksToRun, err := getTasksToRun(ctx, s.log, r, rc)
		if err != nil {
			return errors.WithStack(err)
		}

		return s.submitRunTasks(ctx, r, rc, tasksToRun)
	}

	return nil
}

// advanceRun updates the run result and phase. It must be the unique function that
// should update them.
func advanceRun(ctx context.Context, log zerolog.Logger, r *types.Run, rc *types.RunConfig, scheduledExecutorTasks []*types.ExecutorTask) error {
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

func (s *Runservice) handleExecutorTaskUpdate(ctx context.Context, et *types.ExecutorTask) error {
	r, _, err := store.GetRun(ctx, s.e, et.Spec.RunID)
	if err != nil {
		return errors.WithStack(err)
	}
	rc, err := store.OSTGetRunConfig(s.dm, r.ID)
	if err != nil {
		return errors.Wrapf(err, "cannot get run config %q", r.ID)
	}

	if err := s.updateRunTaskStatus(ctx, et, r); err != nil {
		return errors.WithStack(err)
	}
	r, err = store.AtomicPutRun(ctx, s.e, r, nil, nil)
	if err != nil {
		return errors.WithStack(err)
	}

	return s.scheduleRun(ctx, r, rc)
}

func (s *Runservice) updateRunTaskStatus(ctx context.Context, et *types.ExecutorTask, r *types.Run) error {
	s.log.Debug().Msgf("et: %s", util.Dump(et))

	rt, ok := r.Tasks[et.ID]
	if !ok {
		return errors.Errorf("no such run task with id %s for run %s", et.ID, r.ID)
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

func (s *Runservice) executorTaskUpdateHandler(ctx context.Context, c <-chan *types.ExecutorTask) {
	for {
		select {
		case <-ctx.Done():
			return
		case et := <-c:
			go func() {
				if err := s.handleExecutorTaskUpdate(ctx, et); err != nil {
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
	// TODO(sgotti) use paged List
	resp, err := s.e.List(ctx, common.EtcdTasksDir, "", 0)
	if err != nil {
		return errors.WithStack(err)
	}

	for _, kv := range resp.Kvs {
		var et *types.ExecutorTask
		if err := json.Unmarshal(kv.Value, &et); err != nil {
			s.log.Err(err).Send()
			continue
		}
		et.Revision = kv.ModRevision
		if err := s.executorTaskCleaner(ctx, et); err != nil {
			s.log.Err(err).Send()
		}
	}

	return nil
}

func (s *Runservice) executorTaskCleaner(ctx context.Context, et *types.ExecutorTask) error {
	s.log.Debug().Msgf("et: %s", util.Dump(et))
	if et.Status.Phase.IsFinished() {
		r, _, err := store.GetRun(ctx, s.e, et.Spec.RunID)
		if err != nil {
			if errors.Is(err, etcd.ErrKeyNotFound) {
				// run doesn't exists, remove executor task
				if err := store.DeleteExecutorTask(ctx, s.e, et.ID); err != nil {
					s.log.Err(err).Send()
					return errors.WithStack(err)
				}
				return nil
			}
			s.log.Err(err).Send()
			return errors.WithStack(err)
		}

		if r.Phase.IsFinished() {
			// if the run is finished mark the executor tasks to stop
			if !et.Spec.Stop {
				et.Spec.Stop = true
				if _, err := store.AtomicPutExecutorTask(ctx, s.e, et); err != nil {
					return errors.WithStack(err)
				}
				if err := s.sendExecutorTask(ctx, et); err != nil {
					s.log.Err(err).Send()
					return errors.WithStack(err)
				}
			}
		}
	}

	if !et.Status.Phase.IsFinished() {
		// if the executor doesn't exists anymore mark the not finished executor tasks as failed
		executor, err := store.GetExecutor(ctx, s.e, et.Spec.ExecutorID)
		if err != nil && !errors.Is(err, etcd.ErrKeyNotFound) {
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
			if _, err := store.AtomicPutExecutorTask(ctx, s.e, et); err != nil {
				return errors.WithStack(err)
			}
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

	session, err := concurrency.NewSession(s.e.Client(), concurrency.WithTTL(5), concurrency.WithContext(ctx))
	if err != nil {
		return errors.WithStack(err)
	}
	defer session.Close()

	m := etcd.NewMutex(session, common.EtcdTaskUpdaterLockKey)

	if err := m.TryLock(ctx); err != nil {
		if errors.Is(err, etcd.ErrLocked) {
			return nil
		}
		return errors.WithStack(err)
	}
	defer func() { _ = m.Unlock(ctx) }()

	// TODO(sgotti) use paged List
	resp, err := s.e.List(ctx, common.EtcdTasksDir, "", 0)
	if err != nil {
		return errors.WithStack(err)
	}

	for _, kv := range resp.Kvs {
		var et *types.ExecutorTask
		if err := json.Unmarshal(kv.Value, &et); err != nil {
			return errors.WithStack(err)
		}
		et.Revision = kv.ModRevision
		if err := s.handleExecutorTaskUpdate(ctx, et); err != nil {
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

func (s *Runservice) fetchLog(ctx context.Context, rt *types.RunTask, setup bool, stepnum int) error {
	et, err := store.GetExecutorTask(ctx, s.e, rt.ID)
	if err != nil && !errors.Is(err, etcd.ErrKeyNotFound) {
		return errors.WithStack(err)
	}
	if et == nil {
		if rt.Status != types.RunTaskStatusSkipped {
			s.log.Error().Msgf("executor task with id %q doesn't exist. This shouldn't happen. Skipping fetching", rt.ID)
		}
		return nil
	}
	executor, err := store.GetExecutor(ctx, s.e, et.Spec.ExecutorID)
	if err != nil && !errors.Is(err, etcd.ErrKeyNotFound) {
		return errors.WithStack(err)
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
		u = fmt.Sprintf(executor.ListenURL+"/api/v1alpha/executor/logs?taskid=%s&setup", rt.ID)
	} else {
		u = fmt.Sprintf(executor.ListenURL+"/api/v1alpha/executor/logs?taskid=%s&step=%d", rt.ID, stepnum)
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
	r, _, err := store.GetRun(ctx, s.e, runID)
	if err != nil {
		return errors.WithStack(err)
	}
	rt, ok := r.Tasks[runTaskID]
	if !ok {
		return errors.Errorf("no such task with ID %s in run %s", runTaskID, runID)
	}

	rt.SetupStep.LogPhase = types.RunTaskFetchPhaseFinished
	if _, err := store.AtomicPutRun(ctx, s.e, r, nil, nil); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (s *Runservice) finishStepLogPhase(ctx context.Context, runID, runTaskID string, stepnum int) error {
	r, _, err := store.GetRun(ctx, s.e, runID)
	if err != nil {
		return errors.WithStack(err)
	}
	rt, ok := r.Tasks[runTaskID]
	if !ok {
		return errors.Errorf("no such task with ID %s in run %s", runTaskID, runID)
	}
	if len(rt.Steps) <= stepnum {
		return errors.Errorf("no such step for task %s in run %s", runTaskID, runID)
	}

	rt.Steps[stepnum].LogPhase = types.RunTaskFetchPhaseFinished
	if _, err := store.AtomicPutRun(ctx, s.e, r, nil, nil); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (s *Runservice) finishArchivePhase(ctx context.Context, runID, runTaskID string, stepnum int) error {
	r, _, err := store.GetRun(ctx, s.e, runID)
	if err != nil {
		return errors.WithStack(err)
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

	if _, err := store.AtomicPutRun(ctx, s.e, r, nil, nil); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (s *Runservice) fetchTaskLogs(ctx context.Context, runID string, rt *types.RunTask) {
	s.log.Debug().Msgf("fetchTaskLogs")

	// fetch setup log
	if rt.SetupStep.LogPhase == types.RunTaskFetchPhaseNotStarted {
		if err := s.fetchLog(ctx, rt, true, 0); err != nil {
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
			if err := s.fetchLog(ctx, rt, false, i); err != nil {
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

func (s *Runservice) fetchArchive(ctx context.Context, rt *types.RunTask, stepnum int) error {
	et, err := store.GetExecutorTask(ctx, s.e, rt.ID)
	if err != nil && !errors.Is(err, etcd.ErrKeyNotFound) {
		return errors.WithStack(err)
	}
	if et == nil {
		if rt.Status != types.RunTaskStatusSkipped {
			s.log.Error().Msgf("executor task with id %q doesn't exist. This shouldn't happen. Skipping fetching", rt.ID)
		}
		return nil
	}
	executor, err := store.GetExecutor(ctx, s.e, et.Spec.ExecutorID)
	if err != nil && !errors.Is(err, etcd.ErrKeyNotFound) {
		return errors.WithStack(err)
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

	u := fmt.Sprintf(executor.ListenURL+"/api/v1alpha/executor/archives?taskid=%s&step=%d", rt.ID, stepnum)
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
			if err := s.fetchArchive(ctx, rt, stepnum); err != nil {
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
	runs, err := store.GetRuns(ctx, s.e)
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
	session, err := concurrency.NewSession(s.e.Client(), concurrency.WithTTL(5), concurrency.WithContext(ctx))
	if err != nil {
		return errors.WithStack(err)
	}
	defer session.Close()

	m := etcd.NewMutex(session, common.EtcdTaskFetcherLockKey(rt.ID))

	if err := m.TryLock(ctx); err != nil {
		if errors.Is(err, etcd.ErrLocked) {
			return nil
		}
		return errors.WithStack(err)
	}
	defer func() { _ = m.Unlock(ctx) }()

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
		if err := store.DeleteExecutorTask(ctx, s.e, rt.ID); err != nil {
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
	runs, err := store.GetRuns(ctx, s.e)
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
	s.log.Debug().Msgf("runScheduler")
	rc, err := store.OSTGetRunConfig(s.dm, r.ID)
	if err != nil {
		return errors.Wrapf(err, "cannot get run config %q", r.ID)
	}

	return s.scheduleRun(ctx, r, rc)
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
	runs, err := store.GetRuns(ctx, s.e)
	if err != nil {
		return errors.WithStack(err)
	}
	for _, r := range runs {
		if err := s.finishedRunArchiver(ctx, r); err != nil {
			s.log.Err(err).Send()
		}
	}

	// We write archived runs in objectstorage in the ordered they were archived
	runs, err = store.GetRuns(ctx, s.e)
	if err != nil {
		return errors.WithStack(err)
	}
	for _, r := range runs {
		if r.Archived {
			if err := s.runOSTArchiver(ctx, r); err != nil {
				s.log.Err(err).Send()
			}
		}
	}

	return nil
}

// finishedRunArchiver archives a run if it's finished and all the fetching
// phases (logs and archives) are marked as finished
func (s *Runservice) finishedRunArchiver(ctx context.Context, r *types.Run) error {
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
	if _, err := store.AtomicPutRun(ctx, s.e, r, nil, nil); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (s *Runservice) runOSTArchiver(ctx context.Context, r *types.Run) error {
	// TODO(sgotti) avoid saving multiple times the run on objectstorage if the
	// store.DeletedArchivedRun fails
	s.log.Info().Msgf("saving run in objectstorage: %s", r.ID)
	ra, err := store.OSTSaveRunAction(r)
	if err != nil {
		return errors.WithStack(err)
	}

	actions := []*datamanager.Action{ra}

	if _, err = s.dm.WriteWal(ctx, actions, nil); err != nil {
		return errors.WithStack(err)
	}

	s.log.Info().Msgf("deleting run from etcd: %s", r.ID)
	if err := store.DeleteRun(ctx, s.e, r.ID); err != nil {
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

	session, err := concurrency.NewSession(s.e.Client(), concurrency.WithTTL(5), concurrency.WithContext(ctx))
	if err != nil {
		return errors.WithStack(err)
	}
	defer session.Close()

	m := etcd.NewMutex(session, common.EtcdCacheCleanerLockKey)

	if err := m.TryLock(ctx); err != nil {
		if errors.Is(err, etcd.ErrLocked) {
			return nil
		}
		return errors.WithStack(err)
	}
	defer func() { _ = m.Unlock(ctx) }()

	doneCh := make(chan struct{})
	defer close(doneCh)
	for object := range s.ost.List(store.OSTCacheDir()+"/", "", true, doneCh) {
		if object.Err != nil {
			return errors.WithStack(object.Err)
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

	session, err := concurrency.NewSession(s.e.Client(), concurrency.WithTTL(5), concurrency.WithContext(ctx))
	if err != nil {
		return errors.WithStack(err)
	}
	defer session.Close()

	m := etcd.NewMutex(session, common.EtcdWorkspaceCleanerLockKey)

	if err := m.TryLock(ctx); err != nil {
		if errors.Is(err, etcd.ErrLocked) {
			return nil
		}
		return errors.WithStack(err)
	}
	defer func() { _ = m.Unlock(ctx) }()

	doneCh := make(chan struct{})
	defer close(doneCh)
	for object := range s.ost.List(store.OSTArchivesBaseDir()+"/", "", true, doneCh) {
		if object.Err != nil {
			return errors.WithStack(object.Err)
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
