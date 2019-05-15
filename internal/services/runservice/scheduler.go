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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/sorintlab/agola/internal/datamanager"
	"github.com/sorintlab/agola/internal/etcd"
	slog "github.com/sorintlab/agola/internal/log"
	"github.com/sorintlab/agola/internal/objectstorage"
	"github.com/sorintlab/agola/internal/runconfig"
	"github.com/sorintlab/agola/internal/services/runservice/common"
	"github.com/sorintlab/agola/internal/services/runservice/store"
	"github.com/sorintlab/agola/internal/services/runservice/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/pkg/errors"
	etcdclientv3 "go.etcd.io/etcd/clientv3"
	"go.etcd.io/etcd/clientv3/concurrency"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	cacheCleanerInterval = 1 * 24 * time.Hour
)

var level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
var logger = slog.New(level)
var log = logger.Sugar()

func mergeEnv(dest, src map[string]string) {
	for k, v := range src {
		dest[k] = v
	}
}

func (s *Runservice) runActiveExecutorTasks(ctx context.Context, runID string) ([]*types.ExecutorTask, error) {
	// the real source of active tasks is the number of executor tasks in etcd
	// we can't rely on RunTask.Status since it's only updated when receiveing
	// updated from the executor so it could be in a NotStarted state but have an
	// executor tasks scheduled and running
	ets, err := store.GetExecutorTasksForRun(ctx, s.e, runID)
	if err != nil {
		return nil, err
	}
	activeTasks := []*types.ExecutorTask{}
	for _, et := range ets {
		if !et.Status.Phase.IsFinished() {
			activeTasks = append(activeTasks, et)
		}
	}

	return activeTasks, nil
}

func (s *Runservice) runHasActiveExecutorTasks(ctx context.Context, runID string) (bool, error) {
	activeTasks, err := s.runActiveExecutorTasks(ctx, runID)
	if err != nil {
		return false, err
	}

	return len(activeTasks) > 0, nil
}

func advanceRunTasks(ctx context.Context, curRun *types.Run, rc *types.RunConfig, activeExecutorTasks []*types.ExecutorTask) (*types.Run, error) {
	log.Debugf("run: %s", util.Dump(curRun))
	log.Debugf("rc: %s", util.Dump(rc))

	// take a deepcopy of r so we do logic only on fixed status and not affeccted by current changes (due to random map iteration)
	newRun := curRun.DeepCopy()

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
			for _, et := range activeExecutorTasks {
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
		matchedNum := 0
		if allParentsFinished {
			for _, p := range parents {
				matched := false
				rp := curRun.Tasks[p.ID]
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

			// if all parents are matched then we can start it, otherwise we mark the step to be skipped
			skip := len(parents) != matchedNum
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

func getTasksToRun(ctx context.Context, r *types.Run, rc *types.RunConfig) ([]*types.RunTask, error) {
	log.Debugf("run: %s", util.Dump(r))
	log.Debugf("rc: %s", util.Dump(rc))

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
			// Run only if approved (when needs approval)
			if !rct.NeedsApproval || (rct.NeedsApproval && rt.Approved) {
				tasksToRun = append(tasksToRun, rt)
			}
		}
	}

	return tasksToRun, nil
}

func (s *Runservice) submitRunTasks(ctx context.Context, r *types.Run, rc *types.RunConfig, tasks []*types.RunTask) error {
	log.Debugf("tasksToRun: %s", util.Dump(tasks))

	for _, rt := range tasks {
		rct := rc.Tasks[rt.ID]

		executor, err := s.chooseExecutor(ctx, rct)
		if err != nil {
			return err
		}
		if executor == nil {
			log.Warnf("cannot choose an executor")
			return nil
		}

		et := s.genExecutorTask(ctx, r, rt, rc, executor)
		log.Debugf("et: %s", util.Dump(et))

		// check that the executorTask wasn't already scheduled
		// just a check but it's not really needed since the call to
		// atomicPutExecutorTask will fail if it already exists
		tet, err := store.GetExecutorTask(ctx, s.e, et.ID)
		if err != nil && err != etcd.ErrKeyNotFound {
			return err
		}
		if tet != nil {
			continue
		}
		if _, err := store.AtomicPutExecutorTask(ctx, s.e, et); err != nil {
			return err
		}
		if err := s.sendExecutorTask(ctx, et); err != nil {
			return err
		}
	}

	return nil
}

// chooseExecutor chooses the executor to schedule the task on. Now it's a very simple/dumb selection
// TODO(sgotti) improve this to use executor statistic, labels (arch type) etc...
func (s *Runservice) chooseExecutor(ctx context.Context, rct *types.RunConfigTask) (*types.Executor, error) {
	executors, err := store.GetExecutors(ctx, s.e)
	if err != nil {
		return nil, err
	}
	for _, e := range executors {
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
			if e.ActiveTasks >= e.ActiveTasksLimit {
				continue
			}
		}

		return e, nil
	}
	return nil, nil
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

func (s *Runservice) genExecutorTask(ctx context.Context, r *types.Run, rt *types.RunTask, rc *types.RunConfig, executor *types.Executor) *types.ExecutorTask {
	rct := rc.Tasks[rt.ID]

	environment := map[string]string{}
	if rct.Environment != nil {
		environment = rct.Environment
	}
	mergeEnv(environment, rc.StaticEnvironment)
	// run config Environment variables ovverride every other environment variable
	mergeEnv(environment, rc.Environment)

	et := &types.ExecutorTask{
		// The executorTask ID must be the same as the runTask ID so we can detect if
		// there's already an executorTask scheduled for that run task and we can get
		// at most once task execution
		ID:          rt.ID,
		RunID:       r.ID,
		TaskName:    rct.Name,
		Arch:        rct.Runtime.Arch,
		Containers:  rct.Runtime.Containers,
		Environment: environment,
		WorkingDir:  rct.WorkingDir,
		Shell:       rct.Shell,
		User:        rct.User,
		Steps:       rct.Steps,
		CachePrefix: store.OSTRootGroup(r.Group),
		Status: types.ExecutorTaskStatus{
			Phase:      types.ExecutorTaskPhaseNotStarted,
			Steps:      make([]*types.ExecutorTaskStepStatus, len(rct.Steps)),
			ExecutorID: executor.ID,
		},
		DockerRegistriesAuth: rct.DockerRegistriesAuth,
	}

	for i := range et.Status.Steps {
		et.Status.Steps[i] = &types.ExecutorTaskStepStatus{
			Phase: types.ExecutorTaskPhaseNotStarted,
		}
	}

	// calculate workspace operations
	// TODO(sgotti) right now we don't support duplicated files. So it's not currently possibile to overwrite a file in a upper layer.
	// this simplifies the workspaces extractions since they could be extracted in any order. We make them ordered just for reproducibility
	wsops := []types.WorkspaceOperation{}
	rctAllParents := runconfig.GetAllParents(rc.Tasks, rct)

	// sort parents by level and name just for reproducibility
	sort.Sort(parentsByLevelName(rctAllParents))

	for _, rctParent := range rctAllParents {
		log.Debugf("rctParent: %s", util.Dump(rctParent))
		for _, archiveStep := range r.Tasks[rctParent.ID].WorkspaceArchives {
			wsop := types.WorkspaceOperation{TaskID: rctParent.ID, Step: archiveStep}
			wsops = append(wsops, wsop)
		}
	}

	et.WorkspaceOperations = wsops

	return et
}

// sendExecutorTask sends executor task to executor, if this fails the executor
// will periodically fetch the executortask anyway
func (s *Runservice) sendExecutorTask(ctx context.Context, et *types.ExecutorTask) error {
	executor, err := store.GetExecutor(ctx, s.e, et.Status.ExecutorID)
	if err != nil && err != etcd.ErrKeyNotFound {
		return err
	}
	if executor == nil {
		log.Warnf("executor with id %q doesn't exist", et.Status.ExecutorID)
		return nil
	}

	etj, err := json.Marshal(et)
	if err != nil {
		return err
	}

	r, err := http.Post(executor.ListenURL+"/api/v1alpha/executor", "", bytes.NewReader(etj))
	if err != nil {
		return err
	}
	if r.StatusCode != http.StatusOK {
		return errors.Errorf("received http status: %d", r.StatusCode)
	}

	return nil
}

func (s *Runservice) compactChangeGroupsLoop(ctx context.Context) {
	for {
		if err := s.compactChangeGroups(ctx); err != nil {
			log.Errorf("err: %+v", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(1 * time.Second)
	}
}

func (s *Runservice) compactChangeGroups(ctx context.Context) error {
	resp, err := s.e.Client().Get(ctx, common.EtcdChangeGroupMinRevisionKey)
	if err != nil {
		return err
	}

	revision := resp.Kvs[0].ModRevision

	// first update minrevision
	cmp := etcdclientv3.Compare(etcdclientv3.ModRevision(common.EtcdChangeGroupMinRevisionKey), "=", revision)
	then := etcdclientv3.OpPut(common.EtcdChangeGroupMinRevisionKey, "")
	txn := s.e.Client().Txn(ctx).If(cmp).Then(then)
	tresp, err := txn.Commit()
	if err != nil {
		return etcd.FromEtcdError(err)
	}
	if !tresp.Succeeded {
		return errors.Errorf("failed to update change group min revision key due to concurrent update")
	}

	revision = tresp.Header.Revision

	// then remove all the groups keys with modrevision < minrevision
	// remove old groups

	resp, err = s.e.List(ctx, common.EtcdChangeGroupsDir, "", 0)
	if err != nil {
		return err
	}
	for _, kv := range resp.Kvs {
		if kv.ModRevision < revision-common.EtcdChangeGroupMinRevisionRange {
			cmp := etcdclientv3.Compare(etcdclientv3.ModRevision(string(kv.Key)), "=", kv.ModRevision)
			then := etcdclientv3.OpDelete(string(kv.Key))
			txn := s.e.Client().Txn(ctx).If(cmp).Then(then)
			tresp, err := txn.Commit()
			if err != nil {
				return etcd.FromEtcdError(err)
			}
			if !tresp.Succeeded {
				log.Errorf("failed to update change group min revision key due to concurrent update")
			}
		}
	}
	return nil
}

func (s *Runservice) scheduleRun(ctx context.Context, r *types.Run, rc *types.RunConfig) error {
	log.Debugf("r: %s", util.Dump(r))

	prevPhase := r.Phase
	prevResult := r.Result

	activeExecutorTasks, err := s.runActiveExecutorTasks(ctx, r.ID)
	if err != nil {
		return err
	}

	if err := advanceRun(ctx, r, rc, activeExecutorTasks); err != nil {
		return err
	}

	var runEvent *types.RunEvent
	// detect changes to phase and result and set related events
	if prevPhase != r.Phase || prevResult != r.Result {
		var err error
		runEvent, err = common.NewRunEvent(ctx, s.e, r.ID, r.Phase, r.Result)
		if err != nil {
			return err
		}
	}

	r, err = store.AtomicPutRun(ctx, s.e, r, runEvent, nil)
	if err != nil {
		return err
	}

	// if the run is set to stop, stop all tasks
	if r.Stop {
		for _, et := range activeExecutorTasks {
			et.Stop = true
			if _, err := store.AtomicPutExecutorTask(ctx, s.e, et); err != nil {
				return err
			}
			if err := s.sendExecutorTask(ctx, et); err != nil {
				return err
			}
		}
	}

	// advance tasks
	if r.Phase == types.RunPhaseRunning {
		r, err := advanceRunTasks(ctx, r, rc, activeExecutorTasks)
		if err != nil {
			return err
		}
		r, err = store.AtomicPutRun(ctx, s.e, r, nil, nil)
		if err != nil {
			return err
		}

		tasksToRun, err := getTasksToRun(ctx, r, rc)
		if err != nil {
			return err
		}

		return s.submitRunTasks(ctx, r, rc, tasksToRun)
	}

	return nil
}

// advanceRun updates the run result and phase. It must be the unique function that
// should update them.
func advanceRun(ctx context.Context, r *types.Run, rc *types.RunConfig, activeExecutorTasks []*types.ExecutorTask) error {
	log.Debugf("run: %s", util.Dump(r))
	hasActiveTasks := len(activeExecutorTasks) > 0

	// fail run if a task is failed
	if !r.Result.IsSet() && r.Phase == types.RunPhaseRunning {
		for _, rt := range r.Tasks {
			rct, ok := rc.Tasks[rt.ID]
			log.Debugf("rct: %s", util.Dump(rct))
			if !ok {
				return errors.Errorf("no such run config task with id %s for run config %s", rt.ID, rc.ID)
			}
			if rt.Status == types.RunTaskStatusFailed {
				if !rct.IgnoreFailure {
					log.Debugf("marking run %q as failed is task %q is failed", r.ID, rt.ID)
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
			if !hasActiveTasks {
				r.ChangePhase(types.RunPhaseFinished)
			}
		}

		// if the run is finished AND there're no executor tasks scheduled we can mark
		// all not started runtasks' fetch phases (setup step, logs and archives) as finished
		if r.Phase.IsFinished() {
			for _, rt := range r.Tasks {
				log.Debugf("rt: %s", util.Dump(rt))
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
	r, _, err := store.GetRun(ctx, s.e, et.RunID)
	if err != nil {
		return err
	}
	rc, err := store.OSTGetRunConfig(s.dm, r.ID)
	if err != nil {
		return errors.Wrapf(err, "cannot get run config %q", r.ID)
	}

	if err := s.updateRunTaskStatus(ctx, et, r); err != nil {
		return err
	}
	r, err = store.AtomicPutRun(ctx, s.e, r, nil, nil)
	if err != nil {
		return err
	}

	return s.scheduleRun(ctx, r, rc)
}

func (s *Runservice) updateRunTaskStatus(ctx context.Context, et *types.ExecutorTask, r *types.Run) error {
	log.Debugf("et: %s", util.Dump(et))

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
			rt.Status != types.RunTaskStatusRunning {
			wrongstatus = true
		}
	case types.ExecutorTaskPhaseSuccess:
		if rt.Status != types.RunTaskStatusSuccess &&
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
		log.Warnf("wrong executor task status: %s, rt status: %s", et.Status.Phase, rt.Status)
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
					log.Warnf("err: %+v", err)
				}
			}()
		}
	}
}

func (s *Runservice) executorTasksCleanerLoop(ctx context.Context) {
	for {
		log.Debugf("executorTasksCleaner")

		if err := s.executorTasksCleaner(ctx); err != nil {
			log.Errorf("err: %+v", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(1 * time.Second)
	}
}

func (s *Runservice) executorTasksCleaner(ctx context.Context) error {
	resp, err := s.e.List(ctx, common.EtcdTasksDir, "", 0)
	if err != nil {
		return err
	}

	for _, kv := range resp.Kvs {
		var et *types.ExecutorTask
		if err := json.Unmarshal(kv.Value, &et); err != nil {
			log.Errorf("err: %+v", err)
			continue
		}
		et.Revision = kv.ModRevision
		if err := s.executorTaskCleaner(ctx, et); err != nil {
			log.Errorf("err: %+v", err)
		}
	}

	return nil
}

func (s *Runservice) executorTaskCleaner(ctx context.Context, et *types.ExecutorTask) error {
	log.Debugf("et: %s", util.Dump(et))
	if et.Status.Phase.IsFinished() {
		r, _, err := store.GetRun(ctx, s.e, et.RunID)
		if err != nil {
			if err == etcd.ErrKeyNotFound {
				// run doesn't exists, remove executor task
				if err := store.DeleteExecutorTask(ctx, s.e, et.ID); err != nil {
					log.Errorf("err: %+v", err)
					return err
				}
				return nil
			}
			log.Errorf("err: %+v", err)
			return err
		}

		if r.Phase.IsFinished() {
			// if the run is finished mark the executor tasks to stop
			if !et.Stop {
				et.Stop = true
				if _, err := store.AtomicPutExecutorTask(ctx, s.e, et); err != nil {
					return err
				}
				if err := s.sendExecutorTask(ctx, et); err != nil {
					log.Errorf("err: %+v", err)
					return err
				}
			}
		}
	}

	if !et.Status.Phase.IsFinished() {
		// if the executor doesn't exists anymore mark the not finished executor tasks as failed
		executor, err := store.GetExecutor(ctx, s.e, et.Status.ExecutorID)
		if err != nil && err != etcd.ErrKeyNotFound {
			return err
		}
		if executor == nil {
			log.Warnf("executor with id %q doesn't exist. marking executor task %q as failed", et.Status.ExecutorID, et.ID)
			et.Status.Phase = types.ExecutorTaskPhaseFailed
			if _, err := store.AtomicPutExecutorTask(ctx, s.e, et); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Runservice) runTasksUpdaterLoop(ctx context.Context) {
	for {
		log.Debugf("runTasksUpdater")

		if err := s.runTasksUpdater(ctx); err != nil {
			log.Errorf("err: %+v", err)
		}

		time.Sleep(10 * time.Second)
	}
}

func (s *Runservice) runTasksUpdater(ctx context.Context) error {
	log.Debugf("runTasksUpdater")

	session, err := concurrency.NewSession(s.e.Client(), concurrency.WithTTL(5), concurrency.WithContext(ctx))
	if err != nil {
		return err
	}
	defer session.Close()

	m := concurrency.NewMutex(session, common.EtcdTaskUpdaterLockKey)

	// TODO(sgotti) find a way to use a trylock so we'll just return if already
	// locked. Currently multiple task updaters will enqueue and start when another
	// finishes (unuseful and consume resources)
	if err := m.Lock(ctx); err != nil {
		return err
	}
	defer m.Unlock(ctx)

	resp, err := s.e.List(ctx, common.EtcdTasksDir, "", 0)
	if err != nil {
		return err
	}

	for _, kv := range resp.Kvs {
		var et *types.ExecutorTask
		if err := json.Unmarshal(kv.Value, &et); err != nil {
			return err
		}
		et.Revision = kv.ModRevision
		if err := s.handleExecutorTaskUpdate(ctx, et); err != nil {
			log.Errorf("err: %v", err)
		}
	}

	return nil
}

func (s *Runservice) OSTFileExists(path string) (bool, error) {
	_, err := s.ost.Stat(path)
	if err != nil && err != objectstorage.ErrNotExist {
		return false, err
	}
	return err == nil, nil
}

func (s *Runservice) fetchLog(ctx context.Context, rt *types.RunTask, setup bool, stepnum int) error {
	et, err := store.GetExecutorTask(ctx, s.e, rt.ID)
	if err != nil && err != etcd.ErrKeyNotFound {
		return err
	}
	if et == nil {
		if !rt.Skip {
			log.Errorf("executor task with id %q doesn't exist. This shouldn't happen. Skipping fetching", rt.ID)
		}
		return nil
	}
	executor, err := store.GetExecutor(ctx, s.e, et.Status.ExecutorID)
	if err != nil && err != etcd.ErrKeyNotFound {
		return err
	}
	if executor == nil {
		log.Warnf("executor with id %q doesn't exist. Skipping fetching", et.Status.ExecutorID)
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
		return err
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
		return err
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

	return s.ost.WriteObject(logPath, r.Body, size, false)
}

func (s *Runservice) finishSetupLogPhase(ctx context.Context, runID, runTaskID string) error {
	r, _, err := store.GetRun(ctx, s.e, runID)
	if err != nil {
		return err
	}
	rt, ok := r.Tasks[runTaskID]
	if !ok {
		return errors.Errorf("no such task with ID %s in run %s", runTaskID, runID)
	}

	rt.SetupStep.LogPhase = types.RunTaskFetchPhaseFinished
	if _, err := store.AtomicPutRun(ctx, s.e, r, nil, nil); err != nil {
		return err
	}
	return nil
}

func (s *Runservice) finishStepLogPhase(ctx context.Context, runID, runTaskID string, stepnum int) error {
	r, _, err := store.GetRun(ctx, s.e, runID)
	if err != nil {
		return err
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
		return err
	}
	return nil
}

func (s *Runservice) finishArchivePhase(ctx context.Context, runID, runTaskID string, stepnum int) error {
	r, _, err := store.GetRun(ctx, s.e, runID)
	if err != nil {
		return err
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
		return err
	}
	return nil
}

func (s *Runservice) fetchTaskLogs(ctx context.Context, runID string, rt *types.RunTask) {
	log.Debugf("fetchTaskLogs")

	// fetch setup log
	if rt.SetupStep.LogPhase == types.RunTaskFetchPhaseNotStarted {
		if err := s.fetchLog(ctx, rt, true, 0); err != nil {
			log.Errorf("err: %+v", err)
		}
		if err := s.finishSetupLogPhase(ctx, runID, rt.ID); err != nil {
			log.Errorf("err: %+v", err)
		}
	}

	// fetch steps logs
	for i, rts := range rt.Steps {
		lp := rts.LogPhase
		if lp == types.RunTaskFetchPhaseNotStarted {
			if err := s.fetchLog(ctx, rt, false, i); err != nil {
				log.Errorf("err: %+v", err)
				continue
			}
			if err := s.finishStepLogPhase(ctx, runID, rt.ID, i); err != nil {
				log.Errorf("err: %+v", err)
				continue
			}
		}
	}
}

func (s *Runservice) fetchArchive(ctx context.Context, rt *types.RunTask, stepnum int) error {
	et, err := store.GetExecutorTask(ctx, s.e, rt.ID)
	if err != nil && err != etcd.ErrKeyNotFound {
		return err
	}
	if et == nil {
		log.Errorf("executor task with id %q doesn't exist. This shouldn't happen. Skipping fetching", rt.ID)
		return nil
	}
	executor, err := store.GetExecutor(ctx, s.e, et.Status.ExecutorID)
	if err != nil && err != etcd.ErrKeyNotFound {
		return err
	}
	if executor == nil {
		log.Warnf("executor with id %q doesn't exist. Skipping fetching", et.Status.ExecutorID)
		return nil
	}

	path := store.OSTRunTaskArchivePath(rt.ID, stepnum)
	ok, err := s.OSTFileExists(path)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}

	u := fmt.Sprintf(executor.ListenURL+"/api/v1alpha/executor/archives?taskid=%s&step=%d", rt.ID, stepnum)
	log.Debugf("fetchArchive: %s", u)
	r, err := http.Get(u)
	if err != nil {
		return err
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

	return s.ost.WriteObject(path, r.Body, size, false)
}

func (s *Runservice) fetchTaskArchives(ctx context.Context, runID string, rt *types.RunTask) {
	log.Debugf("fetchTaskArchives")

	for i, stepnum := range rt.WorkspaceArchives {
		phase := rt.WorkspaceArchivesPhase[i]
		if phase == types.RunTaskFetchPhaseNotStarted {
			if err := s.fetchArchive(ctx, rt, stepnum); err != nil {
				log.Errorf("err: %+v", err)
				continue
			}
			if err := s.finishArchivePhase(ctx, runID, rt.ID, stepnum); err != nil {
				log.Errorf("err: %+v", err)
				continue
			}
		}
	}
}

func (s *Runservice) fetcherLoop(ctx context.Context) {
	for {
		log.Debugf("fetcher")

		if err := s.fetcher(ctx); err != nil {
			log.Errorf("err: %+v", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(2 * time.Second)
	}
}

func (s *Runservice) fetcher(ctx context.Context) error {
	log.Debugf("fetcher")
	runs, err := store.GetRuns(ctx, s.e)
	if err != nil {
		return err
	}
	for _, r := range runs {
		log.Debugf("r: %s", util.Dump(r))
		for _, rt := range r.Tasks {
			log.Debugf("rt: %s", util.Dump(rt))
			if rt.Status.IsFinished() {
				// write related logs runID
				runIDPath := store.OSTRunTaskLogsRunPath(rt.ID, r.ID)
				exists, err := s.OSTFileExists(runIDPath)
				if err != nil {
					log.Errorf("err: %+v", err)
				} else if !exists {
					if err := s.ost.WriteObject(runIDPath, bytes.NewReader([]byte{}), 0, false); err != nil {
						log.Errorf("err: %+v", err)
					}
				}

				// write related archives runID
				runIDPath = store.OSTRunTaskArchivesRunPath(rt.ID, r.ID)
				exists, err = s.OSTFileExists(runIDPath)
				if err != nil {
					log.Errorf("err: %+v", err)
				} else if !exists {
					if err := s.ost.WriteObject(runIDPath, bytes.NewReader([]byte{}), 0, false); err != nil {
						log.Errorf("err: %+v", err)
					}
				}

				s.fetchTaskLogs(ctx, r.ID, rt)
				s.fetchTaskArchives(ctx, r.ID, rt)
			}
		}
	}
	return nil

}

func (s *Runservice) runsSchedulerLoop(ctx context.Context) {
	for {
		log.Debugf("runsSchedulerLoop")

		if err := s.runsScheduler(ctx); err != nil {
			log.Errorf("err: %+v", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(2 * time.Second)
	}
}

func (s *Runservice) runsScheduler(ctx context.Context) error {
	log.Debugf("runsScheduler")
	runs, err := store.GetRuns(ctx, s.e)
	if err != nil {
		return err
	}
	for _, r := range runs {
		if err := s.runScheduler(ctx, r); err != nil {
			log.Errorf("err: %+v", err)
		}
	}

	return nil
}

func (s *Runservice) runScheduler(ctx context.Context, r *types.Run) error {
	log.Debugf("runScheduler")
	rc, err := store.OSTGetRunConfig(s.dm, r.ID)
	if err != nil {
		return errors.Wrapf(err, "cannot get run config %q", r.ID)
	}

	return s.scheduleRun(ctx, r, rc)
}

func (s *Runservice) finishedRunsArchiverLoop(ctx context.Context) {
	for {
		log.Debugf("finished run archiver loop")

		if err := s.finishedRunsArchiver(ctx); err != nil {
			log.Errorf("err: %+v", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(2 * time.Second)
	}
}

func (s *Runservice) finishedRunsArchiver(ctx context.Context) error {
	log.Debugf("finished run archiver")
	runs, err := store.GetRuns(ctx, s.e)
	if err != nil {
		return err
	}
	for _, r := range runs {
		if err := s.finishedRunArchiver(ctx, r); err != nil {
			log.Errorf("err: %+v", err)
		}
	}

	// We write archived runs in objectstorage in the ordered they were archived
	runs, err = store.GetRuns(ctx, s.e)
	if err != nil {
		return err
	}
	for _, r := range runs {
		if r.Archived {
			if err := s.runOSTArchiver(ctx, r); err != nil {
				log.Errorf("err: %+v", err)
			}
		}
	}

	return nil
}

// finishedRunArchiver archives a run if it's finished and all the fetching
// phases (logs and archives) are marked as finished
func (s *Runservice) finishedRunArchiver(ctx context.Context, r *types.Run) error {
	//log.Debugf("r: %s", util.Dump(r))
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
	log.Infof("run %q archiving completed", r.ID)

	// if the fetching is finished we can remove the executor tasks. We cannot
	// remove it before since it contains the reference to the executor where we
	// should fetch the data

	for _, rt := range r.Tasks {
		log.Infof("deleting executor task %s", rt.ID)
		if err := store.DeleteExecutorTask(ctx, s.e, rt.ID); err != nil {
			return err
		}
	}

	r.Archived = true
	if _, err := store.AtomicPutRun(ctx, s.e, r, nil, nil); err != nil {
		return err
	}

	return nil
}

func (s *Runservice) runOSTArchiver(ctx context.Context, r *types.Run) error {
	// TODO(sgotti) avoid saving multiple times the run on objectstorage if the
	// store.DeletedArchivedRun fails
	log.Infof("saving run in objectstorage: %s", r.ID)
	ra, err := store.OSTSaveRunAction(r)
	if err != nil {
		return err
	}

	actions := append([]*datamanager.Action{ra})

	if _, err = s.dm.WriteWal(ctx, actions, nil); err != nil {
		return err
	}

	log.Infof("deleting run from etcd: %s", r.ID)
	if err := store.DeleteRun(ctx, s.e, r.ID); err != nil {
		return err
	}

	return nil
}

func (s *Runservice) cacheCleanerLoop(ctx context.Context, cacheExpireInterval time.Duration) {
	for {
		if err := s.cacheCleaner(ctx, cacheExpireInterval); err != nil {
			log.Errorf("err: %+v", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(cacheCleanerInterval)
	}
}

func (s *Runservice) cacheCleaner(ctx context.Context, cacheExpireInterval time.Duration) error {
	log.Debugf("cacheCleaner")

	session, err := concurrency.NewSession(s.e.Client(), concurrency.WithTTL(5), concurrency.WithContext(ctx))
	if err != nil {
		return err
	}
	defer session.Close()

	m := concurrency.NewMutex(session, common.EtcdCacheCleanerLockKey)

	// TODO(sgotti) find a way to use a trylock so we'll just return if already
	// locked. Currently multiple cachecleaners will enqueue and start when another
	// finishes (unuseful and consume resources)
	if err := m.Lock(ctx); err != nil {
		return err
	}
	defer m.Unlock(ctx)

	doneCh := make(chan struct{})
	defer close(doneCh)
	for object := range s.ost.List(store.OSTCacheDir()+"/", "", true, doneCh) {
		if object.Err != nil {
			return object.Err
		}
		if object.LastModified.Add(cacheExpireInterval).Before(time.Now()) {
			if err := s.ost.DeleteObject(object.Path); err != nil {
				if err != objectstorage.ErrNotExist {
					log.Warnf("failed to delete cache object %q: %v", object.Path, err)
				}
			}
		}
	}

	return nil
}
