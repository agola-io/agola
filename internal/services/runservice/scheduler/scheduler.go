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

package scheduler

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"time"

	scommon "github.com/sorintlab/agola/internal/common"
	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/etcd"
	slog "github.com/sorintlab/agola/internal/log"
	"github.com/sorintlab/agola/internal/objectstorage"
	"github.com/sorintlab/agola/internal/runconfig"
	"github.com/sorintlab/agola/internal/services/config"
	"github.com/sorintlab/agola/internal/services/runservice/scheduler/api"
	"github.com/sorintlab/agola/internal/services/runservice/scheduler/command"
	"github.com/sorintlab/agola/internal/services/runservice/scheduler/common"
	"github.com/sorintlab/agola/internal/services/runservice/scheduler/readdb"
	"github.com/sorintlab/agola/internal/services/runservice/scheduler/store"
	"github.com/sorintlab/agola/internal/services/runservice/types"
	"github.com/sorintlab/agola/internal/util"
	"github.com/sorintlab/agola/internal/wal"

	ghandlers "github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	etcdclientv3 "go.etcd.io/etcd/clientv3"
	"go.etcd.io/etcd/clientv3/concurrency"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
var logger = slog.New(level)
var log = logger.Sugar()

func mergeEnv(dest, src map[string]string) {
	for k, v := range src {
		dest[k] = v
	}
}

func (s *Scheduler) runActiveExecutorTasks(ctx context.Context, runID string) ([]*types.ExecutorTask, error) {
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

func (s *Scheduler) runHasActiveExecutorTasks(ctx context.Context, runID string) (bool, error) {
	activeTasks, err := s.runActiveExecutorTasks(ctx, runID)
	if err != nil {
		return false, err
	}

	return len(activeTasks) > 0, nil
}

func advanceRunTasks(ctx context.Context, r *types.Run, rc *types.RunConfig) error {
	log.Debugf("run: %s", util.Dump(r))
	log.Debugf("rc: %s", util.Dump(rc))

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

		// if all parents are finished check if the task could be executed or be skipped
		matchedNum := 0
		if allParentsFinished {
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

	return nil
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

func (s *Scheduler) submitRunTasks(ctx context.Context, r *types.Run, rc *types.RunConfig, tasks []*types.RunTask) error {
	log.Debugf("tasksToRun: %s", util.Dump(tasks))

	for _, rt := range tasks {
		executor, err := s.chooseExecutor(ctx)
		if err != nil {
			return err
		}
		if executor == nil {
			return errors.Errorf("cannot choose an executor")
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
func (s *Scheduler) chooseExecutor(ctx context.Context) (*types.Executor, error) {
	executors, err := store.GetExecutors(ctx, s.e)
	if err != nil {
		return nil, err
	}
	for _, e := range executors {
		return e, nil
	}
	return nil, nil
}

func (s *Scheduler) genExecutorTask(ctx context.Context, r *types.Run, rt *types.RunTask, rc *types.RunConfig, executor *types.Executor) *types.ExecutorTask {
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
		Containers:  rct.Runtime.Containers,
		Environment: environment,
		WorkingDir:  rct.WorkingDir,
		Shell:       rct.Shell,
		User:        rct.User,
		Steps:       rct.Steps,
		Status: types.ExecutorTaskStatus{
			Phase:      types.ExecutorTaskPhaseNotStarted,
			Steps:      make([]*types.ExecutorTaskStepStatus, len(rct.Steps)),
			ExecutorID: executor.ID,
		},
	}

	for i := range et.Status.Steps {
		et.Status.Steps[i] = &types.ExecutorTaskStepStatus{
			Phase: types.ExecutorTaskPhaseNotStarted,
		}
	}

	// calculate workspace layers
	ws := make(types.Workspace, rct.Level+1)
	rctAllParents := runconfig.GetAllParents(rc.Tasks, rct)
	log.Debugf("rctAllParents: %s", util.Dump(rctAllParents))
	for _, rctParent := range rctAllParents {
		log.Debugf("rctParent: %s", util.Dump(rctParent))
		log.Debugf("ws: %s", util.Dump(ws))
		archives := []types.WorkspaceArchive{}
		for _, archiveStep := range r.Tasks[rctParent.ID].WorkspaceArchives {
			archives = append(archives, types.WorkspaceArchive{TaskID: rctParent.ID, Step: archiveStep})
		}
		log.Debugf("archives: %v", util.Dump(archives))
		if len(archives) > 0 {
			ws[rctParent.Level] = append(ws[rctParent.Level], archives)
		}
	}
	log.Debugf("ws: %s", util.Dump(ws))

	et.Workspace = ws

	return et
}

// sendExecutorTask sends executor task to executor, if this fails the executor
// will periodically fetch the executortask anyway
func (s *Scheduler) sendExecutorTask(ctx context.Context, et *types.ExecutorTask) error {
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

func (s *Scheduler) compactChangeGroupsLoop(ctx context.Context) {
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

func (s *Scheduler) compactChangeGroups(ctx context.Context) error {
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

func (s *Scheduler) scheduleRun(ctx context.Context, r *types.Run, rc *types.RunConfig) error {
	log.Debugf("r: %s", util.Dump(r))

	prevPhase := r.Phase
	prevResult := r.Result

	hasActiveTasks, err := s.runHasActiveExecutorTasks(ctx, r.ID)
	if err != nil {
		return err
	}

	if err := advanceRun(ctx, r, rc, hasActiveTasks); err != nil {
		return err
	}

	var runEvent *common.RunEvent
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
		activeExecutorTasks, err := s.runActiveExecutorTasks(ctx, r.ID)
		if err != nil {
			return err
		}
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
		if err := advanceRunTasks(ctx, r, rc); err != nil {
			return err
		}
		r, err := store.AtomicPutRun(ctx, s.e, r, nil, nil)
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
func advanceRun(ctx context.Context, r *types.Run, rc *types.RunConfig, hasActiveTasks bool) error {
	log.Debugf("run: %s", util.Dump(r))

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

func (s *Scheduler) handleExecutorTaskUpdate(ctx context.Context, et *types.ExecutorTask) error {
	r, _, err := store.GetRun(ctx, s.e, et.RunID)
	if err != nil {
		return err
	}
	rc, err := store.LTSGetRunConfig(s.wal, r.ID)
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

func (s *Scheduler) updateRunTaskStatus(ctx context.Context, et *types.ExecutorTask, r *types.Run) error {
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

func (s *Scheduler) executorTaskUpdateHandler(ctx context.Context, c <-chan *types.ExecutorTask) {
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

func (s *Scheduler) executorTasksCleanerLoop(ctx context.Context) {
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

func (s *Scheduler) executorTasksCleaner(ctx context.Context) error {
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

func (s *Scheduler) executorTaskCleaner(ctx context.Context, et *types.ExecutorTask) error {
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

func (s *Scheduler) runTasksUpdaterLoop(ctx context.Context) {
	for {
		log.Debugf("runTasksUpdater")

		if err := s.runTasksUpdater(ctx); err != nil {
			log.Errorf("err: %+v", err)
		}

		time.Sleep(10 * time.Second)
	}
}

func (s *Scheduler) runTasksUpdater(ctx context.Context) error {
	log.Debugf("runTasksUpdater")

	session, err := concurrency.NewSession(s.e.Client(), concurrency.WithTTL(5), concurrency.WithContext(ctx))
	if err != nil {
		return err
	}
	defer session.Close()

	m := concurrency.NewMutex(session, "taskupdaterlock")

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

func (s *Scheduler) fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	return !os.IsNotExist(err), nil
}

func (s *Scheduler) fetchLog(ctx context.Context, rt *types.RunTask, setup bool, stepnum int) error {
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
		logPath = store.LTSRunTaskSetupLogPath(rt.ID)
	} else {
		logPath = store.LTSRunTaskStepLogPath(rt.ID, stepnum)
	}
	ok, err := s.fileExists(logPath)
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

	return s.lts.WriteObject(logPath, r.Body)
}

func (s *Scheduler) finishSetupLogPhase(ctx context.Context, runID, runTaskID string) error {
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

func (s *Scheduler) finishStepLogPhase(ctx context.Context, runID, runTaskID string, stepnum int) error {
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

func (s *Scheduler) finishArchivePhase(ctx context.Context, runID, runTaskID string, stepnum int) error {
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

func (s *Scheduler) fetchTaskLogs(ctx context.Context, runID string, rt *types.RunTask) {
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

func (s *Scheduler) fetchArchive(ctx context.Context, rt *types.RunTask, stepnum int) error {
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

	path := store.LTSRunArchivePath(rt.ID, stepnum)
	ok, err := s.fileExists(path)
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

	return s.lts.WriteObject(path, r.Body)
}

func (s *Scheduler) fetchTaskArchives(ctx context.Context, runID string, rt *types.RunTask) {
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

func (s *Scheduler) fetcherLoop(ctx context.Context) {
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

func (s *Scheduler) fetcher(ctx context.Context) error {
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
				s.fetchTaskLogs(ctx, r.ID, rt)
				s.fetchTaskArchives(ctx, r.ID, rt)
			}
		}

		// We don't update the fetch phases and atomic put the run since fetching may
		// take a lot of time and the run will be already updated in the meantime
		// causing the atomic put will fail
		// Another loop will check if the fetched file exists and update the run
	}
	return nil

}

func (s *Scheduler) runsSchedulerLoop(ctx context.Context) {
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

func (s *Scheduler) runsScheduler(ctx context.Context) error {
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

func (s *Scheduler) runScheduler(ctx context.Context, r *types.Run) error {
	log.Debugf("runScheduler")
	rc, err := store.LTSGetRunConfig(s.wal, r.ID)
	if err != nil {
		return errors.Wrapf(err, "cannot get run config %q", r.ID)
	}

	return s.scheduleRun(ctx, r, rc)
}

func (s *Scheduler) finishedRunsArchiverLoop(ctx context.Context) {
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

func (s *Scheduler) finishedRunsArchiver(ctx context.Context) error {
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

	// We write archived runs in lts in the ordered they were archived
	runs, err = store.GetRuns(ctx, s.e)
	if err != nil {
		return err
	}
	for _, r := range runs {
		if r.Archived {
			if err := s.runLTSArchiver(ctx, r); err != nil {
				log.Errorf("err: %+v", err)
			}
		}
	}

	return nil
}

// finishedRunArchiver archives a run if it's finished and all the fetching
// phases (logs and archives) are marked as finished
func (s *Scheduler) finishedRunArchiver(ctx context.Context, r *types.Run) error {
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

func (s *Scheduler) runLTSArchiver(ctx context.Context, r *types.Run) error {
	// TODO(sgotti) avoid saving multiple times the run on lts if the
	// store.DeletedArchivedRun fails
	log.Infof("saving run in lts: %s", r.ID)
	ra, err := store.LTSSaveRunAction(r)
	if err != nil {
		return err
	}

	actions := append([]*wal.Action{ra})

	if _, err = s.wal.WriteWal(ctx, actions, nil); err != nil {
		return err
	}

	log.Infof("deleting run from etcd: %s", r.ID)
	if err := store.DeleteRun(ctx, s.e, r.ID); err != nil {
		return err
	}

	return nil
}

func (s *Scheduler) dumpLTSLoop(ctx context.Context) {
	for {
		log.Debugf("lts dump loop")

		// TODO(sgotti) create new dump only after N files
		if err := s.dumpLTS(ctx); err != nil {
			log.Errorf("err: %+v", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(10 * time.Second)
	}
}

func (s *Scheduler) dumpLTS(ctx context.Context) error {
	type indexHeader struct {
		LastWalSequence string
	}
	type indexData struct {
		DataType string
		Data     interface{}
	}

	type indexDataRun struct {
		ID    string
		Group string
		Phase types.RunPhase
	}
	type indexDataRunCounter struct {
		Group   string
		Counter uint64
	}

	indexDir := strconv.FormatInt(time.Now().UnixNano(), 10)

	var lastWalSequence string
	err := s.readDB.Do(func(tx *db.Tx) error {
		var err error
		lastWalSequence, err = s.readDB.GetCommittedWalSequenceLTS(tx)
		return err
	})
	if err != nil {
		return err
	}

	data := []byte{}
	iheader := &indexHeader{LastWalSequence: lastWalSequence}
	ihj, err := json.Marshal(iheader)
	if err != nil {
		return err
	}
	data = append(data, ihj...)

	var lastRunID string
	stop := false
	for {
		err := s.readDB.Do(func(tx *db.Tx) error {
			var err error
			lruns, err := s.readDB.GetRunsFilteredLTS(tx, nil, false, nil, lastRunID, 1000, types.SortOrderDesc)
			if err != nil {
				return err
			}
			if len(lruns) == 0 {
				stop = true
			} else {
				lastRunID = lruns[len(lruns)-1].ID
			}
			for _, run := range lruns {
				id := &indexData{DataType: string(common.DataTypeRun), Data: indexDataRun{ID: run.ID, Group: run.GroupPath, Phase: types.RunPhase(run.Phase)}}
				idj, err := json.Marshal(id)
				if err != nil {
					return err
				}
				data = append(data, idj...)
			}
			return nil
		})
		if err != nil {
			return err
		}
		if stop {
			break
		}
	}

	var lastGroup string
	stop = false
	for {
		err := s.readDB.Do(func(tx *db.Tx) error {
			var err error
			counters, err := s.readDB.GetRunCountersLTS(tx, lastGroup, 1000)
			if err != nil {
				return err
			}
			if len(counters) == 0 {
				stop = true
			} else {
				lastGroup = counters[len(counters)-1].Group
			}
			for _, counter := range counters {
				id := &indexData{DataType: string(common.DataTypeRunCounter), Data: indexDataRunCounter{Group: counter.Group, Counter: counter.Counter}}
				idj, err := json.Marshal(id)
				if err != nil {
					return err
				}
				data = append(data, idj...)
			}
			return nil
		})
		if err != nil {
			return err
		}
		if stop {
			break
		}
	}

	index := path.Join(common.StorageRunsIndexesDir, indexDir, "all")

	if err = s.lts.WriteObject(index, bytes.NewReader(data)); err != nil {
		return err
	}

	return nil
}

func (s *Scheduler) dumpLTSCleanerLoop(ctx context.Context) {
	for {
		log.Infof("lts dump cleaner loop")

		if err := s.dumpLTSCleaner(ctx); err != nil {
			log.Errorf("err: %+v", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(10 * time.Second)
	}
}

func (s *Scheduler) dumpLTSCleaner(ctx context.Context) error {
	type indexData struct {
		ID    string
		Group string
		Phase types.RunPhase
	}

	// collect all old indexes
	objects := []string{}
	doneCh := make(chan struct{})
	defer close(doneCh)
	var indexPath string
	for object := range s.lts.List(common.StorageRunsIndexesDir+"/", "", true, doneCh) {
		if object.Err != nil {
			return object.Err
		}

		h := util.PathList(object.Path)
		if len(h) < 2 {
			return errors.Errorf("wrong index dir path %q", object.Path)
		}
		curIndexPath := object.Path
		if curIndexPath > indexPath {
			if indexPath != "" {
				objects = append(objects, indexPath)
			}
			indexPath = curIndexPath
		} else {
			objects = append(objects, curIndexPath)
		}
	}

	for _, object := range objects {
		if err := s.lts.DeleteObject(object); err != nil {
			log.Errorf("object: %s, err: %v", object, err)
			return err
		}
	}

	return nil
}

type Scheduler struct {
	c      *config.RunServiceScheduler
	e      *etcd.Store
	lts    *objectstorage.ObjStorage
	wal    *wal.WalManager
	readDB *readdb.ReadDB
	ch     *command.CommandHandler
}

func NewScheduler(ctx context.Context, c *config.RunServiceScheduler) (*Scheduler, error) {
	if c.Debug {
		level.SetLevel(zapcore.DebugLevel)
	}

	lts, err := scommon.NewLTS(&c.LTS)
	if err != nil {
		return nil, err
	}
	e, err := scommon.NewEtcd(&c.Etcd, logger, "runscheduler")
	if err != nil {
		return nil, err
	}

	s := &Scheduler{
		c:   c,
		e:   e,
		lts: lts,
	}

	walConf := &wal.WalManagerConfig{
		E:              e,
		Lts:            lts,
		DataToPathFunc: common.DataToPathFunc,
	}
	wal, err := wal.NewWalManager(ctx, logger, walConf)
	if err != nil {
		return nil, err
	}
	s.wal = wal

	readDB, err := readdb.NewReadDB(ctx, logger, filepath.Join(c.DataDir, "readdb"), e, lts, wal)
	if err != nil {
		return nil, err
	}
	s.readDB = readDB

	ch := command.NewCommandHandler(logger, e, readDB, lts, wal)
	s.ch = ch

	return s, nil
}

func (s *Scheduler) InitEtcd(ctx context.Context) error {
	// Create changegroup min revision if it doesn't exists
	cmp := []etcdclientv3.Cmp{}
	then := []etcdclientv3.Op{}

	cmp = append(cmp, etcdclientv3.Compare(etcdclientv3.CreateRevision(common.EtcdChangeGroupMinRevisionKey), "=", 0))
	then = append(then, etcdclientv3.OpPut(common.EtcdChangeGroupMinRevisionKey, ""))
	txn := s.e.Client().Txn(ctx).If(cmp...).Then(then...)
	if _, err := txn.Commit(); err != nil {
		return etcd.FromEtcdError(err)
	}

	return nil
}

func (s *Scheduler) Run(ctx context.Context) error {
	errCh := make(chan error)
	walReadyCh := make(chan struct{})

	go func() { errCh <- s.wal.Run(ctx, walReadyCh) }()

	// wait for wal to be ready
	<-walReadyCh

	for {
		err := s.InitEtcd(ctx)
		if err == nil {
			break
		}
		log.Errorf("failed to initialize etcd: %+v", err)
		time.Sleep(1 * time.Second)
	}

	go s.readDB.Run(ctx)

	ch := make(chan *types.ExecutorTask)

	// noop coors handler
	corsHandler := func(h http.Handler) http.Handler {
		return h
	}

	corsAllowedMethodsOptions := ghandlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "DELETE"})
	corsAllowedHeadersOptions := ghandlers.AllowedHeaders([]string{"Accept", "Accept-Encoding", "Authorization", "Content-Length", "Content-Type", "X-CSRF-Token", "Authorization"})
	corsAllowedOriginsOptions := ghandlers.AllowedOrigins([]string{"*"})
	corsHandler = ghandlers.CORS(corsAllowedMethodsOptions, corsAllowedHeadersOptions, corsAllowedOriginsOptions)

	// executor dedicated api, only calls from executor should happen on these handlers
	executorStatusHandler := api.NewExecutorStatusHandler(s.e, ch)
	executorTaskStatusHandler := api.NewExecutorTaskStatusHandler(s.e, ch)
	executorTaskHandler := api.NewExecutorTaskHandler(s.e)
	executorTasksHandler := api.NewExecutorTasksHandler(s.e)
	archivesHandler := api.NewArchivesHandler(logger, s.lts)

	// api from clients
	executorDeleteHandler := api.NewExecutorDeleteHandler(logger, s.ch)

	logsHandler := api.NewLogsHandler(logger, s.e, s.lts, s.wal)

	runHandler := api.NewRunHandler(logger, s.e, s.wal, s.readDB)
	runTaskActionsHandler := api.NewRunTaskActionsHandler(logger, s.ch)
	runsHandler := api.NewRunsHandler(logger, s.readDB)
	runActionsHandler := api.NewRunActionsHandler(logger, s.ch)
	runCreateHandler := api.NewRunCreateHandler(logger, s.ch)
	changeGroupsUpdateTokensHandler := api.NewChangeGroupsUpdateTokensHandler(logger, s.readDB)

	router := mux.NewRouter()
	apirouter := router.PathPrefix("/api/v1alpha").Subrouter()
	apirouter.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadRequest) })

	apirouter.Handle("/executor/{executorid}", executorStatusHandler).Methods("POST")
	apirouter.Handle("/executor/{executorid}", executorDeleteHandler).Methods("DELETE")
	apirouter.Handle("/executor/{executorid}/tasks", executorTasksHandler).Methods("GET")
	apirouter.Handle("/executor/{executorid}/tasks/{taskid}", executorTaskHandler).Methods("GET")
	apirouter.Handle("/executor/{executorid}/tasks/{taskid}", executorTaskStatusHandler).Methods("POST")
	apirouter.Handle("/executor/archives", archivesHandler).Methods("GET")

	apirouter.Handle("/logs", logsHandler).Methods("GET")

	apirouter.Handle("/runs/{runid}", runHandler).Methods("GET")
	apirouter.Handle("/runs/{runid}/actions", runActionsHandler).Methods("PUT")
	apirouter.Handle("/runs/{runid}/tasks/{taskid}/actions", runTaskActionsHandler).Methods("PUT")
	apirouter.Handle("/runs", runsHandler).Methods("GET")
	apirouter.Handle("/runs", runCreateHandler).Methods("POST")

	apirouter.Handle("/changegroups", changeGroupsUpdateTokensHandler).Methods("GET")

	mainrouter := mux.NewRouter()
	mainrouter.PathPrefix("/").Handler(corsHandler(router))

	// Return a bad request when it doesn't match any route
	mainrouter.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadRequest) })

	go s.executorTasksCleanerLoop(ctx)
	go s.runsSchedulerLoop(ctx)
	go s.runTasksUpdaterLoop(ctx)
	go s.fetcherLoop(ctx)
	go s.finishedRunsArchiverLoop(ctx)
	go s.dumpLTSLoop(ctx)
	go s.dumpLTSCleanerLoop(ctx)
	go s.compactChangeGroupsLoop(ctx)

	go s.executorTaskUpdateHandler(ctx, ch)

	var tlsConfig *tls.Config
	if s.c.Web.TLS {
		var err error
		tlsConfig, err = util.NewTLSConfig(s.c.Web.TLSCertFile, s.c.Web.TLSKeyFile, "", false)
		if err != nil {
			log.Errorf("err: %+v")
			return err
		}
	}

	httpServer := http.Server{
		Addr:      s.c.Web.ListenAddress,
		Handler:   mainrouter,
		TLSConfig: tlsConfig,
	}

	lerrCh := make(chan error)
	go func() {
		lerrCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		log.Infof("runservice scheduler exiting")
		httpServer.Close()
		return nil
	case err := <-lerrCh:
		log.Errorf("http server listen error: %v", err)
		return err
	case err := <-errCh:
		log.Errorf("error: %+v", err)
		return err
	}
}
