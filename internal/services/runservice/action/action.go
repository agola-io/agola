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

package action

import (
	"context"
	"fmt"
	"path"
	"time"

	"agola.io/agola/internal/datamanager"
	"agola.io/agola/internal/db"
	"agola.io/agola/internal/etcd"
	"agola.io/agola/internal/objectstorage"
	"agola.io/agola/internal/runconfig"
	"agola.io/agola/internal/sequence"
	"agola.io/agola/internal/services/runservice/common"
	"agola.io/agola/internal/services/runservice/readdb"
	"agola.io/agola/internal/services/runservice/store"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/runservice/types"

	"go.uber.org/zap"
	errors "golang.org/x/xerrors"
)

type ActionHandler struct {
	log             *zap.SugaredLogger
	e               *etcd.Store
	readDB          *readdb.ReadDB
	ost             *objectstorage.ObjStorage
	dm              *datamanager.DataManager
	maintenanceMode bool
}

func NewActionHandler(logger *zap.Logger, e *etcd.Store, readDB *readdb.ReadDB, ost *objectstorage.ObjStorage, dm *datamanager.DataManager) *ActionHandler {
	return &ActionHandler{
		log:             logger.Sugar(),
		e:               e,
		readDB:          readDB,
		ost:             ost,
		dm:              dm,
		maintenanceMode: false,
	}
}

func (h *ActionHandler) SetMaintenanceMode(maintenanceMode bool) {
	h.maintenanceMode = maintenanceMode
}

type RunChangePhaseRequest struct {
	RunID                   string
	Phase                   types.RunPhase
	ChangeGroupsUpdateToken string
}

func (h *ActionHandler) ChangeRunPhase(ctx context.Context, req *RunChangePhaseRequest) error {
	cgt, err := types.UnmarshalChangeGroupsUpdateToken(req.ChangeGroupsUpdateToken)
	if err != nil {
		return err
	}

	r, _, err := store.GetRun(ctx, h.e, req.RunID)
	if err != nil {
		return err
	}

	var runEvent *types.RunEvent

	switch req.Phase {
	case types.RunPhaseRunning:
		if r.Phase != types.RunPhaseQueued {
			return errors.Errorf("run %q is not queued but in %q phase", r.ID, r.Phase)
		}
		r.ChangePhase(types.RunPhaseRunning)
		runEvent, err = common.NewRunEvent(ctx, h.e, r.ID, r.Phase, r.Result)
		if err != nil {
			return err
		}
	case types.RunPhaseCancelled:
		if r.Phase != types.RunPhaseQueued {
			return errors.Errorf("run %q is not queued but in %q phase", r.ID, r.Phase)
		}
		r.ChangePhase(types.RunPhaseCancelled)
		runEvent, err = common.NewRunEvent(ctx, h.e, r.ID, r.Phase, r.Result)
		if err != nil {
			return err
		}
	default:
		return errors.Errorf("unsupport change phase %q", req.Phase)

	}

	_, err = store.AtomicPutRun(ctx, h.e, r, runEvent, cgt)
	return err
}

type RunStopRequest struct {
	RunID                   string
	ChangeGroupsUpdateToken string
}

func (h *ActionHandler) StopRun(ctx context.Context, req *RunStopRequest) error {
	cgt, err := types.UnmarshalChangeGroupsUpdateToken(req.ChangeGroupsUpdateToken)
	if err != nil {
		return err
	}

	r, _, err := store.GetRun(ctx, h.e, req.RunID)
	if err != nil {
		return err
	}

	if r.Phase != types.RunPhaseRunning {
		return errors.Errorf("run %s is not running but in %q phase", r.ID, r.Phase)
	}
	r.Stop = true

	_, err = store.AtomicPutRun(ctx, h.e, r, nil, cgt)
	return err
}

type RunCreateRequest struct {
	RunConfigTasks    map[string]*types.RunConfigTask
	Name              string
	Group             string
	SetupErrors       []string
	StaticEnvironment map[string]string
	CacheGroup        string

	// existing run fields
	RunID      string
	FromStart  bool
	ResetTasks []string

	// common fields
	Environment map[string]string
	Annotations map[string]string

	ChangeGroupsUpdateToken string
}

func (h *ActionHandler) CreateRun(ctx context.Context, req *RunCreateRequest) (*types.RunBundle, error) {
	runcgt, err := types.UnmarshalChangeGroupsUpdateToken(req.ChangeGroupsUpdateToken)
	if err != nil {
		return nil, err
	}

	var rb *types.RunBundle
	if req.RunID == "" {
		rb, err = h.newRun(ctx, req)
	} else {
		rb, err = h.recreateRun(ctx, req)
	}
	if err != nil {
		return nil, err
	}

	return rb, h.saveRun(ctx, rb, runcgt)
}

func (h *ActionHandler) newRun(ctx context.Context, req *RunCreateRequest) (*types.RunBundle, error) {
	rcts := req.RunConfigTasks
	setupErrors := req.SetupErrors

	if req.Group == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("run group is empty"))
	}
	if !path.IsAbs(req.Group) {
		return nil, util.NewErrBadRequest(errors.Errorf("run group %q must be an absolute path", req.Group))
	}
	if req.RunConfigTasks == nil && len(setupErrors) == 0 {
		return nil, util.NewErrBadRequest(errors.Errorf("empty run config tasks and setup errors"))
	}

	// generate a new run sequence that will be the same for the run and runconfig
	seq, err := sequence.IncSequence(ctx, h.e, common.EtcdRunSequenceKey)
	if err != nil {
		return nil, err
	}
	id := seq.String()

	if err := runconfig.CheckRunConfigTasks(rcts); err != nil {
		h.log.Errorf("check run config tasks failed: %+v", err)
		setupErrors = append(setupErrors, err.Error())
	}

	// generate tasks levels
	if len(setupErrors) == 0 {
		if err := runconfig.GenTasksLevels(rcts); err != nil {
			h.log.Errorf("gen tasks leveles failed: %+v", err)
			setupErrors = append(setupErrors, err.Error())
		}
	}

	rc := &types.RunConfig{
		ID:                id,
		Name:              req.Name,
		Group:             req.Group,
		SetupErrors:       setupErrors,
		Tasks:             rcts,
		StaticEnvironment: req.StaticEnvironment,
		Environment:       req.Environment,
		Annotations:       req.Annotations,
		CacheGroup:        req.CacheGroup,
	}

	run := genRun(rc)
	h.log.Debugf("created run: %s", util.Dump(run))

	return &types.RunBundle{
		Run: run,
		Rc:  rc,
	}, nil
}

func (h *ActionHandler) recreateRun(ctx context.Context, req *RunCreateRequest) (*types.RunBundle, error) {
	// generate a new run sequence that will be the same for the run and runconfig
	seq, err := sequence.IncSequence(ctx, h.e, common.EtcdRunSequenceKey)
	if err != nil {
		return nil, err
	}
	id := seq.String()

	// fetch the existing runconfig and run
	h.log.Infof("creating run from existing run")
	rc, err := store.OSTGetRunConfig(h.dm, req.RunID)
	if err != nil {
		return nil, util.NewErrBadRequest(errors.Errorf("runconfig %q doesn't exist: %w", req.RunID, err))
	}

	run, err := store.GetRunEtcdOrOST(ctx, h.e, h.dm, req.RunID)
	if err != nil {
		return nil, err
	}
	if run == nil {
		return nil, util.NewErrBadRequest(errors.Errorf("run %q doesn't exist: %w", req.RunID, err))
	}

	h.log.Debugf("rc: %s", util.Dump(rc))
	h.log.Debugf("run: %s", util.Dump(run))

	if req.FromStart {
		if canRestart, reason := run.CanRestartFromScratch(); !canRestart {
			return nil, util.NewErrBadRequest(errors.Errorf("run cannot be restarted: %s", reason))
		}
	} else {
		if canRestart, reason := run.CanRestartFromFailedTasks(); !canRestart {
			return nil, util.NewErrBadRequest(errors.Errorf("run cannot be restarted: %s", reason))
		}
	}

	rb := recreateRun(util.DefaultUUIDGenerator{}, run, rc, id, req)

	h.log.Debugf("created rc from existing rc: %s", util.Dump(rb.Rc))
	h.log.Debugf("created run from existing run: %s", util.Dump(rb.Run))

	return rb, nil
}

func recreateRun(uuid util.UUIDGenerator, run *types.Run, rc *types.RunConfig, newID string, req *RunCreateRequest) *types.RunBundle {
	// update the run config ID
	rc.ID = newID
	// update the run config Environment
	rc.Environment = req.Environment

	// update the run ID
	run.ID = newID
	// reset run revision
	run.Revision = 0
	// reset phase/result/archived/stop
	run.Phase = types.RunPhaseQueued
	run.Result = types.RunResultUnknown
	run.Archived = false
	run.Stop = false
	run.EnqueueTime = nil
	run.StartTime = nil
	run.EndTime = nil

	// TODO(sgotti) handle reset tasks
	// currently we only restart a run resetting al failed tasks
	recreatedRCTasks := map[string]struct{}{}

	for _, rt := range run.Tasks {
		if req.FromStart || rt.Status != types.RunTaskStatusSuccess {
			rct, ok := rc.Tasks[rt.ID]
			if !ok {
				panic(fmt.Errorf("no runconfig task %q", rt.ID))
			}
			// change rct id
			rct.ID = uuid.New(rct.Name).String()

			// update runconfig with new tasks
			delete(rc.Tasks, rt.ID)
			rc.Tasks[rct.ID] = rct

			// update other runconfig tasks depends to new task id
			for _, t := range rc.Tasks {
				if d, ok := t.Depends[rt.ID]; ok {
					delete(t.Depends, rt.ID)
					nd := &types.RunConfigTaskDepend{
						TaskID:     rct.ID,
						Conditions: d.Conditions,
					}
					t.Depends[rct.ID] = nd
				}
			}

			recreatedRCTasks[rct.ID] = struct{}{}
		}
	}

	// also recreate all runconfig tasks that are childs of a previously recreated
	// runconfig task
	rcTasksToRecreate := map[string]struct{}{}
	for _, rct := range rc.Tasks {
		parents := runconfig.GetAllParents(rc.Tasks, rct)
		for _, parent := range parents {
			if _, ok := recreatedRCTasks[parent.ID]; ok {
				rcTasksToRecreate[rct.ID] = struct{}{}
				break
			}
		}
	}

	for rcTaskToRecreate := range rcTasksToRecreate {
		rct := rc.Tasks[rcTaskToRecreate]
		// change rct id
		rct.ID = uuid.New(rct.Name).String()

		// update runconfig with new tasks
		delete(rc.Tasks, rcTaskToRecreate)
		rc.Tasks[rct.ID] = rct

		// update other runconfig tasks depends to new task id
		for _, t := range rc.Tasks {
			if d, ok := t.Depends[rcTaskToRecreate]; ok {
				delete(t.Depends, rcTaskToRecreate)
				nd := &types.RunConfigTaskDepend{
					TaskID:     rct.ID,
					Conditions: d.Conditions,
				}
				t.Depends[rct.ID] = nd
			}
		}
	}

	// update run

	// remove deleted tasks from run config
	tasksToDelete := []string{}
	for _, rt := range run.Tasks {
		if _, ok := rc.Tasks[rt.ID]; !ok {
			tasksToDelete = append(tasksToDelete, rt.ID)
		}
	}
	for _, rtID := range tasksToDelete {
		delete(run.Tasks, rtID)
	}
	// create new tasks from runconfig
	for _, rct := range rc.Tasks {
		if _, ok := run.Tasks[rct.ID]; !ok {
			nrt := genRunTask(rct)
			run.Tasks[nrt.ID] = nrt
		}
	}

	return &types.RunBundle{
		Run: run,
		Rc:  rc,
	}
}

func (h *ActionHandler) saveRun(ctx context.Context, rb *types.RunBundle, runcgt *types.ChangeGroupsUpdateToken) error {
	run := rb.Run
	rc := rb.Rc

	c, cgt, err := h.getRunCounter(ctx, run.Group)
	h.log.Debugf("c: %d, cgt: %s", c, util.Dump(cgt))
	if err != nil {
		return err
	}
	c++
	run.Counter = c

	run.EnqueueTime = util.TimeP(time.Now())

	actions := []*datamanager.Action{}

	// persist group counter
	rca, err := store.OSTUpdateRunCounterAction(ctx, c, run.Group)
	if err != nil {
		return err
	}
	actions = append(actions, rca)

	// persist run config
	rca, err = store.OSTSaveRunConfigAction(rc)
	if err != nil {
		return err
	}
	actions = append(actions, rca)

	if _, err = h.dm.WriteWal(ctx, actions, cgt); err != nil {
		return err
	}

	runEvent, err := common.NewRunEvent(ctx, h.e, run.ID, run.Phase, run.Result)
	if err != nil {
		return err
	}
	if _, err := store.AtomicPutRun(ctx, h.e, run, runEvent, runcgt); err != nil {
		return err
	}
	return nil
}

func genRunTask(rct *types.RunConfigTask) *types.RunTask {
	rt := &types.RunTask{
		ID:                rct.ID,
		Status:            types.RunTaskStatusNotStarted,
		Skip:              rct.Skip,
		Steps:             make([]*types.RunTaskStep, len(rct.Steps)),
		WorkspaceArchives: []int{},
	}
	if rt.Skip {
		rt.Status = types.RunTaskStatusSkipped
	}
	rt.SetupStep = types.RunTaskStep{
		Phase:    types.ExecutorTaskPhaseNotStarted,
		LogPhase: types.RunTaskFetchPhaseNotStarted,
	}
	for i := range rt.Steps {
		s := &types.RunTaskStep{
			Phase:    types.ExecutorTaskPhaseNotStarted,
			LogPhase: types.RunTaskFetchPhaseNotStarted,
		}
		rt.Steps[i] = s
	}
	for i, ps := range rct.Steps {
		switch ps.(type) {
		case *types.SaveToWorkspaceStep:
			rt.WorkspaceArchives = append(rt.WorkspaceArchives, i)
		}
	}
	rt.WorkspaceArchivesPhase = make([]types.RunTaskFetchPhase, len(rt.WorkspaceArchives))
	for i := range rt.WorkspaceArchivesPhase {
		rt.WorkspaceArchivesPhase[i] = types.RunTaskFetchPhaseNotStarted
	}

	return rt
}

func genRun(rc *types.RunConfig) *types.Run {
	r := &types.Run{
		ID:          rc.ID,
		Name:        rc.Name,
		Group:       rc.Group,
		Annotations: rc.Annotations,
		Phase:       types.RunPhaseQueued,
		Result:      types.RunResultUnknown,
		Tasks:       make(map[string]*types.RunTask),
	}

	if len(rc.SetupErrors) > 0 {
		r.Phase = types.RunPhaseSetupError
		return r
	}

	for _, rct := range rc.Tasks {
		rt := genRunTask(rct)
		r.Tasks[rt.ID] = rt
	}

	return r
}

type RunTaskSetAnnotationsRequest struct {
	RunID                   string
	TaskID                  string
	Annotations             map[string]string
	ChangeGroupsUpdateToken string
}

func (h *ActionHandler) RunTaskSetAnnotations(ctx context.Context, req *RunTaskSetAnnotationsRequest) error {
	cgt, err := types.UnmarshalChangeGroupsUpdateToken(req.ChangeGroupsUpdateToken)
	if err != nil {
		return err
	}

	r, _, err := store.GetRun(ctx, h.e, req.RunID)
	if err != nil {
		return err
	}

	task, ok := r.Tasks[req.TaskID]
	if !ok {
		return util.NewErrBadRequest(errors.Errorf("run %q doesn't have task %q", r.ID, req.TaskID))
	}

	task.Annotations = req.Annotations

	_, err = store.AtomicPutRun(ctx, h.e, r, nil, cgt)
	return err
}

type RunTaskApproveRequest struct {
	RunID                   string
	TaskID                  string
	ChangeGroupsUpdateToken string
}

func (h *ActionHandler) ApproveRunTask(ctx context.Context, req *RunTaskApproveRequest) error {
	cgt, err := types.UnmarshalChangeGroupsUpdateToken(req.ChangeGroupsUpdateToken)
	if err != nil {
		return err
	}

	r, _, err := store.GetRun(ctx, h.e, req.RunID)
	if err != nil {
		return err
	}

	task, ok := r.Tasks[req.TaskID]
	if !ok {
		return util.NewErrBadRequest(errors.Errorf("run %q doesn't have task %q", r.ID, req.TaskID))
	}

	if !task.WaitingApproval {
		return util.NewErrBadRequest(errors.Errorf("run %q, task %q is not in waiting approval state", r.ID, req.TaskID))
	}

	if task.Approved {
		return util.NewErrBadRequest(errors.Errorf("run %q, task %q is already approved", r.ID, req.TaskID))
	}

	task.WaitingApproval = false
	task.Approved = true

	_, err = store.AtomicPutRun(ctx, h.e, r, nil, cgt)
	return err
}

func (h *ActionHandler) DeleteExecutor(ctx context.Context, executorID string) error {
	if err := store.DeleteExecutor(ctx, h.e, executorID); err != nil {
		return err
	}

	return nil
}

func (h *ActionHandler) getRunCounter(ctx context.Context, group string) (uint64, *datamanager.ChangeGroupsUpdateToken, error) {
	// use the first group dir after the root
	pl := util.PathList(group)
	if len(pl) < 2 {
		return 0, nil, errors.Errorf("cannot determine group counter name, wrong group path %q", group)
	}

	var c uint64
	var cgt *datamanager.ChangeGroupsUpdateToken
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		c, err = h.readDB.GetRunCounterOST(tx, pl[1])
		if err != nil {
			return err
		}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokensOST(tx, []string{"counter-" + pl[1]})
		return err
	})
	if err != nil {
		return 0, nil, err
	}

	return c, cgt, nil
}

func (h *ActionHandler) GetExecutorTask(ctx context.Context, etID string) (*types.ExecutorTask, error) {
	et, err := store.GetExecutorTask(ctx, h.e, etID)
	if err != nil && err != etcd.ErrKeyNotFound {
		return nil, err
	}
	if et == nil {
		return nil, util.NewErrNotExist(errors.Errorf("executor task %q not found", etID))
	}

	r, _, err := store.GetRun(ctx, h.e, et.Spec.RunID)
	if err != nil {
		return nil, errors.Errorf("cannot get run %q: %w", et.Spec.RunID, err)
	}
	rc, err := store.OSTGetRunConfig(h.dm, r.ID)
	if err != nil {
		return nil, errors.Errorf("cannot get run config %q: %w", r.ID, err)
	}
	rt, ok := r.Tasks[et.ID]
	if !ok {
		return nil, errors.Errorf("no such run task with id %s for run %s", et.ID, r.ID)
	}

	// generate ExecutorTaskSpecData
	et.Spec.ExecutorTaskSpecData = common.GenExecutorTaskSpecData(r, rt, rc)

	return et, nil
}

func (h *ActionHandler) GetExecutorTasks(ctx context.Context, executorID string) ([]*types.ExecutorTask, error) {
	ets, err := store.GetExecutorTasksForExecutor(ctx, h.e, executorID)
	if err != nil && err != etcd.ErrKeyNotFound {
		return nil, err
	}

	for _, et := range ets {
		r, _, err := store.GetRun(ctx, h.e, et.Spec.RunID)
		if err != nil {
			return nil, errors.Errorf("cannot get run %q: %w", et.Spec.RunID, err)
		}
		rc, err := store.OSTGetRunConfig(h.dm, r.ID)
		if err != nil {
			return nil, errors.Errorf("cannot get run config %q: %w", r.ID, err)
		}
		rt, ok := r.Tasks[et.ID]
		if !ok {
			return nil, errors.Errorf("no such run task with id %s for run %s", et.ID, r.ID)
		}

		// generate ExecutorTaskSpecData
		et.Spec.ExecutorTaskSpecData = common.GenExecutorTaskSpecData(r, rt, rc)
	}

	return ets, nil
}
