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
	"path"
	"reflect"
	"sync"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/objectstorage"
	"agola.io/agola/internal/runconfig"
	serrors "agola.io/agola/internal/services/errors"
	"agola.io/agola/internal/services/runservice/common"
	"agola.io/agola/internal/services/runservice/db"
	"agola.io/agola/internal/sqlg/lock"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/runservice/types"
)

type ActionHandler struct {
	log                  zerolog.Logger
	d                    *db.DB
	ost                  objectstorage.ObjStorage
	lf                   lock.LockFactory
	maintenanceMode      bool
	maintenanceModeMutex sync.Mutex
}

func NewActionHandler(log zerolog.Logger, d *db.DB, ost objectstorage.ObjStorage, lf lock.LockFactory) *ActionHandler {
	return &ActionHandler{
		log:             log,
		d:               d,
		ost:             ost,
		lf:              lf,
		maintenanceMode: false,
	}
}

type GetGroupRunsRequest struct {
	Group string

	Limit         int
	SortDirection types.SortDirection

	ChangeGroups    []string
	StartRunCounter uint64
	PhaseFilter     []types.RunPhase
	ResultFilter    []types.RunResult
}

type GetGroupRunsResponse struct {
	Runs                    []*types.Run
	ChangeGroupsUpdateToken string

	HasMore bool
}

func (h *ActionHandler) GetGroupRuns(ctx context.Context, req *GetGroupRunsRequest) (*GetGroupRunsResponse, error) {
	limit := req.Limit
	if limit > 0 {
		limit += 1
	}
	if req.SortDirection == "" {
		req.SortDirection = types.SortDirectionDesc
	}

	var runs []*types.Run
	var cgt *types.ChangeGroupsUpdateToken

	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		runs, err = h.d.GetGroupRuns(tx, req.Group, req.PhaseFilter, req.ResultFilter, req.StartRunCounter, limit, req.SortDirection)
		if err != nil {
			h.log.Err(err).Send()
			return errors.WithStack(err)
		}

		cgt, err = h.GetChangeGroupsUpdateTokens(tx, req.ChangeGroups)
		return errors.WithStack(err)
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	cgts, err := types.MarshalChangeGroupsUpdateToken(cgt)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var hasMore bool
	if req.Limit > 0 {
		hasMore = len(runs) > req.Limit
		if hasMore {
			runs = runs[0:req.Limit]
		}
	}

	return &GetGroupRunsResponse{
		Runs:                    runs,
		ChangeGroupsUpdateToken: cgts,
		HasMore:                 hasMore,
	}, nil
}

type RunChangePhaseRequest struct {
	RunID                   string
	Phase                   types.RunPhase
	ChangeGroupsUpdateToken string
}

func (h *ActionHandler) genChangeGroupsUpdateTokens(changeGroups []*types.ChangeGroup) *types.ChangeGroupsUpdateToken {
	changeGroupsValues := map[string]string{}

	for _, changeGroup := range changeGroups {
		changeGroupsValues[changeGroup.Name] = changeGroup.Value
	}

	return &types.ChangeGroupsUpdateToken{ChangeGroupsValues: changeGroupsValues}
}

func (h *ActionHandler) GetChangeGroupsUpdateTokens(tx *sql.Tx, changeGroupsNames []string) (*types.ChangeGroupsUpdateToken, error) {
	changeGroups, err := h.d.GetChangeGroupsByNames(tx, changeGroupsNames)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	for _, changeGroupName := range changeGroupsNames {
		found := false

		for _, changeGroup := range changeGroups {
			if changeGroup.Name == changeGroupName {
				found = true
				break
			}
		}

		// create and insert non existing changegroup
		if !found {
			newChangeGroup := types.NewChangeGroup(tx)
			newChangeGroup.Name = changeGroupName
			newChangeGroup.Value = uuid.Must(uuid.NewV4()).String()

			changeGroups = append(changeGroups, newChangeGroup)

			if err := h.d.InsertChangeGroup(tx, newChangeGroup); err != nil {
				return nil, errors.WithStack(err)
			}
		}

	}

	return h.genChangeGroupsUpdateTokens(changeGroups), nil
}

func (h *ActionHandler) UpdateChangeGroups(tx *sql.Tx, cgt *types.ChangeGroupsUpdateToken) error {
	if cgt == nil {
		return nil
	}

	changeGroupsNames := []string{}
	for name := range cgt.ChangeGroupsValues {
		changeGroupsNames = append(changeGroupsNames, name)
	}

	// check that all token provided changegroups exists and have the same value
	curChangeGroups, err := h.d.GetChangeGroupsByNames(tx, changeGroupsNames)
	if err != nil {
		return errors.WithStack(err)
	}

	curCgt := h.genChangeGroupsUpdateTokens(curChangeGroups)
	if !reflect.DeepEqual(cgt, curCgt) {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("concurrent update"))
	}

	for _, curChangeGroup := range curChangeGroups {
		// update all change group values
		curChangeGroup.Value = uuid.Must(uuid.NewV4()).String()
		if err := h.d.InsertOrUpdateChangeGroup(tx, curChangeGroup); err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

func (h *ActionHandler) ChangeRunPhase(ctx context.Context, req *RunChangePhaseRequest) error {
	cgt, err := types.UnmarshalChangeGroupsUpdateToken(req.ChangeGroupsUpdateToken)
	if err != nil {
		return errors.WithStack(err)
	}

	err = h.d.Do(ctx, func(tx *sql.Tx) error {
		run, err := h.d.GetRun(tx, req.RunID)
		if err != nil {
			return errors.WithStack(err)
		}

		if run == nil {
			return errors.Errorf("run %q does not exists", req.RunID)
		}

		if err := h.UpdateChangeGroups(tx, cgt); err != nil {
			return errors.WithStack(err)
		}

		switch req.Phase {
		case types.RunPhaseRunning:
			fallthrough
		case types.RunPhaseCancelled:
			if run.Phase != types.RunPhaseQueued {
				return errors.Errorf("run %q is not queued but in %q phase", run.ID, run.Phase)
			}
		default:
			return errors.Errorf("unsupport change phase %q", req.Phase)
		}

		rc, err := h.d.GetRunConfig(tx, run.RunConfigID)
		if err != nil {
			return errors.WithStack(err)
		}

		run.ChangePhase(req.Phase)
		runEvent, err := common.NewRunEvent(h.d, tx, run, rc, types.RunPhaseChanged)
		if err != nil {
			return errors.WithStack(err)
		}

		if err := h.d.UpdateRun(tx, run); err != nil {
			return errors.WithStack(err)
		}
		if err := h.d.InsertRunEvent(tx, runEvent); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

type RunStopRequest struct {
	RunID                   string
	ChangeGroupsUpdateToken string
}

func (h *ActionHandler) StopRun(ctx context.Context, req *RunStopRequest) error {
	cgt, err := types.UnmarshalChangeGroupsUpdateToken(req.ChangeGroupsUpdateToken)
	if err != nil {
		return errors.WithStack(err)
	}

	err = h.d.Do(ctx, func(tx *sql.Tx) error {
		r, err := h.d.GetRun(tx, req.RunID)
		if err != nil {
			return errors.WithStack(err)
		}

		if r == nil {
			return errors.Errorf("run %q does not exists", req.RunID)
		}

		if err := h.UpdateChangeGroups(tx, cgt); err != nil {
			return errors.WithStack(err)
		}

		if r.Phase != types.RunPhaseRunning {
			return errors.Errorf("run %s is not running but in %q phase", r.ID, r.Phase)
		}
		r.Stop = true
		for _, t := range r.TasksWaitingApproval() {
			r.Tasks[t].WaitingApproval = false
		}

		if err := h.d.UpdateRun(tx, r); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return errors.WithStack(err)
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
		return nil, errors.WithStack(err)
	}

	var rb *types.RunBundle
	if req.RunID == "" {
		rb, err = h.newRun(ctx, req)
	} else {
		rb, err = h.recreateRun(ctx, req)
	}
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return rb, h.saveRun(ctx, rb, runcgt)
}

func (h *ActionHandler) newRun(ctx context.Context, req *RunCreateRequest) (*types.RunBundle, error) {
	rcts := req.RunConfigTasks
	setupErrors := req.SetupErrors

	if req.Group == "" {
		return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("run group is empty"), serrors.InvalidRunGroup())
	}
	if !path.IsAbs(req.Group) {
		return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsgf("run group %q must be an absolute path", req.Group), serrors.InvalidRunGroup())
	}
	if req.RunConfigTasks == nil && len(setupErrors) == 0 {
		return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("empty run config tasks and setup errors"))
	}

	if err := runconfig.CheckRunConfigTasks(rcts); err != nil {
		h.log.Err(err).Msg("check run config tasks failed")
		setupErrors = append(setupErrors, err.Error())
	}

	// generate tasks levels
	if len(setupErrors) == 0 {
		if err := runconfig.GenTasksLevels(rcts); err != nil {
			h.log.Err(err).Msg("gen tasks leveles failed")
			setupErrors = append(setupErrors, err.Error())
		}
	}

	rc := types.NewRunConfig(nil)
	rc.Name = req.Name
	rc.Group = req.Group
	rc.SetupErrors = setupErrors
	rc.Tasks = rcts
	rc.StaticEnvironment = req.StaticEnvironment
	rc.Environment = req.Environment
	rc.Annotations = req.Annotations
	rc.CacheGroup = req.CacheGroup

	run := genRun(rc)
	h.log.Debug().Msgf("created run: %s", util.Dump(run))

	return &types.RunBundle{
		Run: run,
		Rc:  rc,
	}, nil
}

func (h *ActionHandler) recreateRun(ctx context.Context, req *RunCreateRequest) (*types.RunBundle, error) {
	// fetch the existing runconfig and run
	h.log.Info().Msg("creating run from existing run")

	var rc *types.RunConfig
	var run *types.Run
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error

		run, err = h.d.GetRun(tx, req.RunID)
		if err != nil {
			return errors.WithStack(err)
		}
		if run == nil {
			return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsgf("run %q doesn't exist", req.RunID), serrors.RunDoesNotExist())
		}

		rc, err = h.d.GetRunConfig(tx, run.RunConfigID)
		if err != nil {
			return errors.WithStack(err)
		}
		if rc == nil {
			return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsgf("runconfig %q doesn't exist", run.RunConfigID), serrors.RunDoesNotExist())
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	h.log.Debug().Msgf("rc: %s", util.Dump(rc))
	h.log.Debug().Msgf("run: %s", util.Dump(run))

	if req.FromStart {
		if canRestart, reason := run.CanRestartFromScratch(); !canRestart {
			return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsgf("run cannot be restarted: %s", reason), serrors.RunCannotBeRestarted())
		}
	} else {
		if canRestart, reason := run.CanRestartFromFailedTasks(); !canRestart {
			return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsgf("run cannot be restarted: %s", reason), serrors.RunCannotBeRestarted())
		}
	}

	newRunID := uuid.Must(uuid.NewV4()).String()
	newRunConfigID := uuid.Must(uuid.NewV4()).String()
	rb := recreateRun(util.DefaultUUIDGenerator{}, run, rc, newRunID, newRunConfigID, req)

	h.log.Debug().Msgf("created rc from existing rc: %s", util.Dump(rb.Rc))
	h.log.Debug().Msgf("created run from existing run: %s", util.Dump(rb.Run))

	return rb, nil
}

func recreateRun(uuid util.UUIDGenerator, run *types.Run, rc *types.RunConfig, newRunID, newRunConfigID string, req *RunCreateRequest) *types.RunBundle {
	// update the run config ID
	rc.ID = newRunConfigID
	// reset run config revision
	// TODO(sgotti) this isn't very clean. We're doing this since we're taking an existing run config and changing only some fields
	rc.Revision = 0
	// update the run config Environment
	rc.Environment = req.Environment

	// update the run ID
	run.ID = newRunID
	// reset run revision
	// TODO(sgotti) this isn't very clean. We're doing this since we're taking an existing run and changing only some fields
	run.Revision = 0
	// reset phase/result/archived/stop
	run.RunConfigID = rc.ID
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
				panic(errors.Errorf("no runconfig task %q", rt.ID))
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

	runCounterGroupID, err := h.getRunCounterGroupID(run.Group)
	if err != nil {
		return errors.WithStack(err)
	}

	run.EnqueueTime = util.Ptr(time.Now())

	err = h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error

		// set objects tx id, revision since they were created outside the transaction
		run.TxID = tx.ID()
		run.Revision = 0

		rc.TxID = tx.ID()
		rc.Revision = 0

		if err := h.UpdateChangeGroups(tx, runcgt); err != nil {
			return errors.WithStack(err)
		}

		// generate a new run counter
		runCounter, err := h.d.NextRunCounter(tx, runCounterGroupID)
		if err != nil {
			return errors.WithStack(err)
		}

		run.Counter = runCounter

		runEvent, err := common.NewRunEvent(h.d, tx, run, rc, types.RunPhaseChanged)
		if err != nil {
			return errors.WithStack(err)
		}

		if err := h.d.InsertRunConfig(tx, rc); err != nil {
			return errors.WithStack(err)
		}
		if err := h.d.InsertRun(tx, run); err != nil {
			return errors.WithStack(err)
		}
		if err := h.d.InsertRunEvent(tx, runEvent); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
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
	r := types.NewRun(nil)
	r.RunConfigID = rc.ID
	r.Name = rc.Name
	r.Group = rc.Group
	r.Annotations = rc.Annotations
	r.Phase = types.RunPhaseQueued
	r.Result = types.RunResultUnknown
	r.Tasks = make(map[string]*types.RunTask)

	if len(rc.SetupErrors) > 0 {
		r.Phase = types.RunPhaseSetupError
		return r
	}

	for id, rct := range rc.Tasks {
		rt := genRunTask(rct)
		r.Tasks[id] = rt
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
		return errors.WithStack(err)
	}

	err = h.d.Do(ctx, func(tx *sql.Tx) error {
		r, err := h.d.GetRun(tx, req.RunID)
		if err != nil {
			return errors.WithStack(err)
		}

		if r == nil {
			return errors.Errorf("run %q does not exists", req.RunID)
		}

		if err := h.UpdateChangeGroups(tx, cgt); err != nil {
			return errors.WithStack(err)
		}

		task, ok := r.Tasks[req.TaskID]
		if !ok {
			return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsgf("run %q doesn't have task %q", r.ID, req.TaskID), serrors.RunTaskDoesNotExist())
		}

		task.Annotations = req.Annotations

		if err := h.d.UpdateRun(tx, r); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

type RunTaskApproveRequest struct {
	RunID                   string
	TaskID                  string
	ChangeGroupsUpdateToken string
}

func (h *ActionHandler) ApproveRunTask(ctx context.Context, req *RunTaskApproveRequest) error {
	cgt, err := types.UnmarshalChangeGroupsUpdateToken(req.ChangeGroupsUpdateToken)
	if err != nil {
		return errors.WithStack(err)
	}

	err = h.d.Do(ctx, func(tx *sql.Tx) error {
		r, err := h.d.GetRun(tx, req.RunID)
		if err != nil {
			return errors.WithStack(err)
		}

		if r == nil {
			return errors.Errorf("run %q does not exists", req.RunID)
		}

		if err := h.UpdateChangeGroups(tx, cgt); err != nil {
			return errors.WithStack(err)
		}

		task, ok := r.Tasks[req.TaskID]
		if !ok {
			return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsgf("run %q doesn't have task %q", r.ID, req.TaskID), serrors.RunTaskDoesNotExist())
		}

		if !task.WaitingApproval {
			return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsgf("run %q, task %q is not in waiting approval state", r.ID, req.TaskID), serrors.RunTaskNotWaitingApproval())
		}

		if task.Approved {
			return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsgf("run %q, task %q is already approved", r.ID, req.TaskID), serrors.RunTaskAlreadyApproved())
		}

		task.WaitingApproval = false
		task.Approved = true

		if err := h.d.UpdateRun(tx, r); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (h *ActionHandler) getRunCounterGroupID(group string) (string, error) {
	// use the first group dir after the root
	pl := util.PathList(group)
	if len(pl) < 2 {
		return "", errors.Errorf("cannot determine group counter name, wrong group path %q", group)
	}
	return pl[1], nil
}

type GetExecutorTaskResponse struct {
	Et         *types.ExecutorTask
	EtSpecData *types.ExecutorTaskSpecData
}

func (h *ActionHandler) GetExecutorTask(ctx context.Context, etID string) (*GetExecutorTaskResponse, error) {
	var et *types.ExecutorTask
	var etSpecData *types.ExecutorTaskSpecData
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error

		et, err = h.d.GetExecutorTask(tx, etID)
		if err != nil {
			return errors.WithStack(err)
		}
		if et == nil {
			return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsgf("executor task %q not found", etID))
		}

		r, err := h.d.GetRun(tx, et.RunID)
		if err != nil {
			return errors.Wrapf(err, "cannot get run %q", et.RunID)
		}
		if r == nil {
			return errors.Errorf("run %q does not exists", et.RunID)
		}

		rc, err := h.d.GetRunConfig(tx, r.RunConfigID)
		if err != nil {
			return errors.Wrapf(err, "cannot get run config %q", r.ID)
		}
		if rc == nil {
			return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsgf("runconfig %q doesn't exist", r.RunConfigID))
		}

		rt, ok := r.Tasks[et.RunTaskID]
		if !ok {
			return errors.Errorf("no such run task with id %s for run %s", et.RunTaskID, r.ID)
		}

		// generate ExecutorTaskSpecData
		etSpecData = common.GenExecutorTaskSpecData(r, rt, rc)

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &GetExecutorTaskResponse{et, etSpecData}, nil
}

func (h *ActionHandler) GetExecutorTasks(ctx context.Context, executorID string) ([]*GetExecutorTaskResponse, error) {
	var res []*GetExecutorTaskResponse
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error

		ets, err := h.d.GetExecutorTasksByExecutor(tx, executorID)
		if err != nil {
			return errors.WithStack(err)
		}

		for _, et := range ets {
			r, err := h.d.GetRun(tx, et.RunID)
			if err != nil {
				return errors.Wrapf(err, "cannot get run %q", et.RunID)
			}
			if r == nil {
				return errors.Errorf("run %q does not exists", et.RunID)
			}

			rc, err := h.d.GetRunConfig(tx, r.RunConfigID)
			if err != nil {
				return errors.Wrapf(err, "cannot get run config %q", r.ID)
			}
			if rc == nil {
				return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsgf("runconfig %q doesn't exist", r.RunConfigID))
			}

			rt, ok := r.Tasks[et.RunTaskID]
			if !ok {
				return errors.Errorf("no such run task with id %s for run %s", et.RunTaskID, r.ID)
			}

			// generate ExecutorTaskSpecData
			etSpecData := common.GenExecutorTaskSpecData(r, rt, rc)
			res = append(res, &GetExecutorTaskResponse{et, etSpecData})
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return res, nil
}
