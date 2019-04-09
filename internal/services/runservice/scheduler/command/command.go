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

package command

import (
	"context"
	"path"
	"time"

	uuid "github.com/satori/go.uuid"
	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/etcd"
	"github.com/sorintlab/agola/internal/objectstorage"
	"github.com/sorintlab/agola/internal/runconfig"
	"github.com/sorintlab/agola/internal/sequence"
	"github.com/sorintlab/agola/internal/services/runservice/scheduler/common"
	"github.com/sorintlab/agola/internal/services/runservice/scheduler/readdb"
	"github.com/sorintlab/agola/internal/services/runservice/scheduler/store"
	"github.com/sorintlab/agola/internal/services/runservice/types"
	"github.com/sorintlab/agola/internal/util"
	"github.com/sorintlab/agola/internal/wal"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type CommandHandler struct {
	log    *zap.SugaredLogger
	e      *etcd.Store
	readDB *readdb.ReadDB
	lts    *objectstorage.ObjStorage
	wal    *wal.WalManager
}

func NewCommandHandler(logger *zap.Logger, e *etcd.Store, readDB *readdb.ReadDB, lts *objectstorage.ObjStorage, wal *wal.WalManager) *CommandHandler {
	return &CommandHandler{
		log:    logger.Sugar(),
		e:      e,
		readDB: readDB,
		lts:    lts,
		wal:    wal,
	}
}

type RunChangePhaseRequest struct {
	RunID                   string
	Phase                   types.RunPhase
	ChangeGroupsUpdateToken string
}

func (s *CommandHandler) ChangeRunPhase(ctx context.Context, req *RunChangePhaseRequest) error {
	cgt, err := types.UnmarshalChangeGroupsUpdateToken(req.ChangeGroupsUpdateToken)
	if err != nil {
		return err
	}

	r, _, err := store.GetRun(ctx, s.e, req.RunID)
	if err != nil {
		return err
	}

	switch req.Phase {
	case types.RunPhaseRunning:
		if r.Phase != types.RunPhaseQueued {
			return errors.Errorf("run %s is not queued but in %q phase", r.ID, r.Phase)
		}
		r.ChangePhase(types.RunPhaseRunning)
	case types.RunPhaseFinished:
		if r.Phase != types.RunPhaseRunning {
			return errors.Errorf("run %s is not running but in %q phase", r.ID, r.Phase)
		}
		r.Stop = true
	}

	_, err = store.AtomicPutRun(ctx, s.e, r, "", cgt)
	return err
}

type RunStopRequest struct {
	RunID                   string
	ChangeGroupsUpdateToken string
}

func (s *CommandHandler) StopRun(ctx context.Context, req *RunStopRequest) error {
	cgt, err := types.UnmarshalChangeGroupsUpdateToken(req.ChangeGroupsUpdateToken)
	if err != nil {
		return err
	}

	r, _, err := store.GetRun(ctx, s.e, req.RunID)
	if err != nil {
		return err
	}

	if r.Phase != types.RunPhaseRunning {
		return errors.Errorf("run %s is not running but in %q phase", r.ID, r.Phase)
	}
	if !r.Result.IsSet() {
		// stop only if the result is not setted yet
		r.Stop = true
	}

	_, err = store.AtomicPutRun(ctx, s.e, r, "", cgt)
	return err
}

type RunCreateRequest struct {
	RunConfigTasks    map[string]*types.RunConfigTask
	Name              string
	Group             string
	SetupErrors       []string
	StaticEnvironment map[string]string

	// existing run fields
	RunID      string
	FromStart  bool
	ResetTasks []string

	// common fields
	Environment map[string]string
	Annotations map[string]string

	ChangeGroupsUpdateToken string
}

func (s *CommandHandler) CreateRun(ctx context.Context, req *RunCreateRequest) (*types.RunBundle, error) {
	runcgt, err := types.UnmarshalChangeGroupsUpdateToken(req.ChangeGroupsUpdateToken)
	if err != nil {
		return nil, err
	}

	var rb *types.RunBundle
	if req.RunID == "" {
		rb, err = s.newRun(ctx, req)
	} else {
		rb, err = s.recreateRun(ctx, req)
	}
	if err != nil {
		return nil, err
	}

	return rb, s.saveRun(ctx, rb, runcgt)
}

func (s *CommandHandler) newRun(ctx context.Context, req *RunCreateRequest) (*types.RunBundle, error) {
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
	seq, err := sequence.IncSequence(ctx, s.e, common.EtcdRunSequenceKey)
	if err != nil {
		return nil, err
	}
	id := seq.String()

	if err := runconfig.CheckRunConfigTasks(rcts); err != nil {
		s.log.Errorf("check run config tasks failed: %+v", err)
		setupErrors = append(setupErrors, err.Error())
	}

	// generate tasks levels
	if len(setupErrors) == 0 {
		if err := runconfig.GenTasksLevels(rcts); err != nil {
			s.log.Errorf("gen tasks leveles failed: %+v", err)
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
	}

	run := s.genRun(ctx, rc)
	s.log.Debugf("created run: %s", util.Dump(run))

	return &types.RunBundle{
		Run: run,
		Rc:  rc,
	}, nil
}

func (s *CommandHandler) recreateRun(ctx context.Context, req *RunCreateRequest) (*types.RunBundle, error) {
	// generate a new run sequence that will be the same for the run and runconfig
	seq, err := sequence.IncSequence(ctx, s.e, common.EtcdRunSequenceKey)
	if err != nil {
		return nil, err
	}
	id := seq.String()

	// fetch the existing runconfig and run
	s.log.Infof("creating run from existing run")
	rc, err := store.LTSGetRunConfig(s.wal, req.RunID)
	if err != nil {
		return nil, util.NewErrBadRequest(errors.Wrapf(err, "runconfig %q doens't exist", req.RunID))
	}
	// update the run config ID
	rc.ID = id
	// update the run config Environment
	rc.Environment = req.Environment

	run, err := store.GetRunEtcdOrLTS(ctx, s.e, s.wal, req.RunID)
	if err != nil {
		return nil, err
	}
	if run == nil {
		return nil, util.NewErrBadRequest(errors.Wrapf(err, "run %q doens't exist", req.RunID))
	}

	if req.FromStart {
		if canRestart, reason := run.CanRestartFromScratch(); !canRestart {
			return nil, util.NewErrBadRequest(errors.Errorf("run cannot be restarted: %s", reason))
		}
	} else {
		if canRestart, reason := run.CanRestartFromFailedTasks(); !canRestart {
			return nil, util.NewErrBadRequest(errors.Errorf("run cannot be restarted: %s", reason))
		}
	}

	// update the run ID
	run.ID = id
	// reset run revision
	run.Revision = 0
	// reset phase/result/archived/stop
	run.Phase = types.RunPhaseQueued
	run.Result = types.RunResultUnknown
	run.Archived = false
	run.Stop = false

	// TODO(sgotti) handle reset tasks
	// currently we only restart a run resetting al failed tasks
	tasksToAdd := []*types.RunTask{}
	tasksToDelete := []string{}

	for _, rt := range run.RunTasks {
		if req.FromStart || rt.Status != types.RunTaskStatusSuccess {
			rct := rc.Tasks[rt.ID]
			// change rct id
			rct.ID = uuid.NewV4().String()

			// update runconfig
			delete(rc.Tasks, rt.ID)
			rc.Tasks[rct.ID] = rct
			// update other tasks depends to new task id
			for _, t := range rc.Tasks {
				for _, d := range t.Depends {
					if d.TaskID == rt.ID {
						d.TaskID = rct.ID
					}
				}
			}

			nrt := s.genRunTask(ctx, rct)
			tasksToAdd = append(tasksToAdd, nrt)
			tasksToDelete = append(tasksToDelete, rt.ID)
		}
	}
	for _, rt := range tasksToAdd {
		run.RunTasks[rt.ID] = rt
	}
	for _, rtID := range tasksToDelete {
		delete(run.RunTasks, rtID)
	}

	s.log.Debugf("created run from existing run: %s", util.Dump(run))

	return &types.RunBundle{
		Run: run,
		Rc:  rc,
	}, nil
}

func (s *CommandHandler) saveRun(ctx context.Context, rb *types.RunBundle, runcgt *types.ChangeGroupsUpdateToken) error {
	run := rb.Run
	rc := rb.Rc

	c, cgt, err := s.getRunCounter(run.Group)
	s.log.Infof("c: %d, cgt: %s", c, util.Dump(cgt))
	if err != nil {
		return err
	}
	c++
	run.Counter = c

	actions := []*wal.Action{}

	// persist group counter
	rca, err := store.LTSUpdateRunCounterAction(ctx, c, run.Group)
	if err != nil {
		return err
	}
	actions = append(actions, rca)

	// persist run config
	rca, err = store.LTSSaveRunConfigAction(rc)
	if err != nil {
		return err
	}
	actions = append(actions, rca)

	if _, err = s.wal.WriteWal(ctx, actions, cgt); err != nil {
		return err
	}

	if _, err := store.AtomicPutRun(ctx, s.e, run, common.RunEventTypeQueued, runcgt); err != nil {
		return err
	}
	return nil
}

func (s *CommandHandler) genRunTask(ctx context.Context, rct *types.RunConfigTask) *types.RunTask {
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

func (s *CommandHandler) genRun(ctx context.Context, rc *types.RunConfig) *types.Run {
	r := &types.Run{
		ID:          rc.ID,
		Name:        rc.Name,
		Group:       rc.Group,
		Annotations: rc.Annotations,
		Phase:       types.RunPhaseQueued,
		Result:      types.RunResultUnknown,
		RunTasks:    make(map[string]*types.RunTask),
		EnqueueTime: util.TimePtr(time.Now()),
	}

	if len(rc.SetupErrors) > 0 {
		r.Phase = types.RunPhaseSetupError
		return r
	}

	for _, rct := range rc.Tasks {
		rt := s.genRunTask(ctx, rct)
		r.RunTasks[rt.ID] = rt
	}

	return r
}

type RunTaskApproveRequest struct {
	RunID                   string
	TaskID                  string
	ApprovalAnnotations     map[string]string
	ChangeGroupsUpdateToken string
}

func (s *CommandHandler) ApproveRunTask(ctx context.Context, req *RunTaskApproveRequest) error {
	cgt, err := types.UnmarshalChangeGroupsUpdateToken(req.ChangeGroupsUpdateToken)
	if err != nil {
		return err
	}

	r, _, err := store.GetRun(ctx, s.e, req.RunID)
	if err != nil {
		return err
	}

	task, ok := r.RunTasks[req.TaskID]
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
	task.ApprovalAnnotations = req.ApprovalAnnotations

	_, err = store.AtomicPutRun(ctx, s.e, r, "", cgt)
	return err
}

func (s *CommandHandler) DeleteExecutor(ctx context.Context, executorID string) error {
	// mark all executor tasks as failed
	ets, err := store.GetExecutorTasks(ctx, s.e, executorID)
	if err != nil {
		return err
	}

	for _, et := range ets {
		et.Status.Phase = types.ExecutorTaskPhaseFailed
		et.FailError = "executor deleted"
		if _, err := store.AtomicPutExecutorTask(ctx, s.e, et); err != nil {
			return err
		}
	}

	// delete the executor
	if err := store.DeleteExecutor(ctx, s.e, executorID); err != nil {
		return err
	}

	return nil
}

func (s *CommandHandler) getRunCounter(group string) (uint64, *wal.ChangeGroupsUpdateToken, error) {
	// use the first group dir after the root
	pl := util.PathList(group)
	if len(pl) < 2 {
		return 0, nil, errors.Errorf("cannot determine group counter name, wrong group path %q", group)
	}

	var c uint64
	var cgt *wal.ChangeGroupsUpdateToken
	err := s.readDB.Do(func(tx *db.Tx) error {
		var err error
		c, err = s.readDB.GetRunCounterLTS(tx, pl[1])
		if err != nil {
			return err
		}
		cgt, err = s.readDB.GetChangeGroupsUpdateTokensLTS(tx, []string{"counter-" + pl[1]})
		return err
	})
	if err != nil {
		return 0, nil, err
	}

	return c, cgt, nil
}
