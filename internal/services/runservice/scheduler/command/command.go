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
	"context"
	"time"

	"github.com/sorintlab/agola/internal/etcd"
	"github.com/sorintlab/agola/internal/objectstorage"
	"github.com/sorintlab/agola/internal/runconfig"
	"github.com/sorintlab/agola/internal/sequence"
	"github.com/sorintlab/agola/internal/services/runservice/scheduler/common"
	"github.com/sorintlab/agola/internal/services/runservice/scheduler/store"
	"github.com/sorintlab/agola/internal/services/runservice/types"
	"github.com/sorintlab/agola/internal/util"
	"github.com/sorintlab/agola/internal/wal"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type CommandHandler struct {
	log *zap.SugaredLogger
	e   *etcd.Store
	lts *objectstorage.ObjStorage
	wal *wal.WalManager
}

func NewCommandHandler(logger *zap.Logger, e *etcd.Store, lts *objectstorage.ObjStorage, wal *wal.WalManager) *CommandHandler {
	return &CommandHandler{
		log: logger.Sugar(),
		e:   e,
		lts: lts,
		wal: wal,
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
	}

	_, err = store.AtomicPutRun(ctx, s.e, r, "", cgt)
	return err
}

type RunCreateRequest struct {
	RunConfig               *types.RunConfig
	Group                   string
	Environment             map[string]string
	Annotations             map[string]string
	ChangeGroupsUpdateToken string
}

func (s *CommandHandler) CreateRun(ctx context.Context, req *RunCreateRequest) error {
	runcgt, err := types.UnmarshalChangeGroupsUpdateToken(req.ChangeGroupsUpdateToken)
	if err != nil {
		return err
	}

	rc := req.RunConfig

	// generate a new run sequence that will be the same for the run, runconfig and rundata
	seq, err := sequence.IncSequence(ctx, s.e, common.EtcdRunSequenceKey)
	if err != nil {
		return err
	}
	id := seq.String()

	// TODO(sgotti) validate run config
	if err := runconfig.CheckRunConfig(rc); err != nil {
		return err
	}

	// set the run config ID
	rc.ID = id

	// generate tasks levels
	if err := runconfig.GenTasksLevels(rc); err != nil {
		return err
	}

	rd := &types.RunData{
		ID:          id,
		Group:       req.Group,
		Environment: req.Environment,
		Annotations: req.Annotations,
	}

	run, err := s.genRun(ctx, rc, rd)
	if err != nil {
		return err
	}
	s.log.Debugf("created run: %s", util.Dump(run))

	c, cgt, err := store.LTSGetRunCounter(s.wal, run.Group)
	s.log.Infof("c: %d, cgt: %s", c, util.Dump(cgt))
	if err != nil && err != objectstorage.ErrNotExist {
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

	// persist run data
	rda, err := store.LTSSaveRunDataAction(rd)
	if err != nil {
		return err
	}
	actions = append(actions, rda)

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
		Steps:             make([]*types.RunTaskStep, len(rct.Steps)),
		WorkspaceArchives: []int{},
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

func (s *CommandHandler) genRun(ctx context.Context, rc *types.RunConfig, rd *types.RunData) (*types.Run, error) {
	r := &types.Run{
		ID:          rc.ID,
		Name:        rc.Name,
		Group:       rd.Group,
		Annotations: rd.Annotations,
		Phase:       types.RunPhaseQueued,
		Result:      types.RunResultUnknown,
		RunTasks:    make(map[string]*types.RunTask),
		EnqueueTime: util.TimePtr(time.Now()),
	}

	for _, rct := range rc.Tasks {
		rt := s.genRunTask(ctx, rct)
		r.RunTasks[rt.ID] = rt
	}

	return r, nil
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
		return errors.Errorf("run %q doesn't have task %q", r.ID, req.TaskID)
	}

	if !task.WaitingApproval {
		return errors.Errorf("run %q, task %q is not in waiting approval state", r.ID, req.TaskID)
	}

	if !task.Approved {
		return errors.Errorf("run %q, task %q is already approved", r.ID, req.TaskID)
	}

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
