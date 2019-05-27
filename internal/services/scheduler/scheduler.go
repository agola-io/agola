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

package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	slog "github.com/sorintlab/agola/internal/log"
	"github.com/sorintlab/agola/internal/services/common"
	"github.com/sorintlab/agola/internal/services/config"
	rsapi "github.com/sorintlab/agola/internal/services/runservice/api"
	"github.com/sorintlab/agola/internal/util"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	errors "golang.org/x/xerrors"
)

var level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
var logger = slog.New(level)
var log = logger.Sugar()

func (s *Scheduler) scheduleLoop(ctx context.Context) {
	for {
		if err := s.schedule(ctx); err != nil {
			log.Errorf("err: %+v", err)
		}
		time.Sleep(1 * time.Second)
	}
}

func (s *Scheduler) schedule(ctx context.Context) error {
	// create a list of project and users with queued runs
	groups := map[string]struct{}{}

	var lastRunID string
	for {
		queuedRunsResponse, _, err := s.runserviceClient.GetQueuedRuns(ctx, lastRunID, 0, nil)
		if err != nil {
			return errors.Errorf("failed to get queued runs: %w", err)
		}
		//log.Infof("queuedRuns: %s", util.Dump(queuedRunsResponse.Runs))

		for _, run := range queuedRunsResponse.Runs {
			groups[run.Group] = struct{}{}
		}

		if len(queuedRunsResponse.Runs) == 0 {
			break
		}

		lastRunID = queuedRunsResponse.Runs[len(queuedRunsResponse.Runs)-1].ID
	}

	for groupID := range groups {
		if err := s.scheduleRun(ctx, groupID); err != nil {
			log.Errorf("scheduler err: %v", err)
		}
	}

	return nil
}

func (s *Scheduler) scheduleRun(ctx context.Context, groupID string) error {
	// get first queued run
	queuedRunsResponse, _, err := s.runserviceClient.GetGroupFirstQueuedRuns(ctx, groupID, nil)
	//log.Infof("first queuedRuns: %s", util.Dump(queuedRunsResponse.Runs))
	if err != nil {
		return errors.Errorf("failed to get the first project queued run: %w", err)
	}
	if len(queuedRunsResponse.Runs) == 0 {
		return nil
	}

	//log.Infof("queued runs: %s", queuedRunsResponse.Runs)
	run := queuedRunsResponse.Runs[0]

	changegroup := util.EncodeSha256Hex(fmt.Sprintf("changegroup-%s", groupID))
	runningRunsResponse, _, err := s.runserviceClient.GetGroupRunningRuns(ctx, groupID, 1, []string{changegroup})
	if err != nil {
		return errors.Errorf("failed to get running runs: %w", err)
	}
	//log.Infof("running Runs: %s", util.Dump(runningRunsResponse.Runs))
	if len(runningRunsResponse.Runs) == 0 {
		log.Infof("starting run %s", run.ID)
		log.Infof("changegroups: %s", runningRunsResponse.ChangeGroupsUpdateToken)
		if _, err := s.runserviceClient.StartRun(ctx, run.ID, runningRunsResponse.ChangeGroupsUpdateToken); err != nil {
			log.Errorf("failed to start run %s: %v", run.ID, err)
		}
	}

	return nil
}

func (s *Scheduler) approveLoop(ctx context.Context) {
	for {
		if err := s.approve(ctx); err != nil {
			log.Errorf("err: %+v", err)
		}
		time.Sleep(1 * time.Second)
	}
}

func (s *Scheduler) approve(ctx context.Context) error {
	var lastRunID string
	for {
		runningRunsResponse, _, err := s.runserviceClient.GetRunningRuns(ctx, lastRunID, 0, nil)
		if err != nil {
			return errors.Errorf("failed to get running runs: %w", err)
		}

		if len(runningRunsResponse.Runs) == 0 {
			break
		}

		for _, run := range runningRunsResponse.Runs {
			if err := s.approveRunTasks(ctx, run.ID); err != nil {
				// just log error and continue with the other runs
				log.Errorf("failed to approve run tasks for run %q: %+v", run.ID, err)
			}
		}

		lastRunID = runningRunsResponse.Runs[len(runningRunsResponse.Runs)-1].ID
	}

	return nil
}

func (s *Scheduler) approveRunTasks(ctx context.Context, runID string) error {
	// refetch run with a dedicated changegroup
	changegroup := util.EncodeSha256Hex(fmt.Sprintf("approval-%s", runID))
	runResp, _, err := s.runserviceClient.GetRun(ctx, runID, []string{changegroup})
	if err != nil {
		return errors.Errorf("failed to get run %q: %w", runID, err)
	}
	run := runResp.Run

	tasksWaitingApproval := run.TasksWaitingApproval()
	for _, rtID := range tasksWaitingApproval {
		rt, ok := run.Tasks[rtID]
		if !ok {
			return util.NewErrBadRequest(errors.Errorf("run %q doesn't have task %q", run.ID, rtID))
		}
		annotations := rt.Annotations
		if annotations == nil {
			continue
		}
		approversAnnotation, ok := annotations[common.ApproversAnnotation]
		if !ok {
			continue
		}
		var approvers []string
		if err := json.Unmarshal([]byte(approversAnnotation), &approvers); err != nil {
			return errors.Errorf("failed to unmarshal run task approvers annotation: %w", err)
		}
		// TODO(sgotti) change when we introduce a config the set the minimum number of required approvers
		if len(approvers) > 0 {
			rsreq := &rsapi.RunTaskActionsRequest{
				ActionType:              rsapi.RunTaskActionTypeApprove,
				ChangeGroupsUpdateToken: runResp.ChangeGroupsUpdateToken,
			}
			if _, err := s.runserviceClient.RunTaskActions(ctx, run.ID, rt.ID, rsreq); err != nil {
				return errors.Errorf("failed to approve run: %w", err)
			}
		}
	}

	return nil
}

type Scheduler struct {
	c                *config.Scheduler
	runserviceClient *rsapi.Client
}

func NewScheduler(c *config.Scheduler) (*Scheduler, error) {
	if c.Debug {
		level.SetLevel(zapcore.DebugLevel)
	}

	return &Scheduler{
		runserviceClient: rsapi.NewClient(c.RunserviceURL),
	}, nil
}

func (s *Scheduler) Run(ctx context.Context) error {
	go s.scheduleLoop(ctx)
	go s.approveLoop(ctx)

	select {
	case <-ctx.Done():
		log.Infof("scheduler exiting")
		return nil
	}
}
