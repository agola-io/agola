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
	"context"
	"encoding/json"
	"fmt"
	"time"

	slog "agola.io/agola/internal/log"
	"agola.io/agola/internal/services/common"
	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/util"
	rsapitypes "agola.io/agola/services/runservice/api/types"
	rsclient "agola.io/agola/services/runservice/client"

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

		sleepCh := time.NewTimer(1 * time.Second).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
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
	if err != nil {
		return errors.Errorf("failed to get the first project queued run: %w", err)
	}
	if len(queuedRunsResponse.Runs) == 0 {
		return nil
	}

	run := queuedRunsResponse.Runs[0]

	changegroup := util.EncodeSha256Hex(fmt.Sprintf("changegroup-%s", groupID))
	runningRunsResponse, _, err := s.runserviceClient.GetGroupRunningRuns(ctx, groupID, 1, []string{changegroup})
	if err != nil {
		return errors.Errorf("failed to get running runs: %w", err)
	}
	if len(runningRunsResponse.Runs) == 0 {
		log.Infof("starting run %s", run.ID)
		log.Debugf("changegroups: %s", runningRunsResponse.ChangeGroupsUpdateToken)
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

		sleepCh := time.NewTimer(1 * time.Second).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
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
			rsreq := &rsapitypes.RunTaskActionsRequest{
				ActionType:              rsapitypes.RunTaskActionTypeApprove,
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
	runserviceClient *rsclient.Client
}

func NewScheduler(ctx context.Context, l *zap.Logger, c *config.Scheduler) (*Scheduler, error) {
	if l != nil {
		logger = l
	}
	if c.Debug {
		level.SetLevel(zapcore.DebugLevel)
	}
	log = logger.Sugar()

	return &Scheduler{
		c:                c,
		runserviceClient: rsclient.NewClient(c.RunserviceURL),
	}, nil
}

func (s *Scheduler) Run(ctx context.Context) error {
	go s.scheduleLoop(ctx)
	go s.approveLoop(ctx)

	<-ctx.Done()
	log.Infof("scheduler exiting")

	return nil
}
