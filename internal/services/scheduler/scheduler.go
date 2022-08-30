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

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/services/common"
	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/util"
	rsapitypes "agola.io/agola/services/runservice/api/types"
	rsclient "agola.io/agola/services/runservice/client"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func (s *Scheduler) scheduleLoop(ctx context.Context) {
	for {
		if err := s.schedule(ctx); err != nil {
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

func (s *Scheduler) schedule(ctx context.Context) error {
	// create a list of project and users with queued runs
	groups := map[string]struct{}{}

	var lastRunSequence uint64
	for {
		queuedRunsResponse, _, err := s.runserviceClient.GetQueuedRuns(ctx, lastRunSequence, 0, nil)
		if err != nil {
			return errors.Wrapf(err, "failed to get queued runs")
		}

		for _, run := range queuedRunsResponse.Runs {
			groups[run.Group] = struct{}{}
		}

		if len(queuedRunsResponse.Runs) == 0 {
			break
		}

		lastRunSequence = queuedRunsResponse.Runs[len(queuedRunsResponse.Runs)-1].Sequence
	}

	for groupID := range groups {
		if err := s.scheduleRun(ctx, groupID); err != nil {
			s.log.Err(err).Msgf("scheduler err")
		}
	}

	return nil
}

func (s *Scheduler) scheduleRun(ctx context.Context, groupID string) error {
	// get first queued run
	queuedRunsResponse, _, err := s.runserviceClient.GetGroupFirstQueuedRuns(ctx, groupID, nil)
	if err != nil {
		return errors.Wrapf(err, "failed to get the first project queued run")
	}
	if len(queuedRunsResponse.Runs) == 0 {
		return nil
	}

	run := queuedRunsResponse.Runs[0]

	changegroup := util.EncodeSha256Hex(fmt.Sprintf("changegroup-%s", groupID))
	runningRunsResponse, _, err := s.runserviceClient.GetGroupRunningRuns(ctx, groupID, 1, []string{changegroup})
	if err != nil {
		return errors.Wrapf(err, "failed to get running runs")
	}
	if len(runningRunsResponse.Runs) == 0 {
		log.Info().Msgf("starting run %s", run.ID)
		if _, err := s.runserviceClient.StartRun(ctx, run.ID, runningRunsResponse.ChangeGroupsUpdateToken); err != nil {
			s.log.Err(err).Msgf("failed to start run %s", run.ID)
		}
	}

	return nil
}

func (s *Scheduler) approveLoop(ctx context.Context) {
	for {
		if err := s.approve(ctx); err != nil {
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

func (s *Scheduler) approve(ctx context.Context) error {
	var lastRunSequence uint64
	for {
		runningRunsResponse, _, err := s.runserviceClient.GetRunningRuns(ctx, lastRunSequence, 0, nil)
		if err != nil {
			return errors.Wrapf(err, "failed to get running runs")
		}

		if len(runningRunsResponse.Runs) == 0 {
			break
		}

		for _, run := range runningRunsResponse.Runs {
			if err := s.approveRunTasks(ctx, run.ID); err != nil {
				// just log error and continue with the other runs
				log.Err(err).Msgf("failed to approve run tasks for run %q", run.ID)
			}
		}

		lastRunSequence = runningRunsResponse.Runs[len(runningRunsResponse.Runs)-1].Sequence
	}

	return nil
}

func (s *Scheduler) approveRunTasks(ctx context.Context, runID string) error {
	// refetch run with a dedicated changegroup
	changegroup := util.EncodeSha256Hex(fmt.Sprintf("approval-%s", runID))
	runResp, _, err := s.runserviceClient.GetRun(ctx, runID, []string{changegroup})
	if err != nil {
		return errors.Wrapf(err, "failed to get run %q", runID)
	}
	run := runResp.Run

	tasksWaitingApproval := run.TasksWaitingApproval()
	for _, rtID := range tasksWaitingApproval {
		rt, ok := run.Tasks[rtID]
		if !ok {
			return errors.Errorf("run %q doesn't have task %q", run.ID, rtID)
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
			return errors.Wrapf(err, "failed to unmarshal run task approvers annotation")
		}
		// TODO(sgotti) change when we introduce a config the set the minimum number of required approvers
		if len(approvers) > 0 {
			rsreq := &rsapitypes.RunTaskActionsRequest{
				ActionType:              rsapitypes.RunTaskActionTypeApprove,
				ChangeGroupsUpdateToken: runResp.ChangeGroupsUpdateToken,
			}
			if _, err := s.runserviceClient.RunTaskActions(ctx, run.ID, rt.ID, rsreq); err != nil {
				return errors.Wrapf(err, "failed to approve run")
			}
		}
	}

	return nil
}

type Scheduler struct {
	log              zerolog.Logger
	c                *config.Scheduler
	runserviceClient *rsclient.Client
}

func NewScheduler(ctx context.Context, log zerolog.Logger, c *config.Scheduler) (*Scheduler, error) {
	if c.Debug {
		log = log.Level(zerolog.DebugLevel)
	}

	return &Scheduler{
		log:              log,
		c:                c,
		runserviceClient: rsclient.NewClient(c.RunserviceURL),
	}, nil
}

func (s *Scheduler) Run(ctx context.Context) error {
	go s.scheduleLoop(ctx)
	go s.approveLoop(ctx)

	<-ctx.Done()
	log.Info().Msgf("scheduler exiting")

	return nil
}
