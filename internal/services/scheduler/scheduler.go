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
	"fmt"
	"time"

	slog "github.com/sorintlab/agola/internal/log"
	"github.com/sorintlab/agola/internal/services/config"
	rsapi "github.com/sorintlab/agola/internal/services/runservice/scheduler/api"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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
		queuedRunsResponse, _, err := s.runserviceClient.GetQueuedRuns(ctx, lastRunID, 0)
		if err != nil {
			return errors.Wrapf(err, "failed to get queued runs")
		}
		//log.Infof("queuedRuns: %s", util.Dump(queuedRunsResponse.Runs))

		for _, run := range queuedRunsResponse.Runs {
			groups[run.Group] = struct{}{}
		}

		if len(queuedRunsResponse.Runs) == 0 {
			break
		}

		if len(queuedRunsResponse.Runs) > 0 {
			lastRunID = queuedRunsResponse.Runs[len(queuedRunsResponse.Runs)-1].ID
		}
	}

	for groupID, _ := range groups {
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
		return errors.Wrapf(err, "failed to get the first project queued run")
	}
	if len(queuedRunsResponse.Runs) == 0 {
		return nil
	}

	//log.Infof("queued runs: %s", queuedRunsResponse.Runs)
	run := queuedRunsResponse.Runs[0]

	runningRunsResponse, _, err := s.runserviceClient.GetGroupRunningRuns(ctx, groupID, 1, []string{fmt.Sprintf("changegroup-%s", groupID)})
	if err != nil {
		return errors.Wrapf(err, "failed to get running runs")
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

type Scheduler struct {
	c                *config.Scheduler
	runserviceClient *rsapi.Client
}

func NewScheduler(c *config.Scheduler) (*Scheduler, error) {
	if c.Debug {
		level.SetLevel(zapcore.DebugLevel)
	}

	return &Scheduler{
		runserviceClient: rsapi.NewClient(c.RunServiceURL),
	}, nil
}

func (s *Scheduler) Run(ctx context.Context) error {
	go s.scheduleLoop(ctx)

	select {
	case <-ctx.Done():
		log.Infof("scheduler exiting")
		return nil
	}
}
