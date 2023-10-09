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

package notification

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/common"
	"agola.io/agola/internal/services/gateway/action"
	"agola.io/agola/services/notification/types"
	rstypes "agola.io/agola/services/runservice/types"
)

type commitStatus struct {
	ProjectID   string
	CommitSHA   string
	State       types.CommitState
	RunCounter  uint64
	Description string
	Context     string
}

func (n *NotificationService) generateCommitStatus(ctx context.Context, ev *rstypes.RunEvent) (*commitStatus, error) {
	var state types.CommitState
	if ev.Phase == rstypes.RunPhaseSetupError {
		state = types.CommitStateError
	}
	if ev.Phase == rstypes.RunPhaseCancelled {
		state = types.CommitStateError
	}
	if ev.Phase == rstypes.RunPhaseRunning && ev.Result == rstypes.RunResultUnknown {
		state = types.CommitStatePending
	}
	if ev.Phase == rstypes.RunPhaseFinished && ev.Result != rstypes.RunResultUnknown {
		switch ev.Result {
		case rstypes.RunResultSuccess:
			state = types.CommitStateSuccess
		case rstypes.RunResultStopped:
			fallthrough
		case rstypes.RunResultFailed:
			state = types.CommitStateFailed
		}
	}

	if state == "" {
		return nil, nil
	}

	run, _, err := n.runserviceClient.GetRun(ctx, ev.RunID, nil)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	groupType, groupID, err := common.GroupTypeIDFromRunGroup(run.RunConfig.Group)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// ignore user direct runs
	if groupType == common.GroupTypeUser {
		return nil, nil
	}

	project, _, err := n.configstoreClient.GetProject(ctx, groupID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get project %s", groupID)
	}

	context := fmt.Sprintf("%s/%s/%s", n.gc.ID, project.Name, run.RunConfig.Name)

	return &commitStatus{
		ProjectID:   project.ID,
		State:       state,
		CommitSHA:   run.Run.Annotations[action.AnnotationCommitSHA],
		RunCounter:  run.Run.Counter,
		Description: statusDescription(state),
		Context:     context,
	}, nil
}

func webRunURL(webExposedURL, projectID string, runNumber uint64) (string, error) {
	u, err := url.Parse(webExposedURL + "/run")
	if err != nil {
		return "", errors.WithStack(err)
	}
	q := url.Values{}
	q.Set("projectref", projectID)
	q.Set("runnumber", strconv.FormatUint(runNumber, 10))

	u.RawQuery = q.Encode()

	return u.String(), nil
}

func statusDescription(state types.CommitState) string {
	switch state {
	case types.CommitStatePending:
		return "The run is pending"
	case types.CommitStateSuccess:
		return "The run finished successfully"
	case types.CommitStateError:
		return "The run encountered an error"
	case types.CommitStateFailed:
		return "The run failed"
	default:
		return ""
	}
}
