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

	gitsource "agola.io/agola/internal/gitsources"
	"agola.io/agola/internal/services/common"
	"agola.io/agola/internal/services/gateway/action"
	rstypes "agola.io/agola/services/runservice/types"

	errors "golang.org/x/xerrors"
)

func (n *NotificationService) updateCommitStatus(ctx context.Context, ev *rstypes.RunEvent) error {
	var commitStatus gitsource.CommitStatus
	if ev.Phase == rstypes.RunPhaseSetupError {
		commitStatus = gitsource.CommitStatusError
	}
	if ev.Phase == rstypes.RunPhaseCancelled {
		commitStatus = gitsource.CommitStatusError
	}
	if ev.Phase == rstypes.RunPhaseRunning && ev.Result == rstypes.RunResultUnknown {
		commitStatus = gitsource.CommitStatusPending
	}
	if ev.Phase == rstypes.RunPhaseFinished && ev.Result != rstypes.RunResultUnknown {
		switch ev.Result {
		case rstypes.RunResultSuccess:
			commitStatus = gitsource.CommitStatusSuccess
		case rstypes.RunResultStopped:
			fallthrough
		case rstypes.RunResultFailed:
			commitStatus = gitsource.CommitStatusFailed
		}
	}

	if commitStatus == "" {
		return nil
	}

	run, _, err := n.runserviceClient.GetRun(ctx, ev.RunID, nil)
	if err != nil {
		return err
	}
	groupType, groupID, err := common.GroupTypeIDFromRunGroup(run.RunConfig.Group)
	if err != nil {
		return err
	}

	// ignore user direct runs
	if groupType == common.GroupTypeUser {
		return nil
	}

	project, _, err := n.configstoreClient.GetProject(ctx, groupID)
	if err != nil {
		return errors.Errorf("failed to get project %s: %w", groupID, err)
	}

	user, _, err := n.configstoreClient.GetUserByLinkedAccount(ctx, project.LinkedAccountID)
	if err != nil {
		return errors.Errorf("failed to get user by linked account %q: %w", project.LinkedAccountID, err)
	}
	la := user.LinkedAccounts[project.LinkedAccountID]
	if la == nil {
		return errors.Errorf("linked account %q in user %q doesn't exist", project.LinkedAccountID, user.Name)
	}
	rs, _, err := n.configstoreClient.GetRemoteSource(ctx, la.RemoteSourceID)
	if err != nil {
		return errors.Errorf("failed to get remote source %q: %w", la.RemoteSourceID, err)
	}

	// TODO(sgotti) handle refreshing oauth2 tokens
	gitSource, err := common.GetGitSource(rs, la)
	if err != nil {
		return errors.Errorf("failed to create gitea client: %w", err)
	}

	targetURL, err := webRunURL(n.c.WebExposedURL, project.ID, run.Run.ID)
	if err != nil {
		return errors.Errorf("failed to generate commit status target url: %w", err)
	}
	description := statusDescription(commitStatus)
	context := fmt.Sprintf("%s/%s/%s", n.gc.ID, project.Name, run.RunConfig.Name)

	if err := gitSource.CreateCommitStatus(project.RepositoryPath, run.Run.Annotations[action.AnnotationCommitSHA], commitStatus, targetURL, description, context); err != nil {
		return err
	}

	return nil
}

func webRunURL(webExposedURL, projectID, runID string) (string, error) {
	u, err := url.Parse(webExposedURL + "/run")
	if err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("projectref", projectID)
	q.Set("runid", runID)

	u.RawQuery = q.Encode()

	return u.String(), nil
}

func statusDescription(commitStatus gitsource.CommitStatus) string {
	switch commitStatus {
	case gitsource.CommitStatusPending:
		return "The run is pending"
	case gitsource.CommitStatusSuccess:
		return "The run finished successfully"
	case gitsource.CommitStatusError:
		return "The run encountered an error"
	case gitsource.CommitStatusFailed:
		return "The run failed"
	default:
		return ""
	}
}
