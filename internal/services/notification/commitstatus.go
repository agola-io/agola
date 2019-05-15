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

package notification

import (
	"context"
	"fmt"
	"net/url"

	gitsource "github.com/sorintlab/agola/internal/gitsources"
	"github.com/sorintlab/agola/internal/services/common"
	"github.com/sorintlab/agola/internal/services/gateway"
	rstypes "github.com/sorintlab/agola/internal/services/runservice/types"

	"github.com/pkg/errors"
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

	// ignore user local runs
	if groupType == common.GroupTypeUser {
		return nil
	}

	project, _, err := n.configstoreClient.GetProject(ctx, groupID)
	if err != nil {
		return errors.Wrapf(err, "failed to get project %s", groupID)
	}

	user, _, err := n.configstoreClient.GetUserByLinkedAccount(ctx, project.LinkedAccountID)
	if err != nil {
		return errors.Wrapf(err, "failed to get user by linked account %q", project.LinkedAccountID)
	}
	la := user.LinkedAccounts[project.LinkedAccountID]
	if la == nil {
		return errors.Errorf("linked account %q in user %q doesn't exist", project.LinkedAccountID, user.Name)
	}
	rs, _, err := n.configstoreClient.GetRemoteSource(ctx, la.RemoteSourceID)
	if err != nil {
		return errors.Wrapf(err, "failed to get remote source %q", la.RemoteSourceID)
	}

	// TODO(sgotti) handle refreshing oauth2 tokens
	gitSource, err := common.GetGitSource(rs, la)
	if err != nil {
		return errors.Wrapf(err, "failed to create gitea client")
	}

	targetURL, err := webRunURL(n.c.WebExposedURL, project.ID, run.Run.ID)
	if err != nil {
		return errors.Wrapf(err, "failed to generate commit status target url")
	}
	description := statusDescription(commitStatus)
	context := fmt.Sprintf("%s/%s/%s", n.gc.ID, project.Name, run.RunConfig.Name)

	if err := gitSource.CreateCommitStatus(project.RepositoryPath, run.Run.Annotations[gateway.AnnotationCommitSHA], commitStatus, targetURL, description, context); err != nil {
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
	q.Set("projectid", projectID)
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
