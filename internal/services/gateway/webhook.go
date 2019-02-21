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

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"

	"github.com/sorintlab/agola/internal/config"
	gitsource "github.com/sorintlab/agola/internal/gitsources"
	"github.com/sorintlab/agola/internal/runconfig"
	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/common"
	rsapi "github.com/sorintlab/agola/internal/services/runservice/scheduler/api"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	agolaDefaultConfigPath = ".agola/config.yml"

	// List of runs annotations
	AnnotationEventType = "event_type"
	AnnotationRunType   = "runtype"
	AnnotationProjectID = "projectid"
	AnnotationUserID    = "userid"
	// AnnotationVirtualBranch represent a "virtual branch": i.e a normal branch, a pr (with name pr-$prid), a tag (with name tag-tagname)
	AnnotationVirtualBranch = "virtual_branch"

	AnnotationCommitSHA   = "commit_sha"
	AnnotationRef         = "ref"
	AnnotationSender      = "sender"
	AnnotationMessage     = "message"
	AnnotationCommitLink  = "commit_link"
	AnnotationCompareLink = "compare_link"

	AnnotationBranch          = "branch"
	AnnotationBranchLink      = "branch_link"
	AnnotationTag             = "tag"
	AnnotationTagLink         = "tag_link"
	AnnotationPullRequestID   = "pull_request_id"
	AnnotationPullRequestLink = "pull_request_link"
)

func genAnnotationVirtualBranch(webhookData *types.WebhookData) string {
	switch webhookData.Event {
	case types.WebhookEventPush:
		return "branch-" + webhookData.Branch
	case types.WebhookEventTag:
		return "tag-" + webhookData.Tag
	case types.WebhookEventPullRequest:
		return "pr-" + webhookData.PullRequestID
	}

	panic(fmt.Errorf("invalid webhook event type: %q", webhookData.Event))
}

func genGroup(baseGroupID string, webhookData *types.WebhookData) string {
	// we pathescape the branch name to handle branches with slashes and make the
	// branch a single path entry
	switch webhookData.Event {
	case types.WebhookEventPush:
		return path.Join(baseGroupID, "branch-"+url.PathEscape(webhookData.Branch))
	case types.WebhookEventTag:
		return path.Join(baseGroupID, "tag-"+url.PathEscape(webhookData.Tag))
	case types.WebhookEventPullRequest:
		return path.Join(baseGroupID, "pr-"+url.PathEscape(webhookData.PullRequestID))
	}

	panic(fmt.Errorf("invalid webhook event type: %q", webhookData.Event))
}

type webhooksHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
	runserviceClient  *rsapi.Client
	apiExposedURL     string
}

func (h *webhooksHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	code, userErr, err := h.handleWebhook(r)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, userErr, code)
	}
}

func (h *webhooksHandler) handleWebhook(r *http.Request) (int, string, error) {
	ctx := r.Context()

	projectID := r.URL.Query().Get("projectid")

	defer r.Body.Close()

	var gitSource gitsource.GitSource
	project, _, err := h.configstoreClient.GetProject(ctx, projectID)
	if err != nil {
		return http.StatusBadRequest, "", errors.Wrapf(err, "failed to get project %s", projectID)
	}
	h.log.Debugf("project: %s", util.Dump(project))

	user, _, err := h.configstoreClient.GetUserByLinkedAccount(ctx, project.LinkedAccountID)
	if err != nil {
		return http.StatusInternalServerError, "", errors.Wrapf(err, "failed to get user by linked account %q", project.LinkedAccountID)
	}
	la := user.LinkedAccounts[project.LinkedAccountID]
	h.log.Infof("la: %s", util.Dump(la))
	if la == nil {
		return http.StatusInternalServerError, "", errors.Errorf("linked account %q in user %q doesn't exist", project.LinkedAccountID, user.UserName)
	}
	rs, _, err := h.configstoreClient.GetRemoteSource(ctx, la.RemoteSourceID)
	if err != nil {
		return http.StatusInternalServerError, "", errors.Wrapf(err, "failed to get remote source %q", la.RemoteSourceID)
	}

	gitSource, err = common.GetGitSource(rs, la)
	if err != nil {
		return http.StatusInternalServerError, "", errors.Wrapf(err, "failed to create gitea client")
	}

	sshPrivKey := project.SSHPrivateKey
	cloneURL := project.CloneURL
	skipSSHHostKeyCheck := project.SkipSSHHostKeyCheck
	runType := types.RunTypeProject
	webhookData, err := gitSource.ParseWebhook(r)
	if err != nil {
		return http.StatusBadRequest, "", errors.Wrapf(err, "failed to parse webhook")
	}
	webhookData.ProjectID = projectID

	h.log.Infof("webhookData: %s", util.Dump(webhookData))

	var data []byte
	err = util.ExponentialBackoff(util.FetchFileBackoff, func() (bool, error) {
		var err error
		data, err = gitSource.GetFile(webhookData.Repo.Owner, webhookData.Repo.Name, webhookData.CommitSHA, agolaDefaultConfigPath)
		if err == nil {
			return true, nil
		}
		h.log.Errorf("get file err: %v", err)
		return false, nil
	})
	if err != nil {
		return http.StatusInternalServerError, "", errors.Wrapf(err, "failed to fetch config file")
	}
	h.log.Debug("data: %s", data)

	gitURL, err := util.ParseGitURL(cloneURL)
	if err != nil {
		return http.StatusInternalServerError, "", errors.Wrapf(err, "failed to parse clone url")
	}

	env := map[string]string{
		"CI":                     "true",
		"AGOLA_SSHPRIVKEY":     sshPrivKey,
		"AGOLA_REPOSITORY_URL": cloneURL,
		"AGOLA_GIT_HOST":       gitURL.Host,
		"AGOLA_GIT_REF":        webhookData.Ref,
		"AGOLA_GIT_COMMITSHA":  webhookData.CommitSHA,
	}

	if skipSSHHostKeyCheck {
		env["AGOLA_SKIPSSHHOSTKEYCHECK"] = "1"
	}

	annotations := map[string]string{
		AnnotationProjectID:     webhookData.ProjectID,
		AnnotationRunType:       string(runType),
		AnnotationEventType:     string(webhookData.Event),
		AnnotationVirtualBranch: genAnnotationVirtualBranch(webhookData),
		AnnotationCommitSHA:     webhookData.CommitSHA,
		AnnotationRef:           webhookData.Ref,
		AnnotationSender:        webhookData.Sender,
		AnnotationMessage:       webhookData.Message,
		AnnotationCommitLink:    webhookData.CommitLink,
		AnnotationCompareLink:   webhookData.CompareLink,
	}

	if webhookData.Event == types.WebhookEventPush {
		annotations[AnnotationBranch] = webhookData.Branch
		annotations[AnnotationBranchLink] = webhookData.BranchLink
	}
	if webhookData.Event == types.WebhookEventTag {
		annotations[AnnotationTag] = webhookData.Tag
		annotations[AnnotationTagLink] = webhookData.TagLink
	}
	if webhookData.Event == types.WebhookEventPullRequest {
		annotations[AnnotationPullRequestID] = webhookData.PullRequestID
		annotations[AnnotationPullRequestLink] = webhookData.PullRequestLink
	}

	group := genGroup(webhookData.ProjectID, webhookData)

	if err := h.createRuns(ctx, data, group, annotations, env); err != nil {
		return http.StatusInternalServerError, "", errors.Wrapf(err, "failed to create run")
	}
	//if err := gitSource.CreateStatus(webhookData.Repo.Owner, webhookData.Repo.Name, webhookData.CommitSHA, gitsource.CommitStatusPending, "localhost:8080", "build %s", "agola"); err != nil {
	//	h.log.Errorf("failed to update commit status: %v", err)
	//}

	return 0, "", nil
}

func (h *webhooksHandler) createRuns(ctx context.Context, configData []byte, group string, annotations, env map[string]string) error {
	config, err := config.ParseConfig([]byte(configData))
	if err != nil {
		return err
	}
	//h.log.Debugf("config: %v", util.Dump(config))

	//h.log.Debugf("pipeline: %s", createRunOpts.PipelineName)
	for _, pipeline := range config.Pipelines {
		rc := runconfig.GenRunConfig(config, pipeline.Name, env)

		h.log.Debugf("rc: %s", util.Dump(rc))
		h.log.Infof("group: %s", group)
		createRunReq := &rsapi.RunCreateRequest{
			RunConfig:   rc,
			Group:       group,
			Annotations: annotations,
		}

		if _, err := h.runserviceClient.CreateRun(ctx, createRunReq); err != nil {
			return err
		}
	}

	return nil
}
