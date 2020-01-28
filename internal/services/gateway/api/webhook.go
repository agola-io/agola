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

package api

import (
	"net/http"

	"agola.io/agola/internal/services/common"
	"agola.io/agola/internal/services/gateway/action"
	"agola.io/agola/internal/services/types"
	"agola.io/agola/internal/util"
	csclient "agola.io/agola/services/configstore/client"
	rsclient "agola.io/agola/services/runservice/client"

	"go.uber.org/zap"
	errors "golang.org/x/xerrors"
)

type webhooksHandler struct {
	log               *zap.SugaredLogger
	ah                *action.ActionHandler
	configstoreClient *csclient.Client
	runserviceClient  *rsclient.Client
	apiExposedURL     string
}

func NewWebhooksHandler(logger *zap.Logger, ah *action.ActionHandler, configstoreClient *csclient.Client, runserviceClient *rsclient.Client, apiExposedURL string) *webhooksHandler {
	return &webhooksHandler{
		log:               logger.Sugar(),
		ah:                ah,
		configstoreClient: configstoreClient,
		runserviceClient:  runserviceClient,
		apiExposedURL:     apiExposedURL,
	}
}

func (h *webhooksHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.handleWebhook(r)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusOK, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

func (h *webhooksHandler) handleWebhook(r *http.Request) error {
	ctx := r.Context()

	projectID := r.URL.Query().Get("projectid")
	if projectID == "" {
		return util.NewErrBadRequest(errors.Errorf("bad webhook url %q. Missing projectid", r.URL))
	}

	defer r.Body.Close()

	csProject, _, err := h.configstoreClient.GetProject(ctx, projectID)
	if err != nil {
		return util.NewErrBadRequest(errors.Errorf("failed to get project %s: %w", projectID, err))
	}
	project := csProject.Project

	user, _, err := h.configstoreClient.GetUserByLinkedAccount(ctx, project.LinkedAccountID)
	if err != nil {
		return util.NewErrInternal(errors.Errorf("failed to get user by linked account %q: %w", project.LinkedAccountID, err))
	}
	la := user.LinkedAccounts[project.LinkedAccountID]
	if la == nil {
		return util.NewErrInternal(errors.Errorf("linked account %q in user %q doesn't exist", project.LinkedAccountID, user.Name))
	}
	rs, _, err := h.configstoreClient.GetRemoteSource(ctx, la.RemoteSourceID)
	if err != nil {
		return util.NewErrInternal(errors.Errorf("failed to get remote source %q: %w", la.RemoteSourceID, err))
	}

	gitSource, err := h.ah.GetGitSource(ctx, rs, user.Name, la)
	if err != nil {
		return util.NewErrInternal(errors.Errorf("failed to create gitea client: %w", err))
	}

	sshPrivKey := project.SSHPrivateKey
	sshHostKey := rs.SSHHostKey
	// use remotesource skipSSHHostKeyCheck config and override with project config if set to true there
	skipSSHHostKeyCheck := rs.SkipSSHHostKeyCheck
	if project.SkipSSHHostKeyCheck {
		skipSSHHostKeyCheck = project.SkipSSHHostKeyCheck
	}

	webhookData, err := gitSource.ParseWebhook(r, project.WebhookSecret)
	if err != nil {
		return util.NewErrBadRequest(errors.Errorf("failed to parse webhook: %w", err))
	}
	// skip nil webhook data
	// TODO(sgotti) report the reason of the skip
	if webhookData == nil {
		h.log.Infof("skipping webhook")
		return nil
	}

	cloneURL := webhookData.SSHURL

	req := &action.CreateRunRequest{
		RunType:            types.RunTypeProject,
		RefType:            common.WebHookEventToRunRefType(webhookData.Event),
		RunCreationTrigger: types.RunCreationTriggerTypeWebhook,

		Project:             project,
		User:                nil,
		RepoPath:            webhookData.Repo.Path,
		GitSource:           gitSource,
		CommitSHA:           webhookData.CommitSHA,
		Message:             webhookData.Message,
		Branch:              webhookData.Branch,
		Tag:                 webhookData.Tag,
		PullRequestID:       webhookData.PullRequestID,
		PRFromSameRepo:      webhookData.PRFromSameRepo,
		Ref:                 webhookData.Ref,
		SSHPrivKey:          sshPrivKey,
		SSHHostKey:          sshHostKey,
		SkipSSHHostKeyCheck: skipSSHHostKeyCheck,
		CloneURL:            cloneURL,

		CommitLink:      webhookData.CommitLink,
		BranchLink:      webhookData.BranchLink,
		TagLink:         webhookData.TagLink,
		PullRequestLink: webhookData.PullRequestLink,
		CompareLink:     webhookData.CompareLink,
	}
	if err := h.ah.CreateRuns(ctx, req); err != nil {
		return util.NewErrInternal(errors.Errorf("failed to create run: %w", err))
	}

	return nil
}
