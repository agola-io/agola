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

package gateway

import (
	"fmt"
	"net/http"

	gitsource "github.com/sorintlab/agola/internal/gitsources"
	"github.com/sorintlab/agola/internal/gitsources/agolagit"
	"github.com/sorintlab/agola/internal/services/common"
	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/action"
	rsapi "github.com/sorintlab/agola/internal/services/runservice/api"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"go.uber.org/zap"
	errors "golang.org/x/xerrors"
)

type webhooksHandler struct {
	log               *zap.SugaredLogger
	ah                *action.ActionHandler
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
	userID := r.URL.Query().Get("userid")
	if projectID == "" && userID == "" {
		return http.StatusBadRequest, "", errors.Errorf("bad webhook url %q. Missing projectid or userid", r.URL)
	}

	runType := types.RunTypeProject
	if projectID == "" {
		runType = types.RunTypeUser
	}

	defer r.Body.Close()

	var project *types.Project
	var user *types.User
	var webhookData *types.WebhookData
	var sshPrivKey string
	var cloneURL string
	var sshHostKey string
	var skipSSHHostKeyCheck bool

	var gitSource gitsource.GitSource
	if runType == types.RunTypeProject {
		csProject, _, err := h.configstoreClient.GetProject(ctx, projectID)
		if err != nil {
			return http.StatusBadRequest, "", errors.Errorf("failed to get project %s: %w", projectID, err)
		}
		project = csProject.Project

		user, _, err := h.configstoreClient.GetUserByLinkedAccount(ctx, project.LinkedAccountID)
		if err != nil {
			return http.StatusInternalServerError, "", errors.Errorf("failed to get user by linked account %q: %w", project.LinkedAccountID, err)
		}
		la := user.LinkedAccounts[project.LinkedAccountID]
		h.log.Infof("la: %s", util.Dump(la))
		if la == nil {
			return http.StatusInternalServerError, "", errors.Errorf("linked account %q in user %q doesn't exist", project.LinkedAccountID, user.Name)
		}
		rs, _, err := h.configstoreClient.GetRemoteSource(ctx, la.RemoteSourceID)
		if err != nil {
			return http.StatusInternalServerError, "", errors.Errorf("failed to get remote source %q: %w", la.RemoteSourceID, err)
		}

		gitSource, err = h.ah.GetGitSource(ctx, rs, user.Name, la)
		if err != nil {
			return http.StatusInternalServerError, "", errors.Errorf("failed to create gitea client: %w", err)
		}

		sshPrivKey = project.SSHPrivateKey
		sshHostKey = rs.SSHHostKey
		// use remotesource skipSSHHostKeyCheck config and override with project config if set to true there
		skipSSHHostKeyCheck = rs.SkipSSHHostKeyCheck
		if project.SkipSSHHostKeyCheck {
			skipSSHHostKeyCheck = project.SkipSSHHostKeyCheck
		}
		runType = types.RunTypeProject
		webhookData, err = gitSource.ParseWebhook(r, project.WebhookSecret)
		if err != nil {
			return http.StatusBadRequest, "", errors.Errorf("failed to parse webhook: %w", err)
		}
		// skip nil webhook data
		// TODO(sgotti) report the reason of the skip
		if webhookData == nil {
			h.log.Infof("skipping webhook")
			return 0, "", nil
		}

		webhookData.ProjectID = projectID

		cloneURL = webhookData.SSHURL

	} else {
		gitSource = agolagit.New(h.apiExposedURL + "/repos")
		var err error
		webhookData, err = gitSource.ParseWebhook(r, "")
		if err != nil {
			return http.StatusBadRequest, "", errors.Errorf("failed to parse webhook: %w", err)
		}
		// skip nil webhook data
		// TODO(sgotti) report the reason of the skip
		if webhookData == nil {
			h.log.Infof("skipping webhook")
			return 0, "", nil
		}

		user, _, err = h.configstoreClient.GetUser(ctx, userID)
		if err != nil {
			return http.StatusBadRequest, "", errors.Errorf("failed to get user with id %q: %w", userID, err)
		}
		h.log.Debugf("user: %s", util.Dump(user))

		cloneURL = fmt.Sprintf("%s/%s", h.apiExposedURL+"/repos", webhookData.Repo.Path)
		runType = types.RunTypeUser
	}

	h.log.Infof("webhookData: %s", util.Dump(webhookData))

	req := &action.CreateRunRequest{
		RunType:            runType,
		RefType:            common.WebHookEventToRunRefType(webhookData.Event),
		RunCreationTrigger: types.RunCreationTriggerTypeWebhook,

		Project:             project,
		User:                user,
		RepoPath:            webhookData.Repo.Path,
		GitSource:           gitSource,
		CommitSHA:           webhookData.CommitSHA,
		Message:             webhookData.Message,
		Branch:              webhookData.Branch,
		Tag:                 webhookData.Tag,
		PullRequestID:       webhookData.PullRequestID,
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
		return http.StatusInternalServerError, "", errors.Errorf("failed to create run: %w", err)
	}

	return 0, "", nil
}
