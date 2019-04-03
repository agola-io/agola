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
	"github.com/sorintlab/agola/internal/gitsources/agolagit"
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
	defaultSSHPort = "22"

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

type GroupType string

const (
	GroupTypeProject     GroupType = "project"
	GroupTypeUser        GroupType = "user"
	GroupTypeBranch      GroupType = "branch"
	GroupTypeTag         GroupType = "tag"
	GroupTypePullRequest GroupType = "pr"
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

func genGroup(baseGroupType GroupType, baseGroupID string, webhookData *types.WebhookData) string {
	// we pathescape the branch name to handle branches with slashes and make the
	// branch a single path entry
	switch webhookData.Event {
	case types.WebhookEventPush:
		return path.Join("/", string(baseGroupType), baseGroupID, string(GroupTypeBranch), url.PathEscape(webhookData.Branch))
	case types.WebhookEventTag:
		return path.Join("/", string(baseGroupType), baseGroupID, string(GroupTypeTag), url.PathEscape(webhookData.Tag))
	case types.WebhookEventPullRequest:
		return path.Join("/", string(baseGroupType), baseGroupID, string(GroupTypePullRequest), url.PathEscape(webhookData.PullRequestID))
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
	userID := r.URL.Query().Get("userid")
	if projectID == "" && userID == "" {
		return http.StatusBadRequest, "", errors.Errorf("bad webhook url %q. Missing projectid or userid", r.URL)
	}

	isUserBuild := false
	if projectID == "" {
		isUserBuild = true
	}

	defer r.Body.Close()

	var webhookData *types.WebhookData
	var sshPrivKey string
	var cloneURL string
	var skipSSHHostKeyCheck bool
	var runType types.RunType
	variables := map[string]string{}

	var gitSource gitsource.GitSource
	if !isUserBuild {
		project, _, err := h.configstoreClient.GetProject(ctx, projectID)
		if err != nil {
			return http.StatusBadRequest, "", errors.Wrapf(err, "failed to get project %s", projectID)
		}
		h.log.Infof("project: %s", util.Dump(project))

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

		sshPrivKey = project.SSHPrivateKey
		cloneURL = project.CloneURL
		skipSSHHostKeyCheck = project.SkipSSHHostKeyCheck
		runType = types.RunTypeProject
		webhookData, err = gitSource.ParseWebhook(r)
		if err != nil {
			return http.StatusBadRequest, "", errors.Wrapf(err, "failed to parse webhook")
		}
		webhookData.ProjectID = projectID

		// get project variables
		pvars, _, err := h.configstoreClient.GetProjectVariables(ctx, project.ID, true)
		if err != nil {
			return http.StatusInternalServerError, "", errors.Wrapf(err, "failed to get project variables")
		}
		h.log.Infof("pvars: %v", util.Dump(pvars))

		// remove overriden variables
		pvars = common.FilterOverridenVariables(pvars)
		h.log.Infof("pvars: %v", util.Dump(pvars))

		// get project secrets
		secrets, _, err := h.configstoreClient.GetProjectSecrets(ctx, project.ID, true)
		if err != nil {
			return http.StatusInternalServerError, "", errors.Wrapf(err, "failed to get project secrets")
		}
		h.log.Infof("secrets: %v", util.Dump(secrets))
		for _, pvar := range pvars {
			// find the value match
			var varval types.VariableValue
			for _, varval = range pvar.Values {
				h.log.Infof("varval: %v", util.Dump(varval))
				match := types.MatchWhen(varval.When, webhookData.Branch, webhookData.Tag, webhookData.Ref)
				if !match {
					continue
				}
				// get the secret value referenced by the variable, it must be a secret at the same level or a lower level
				secret := common.GetVarValueMatchingSecret(varval, pvar.Parent.Path, secrets)
				h.log.Infof("secret: %v", util.Dump(secret))
				if secret != nil {
					varValue, ok := secret.Data[varval.SecretVar]
					if ok {
						variables[pvar.Name] = varValue
					}
				}
				break
			}
		}
		h.log.Infof("variables: %v", util.Dump(variables))

	} else {
		gitSource = agolagit.New(h.apiExposedURL + "/repos")
		var err error
		webhookData, err = gitSource.ParseWebhook(r)
		if err != nil {
			return http.StatusBadRequest, "", errors.Wrapf(err, "failed to parse webhook")
		}

		user, _, err := h.configstoreClient.GetUser(ctx, userID)
		if err != nil {
			return http.StatusBadRequest, "", errors.Wrapf(err, "failed to get user with id %q", userID)
		}
		h.log.Debugf("user: %s", util.Dump(user))
		userID = user.ID

		cloneURL = fmt.Sprintf("%s/%s/%s", h.apiExposedURL+"/repos", webhookData.Repo.Owner, webhookData.Repo.Name)
		runType = types.RunTypeUser
	}

	h.log.Infof("webhookData: %s", util.Dump(webhookData))

	var data []byte
	err := util.ExponentialBackoff(util.FetchFileBackoff, func() (bool, error) {
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
	gitHost := gitURL.Hostname()
	gitPort := gitURL.Port()
	if gitPort == "" {
		gitPort = defaultSSHPort
	}

	// this env vars ovverrides other env vars
	env := map[string]string{
		"CI":                   "true",
		"AGOLA_SSHPRIVKEY":     sshPrivKey,
		"AGOLA_REPOSITORY_URL": cloneURL,
		"AGOLA_GIT_HOST":       gitHost,
		"AGOLA_GIT_PORT":       gitPort,
		"AGOLA_GIT_REF":        webhookData.Ref,
		"AGOLA_GIT_COMMITSHA":  webhookData.CommitSHA,
	}

	if skipSSHHostKeyCheck {
		env["AGOLA_SKIPSSHHOSTKEYCHECK"] = "1"
	}

	annotations := map[string]string{
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

	if !isUserBuild {
		annotations[AnnotationProjectID] = webhookData.ProjectID
	} else {
		annotations[AnnotationUserID] = userID
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

	var group string
	if !isUserBuild {
		group = genGroup(GroupTypeProject, webhookData.ProjectID, webhookData)
	} else {
		group = genGroup(GroupTypeUser, userID, webhookData)
	}

	if err := h.createRuns(ctx, data, group, annotations, env, variables, webhookData); err != nil {
		return http.StatusInternalServerError, "", errors.Wrapf(err, "failed to create run")
	}
	//if err := gitSource.CreateStatus(webhookData.Repo.Owner, webhookData.Repo.Name, webhookData.CommitSHA, gitsource.CommitStatusPending, "localhost:8080", "build %s", "agola"); err != nil {
	//	h.log.Errorf("failed to update commit status: %v", err)
	//}

	return 0, "", nil
}

func (h *webhooksHandler) createRuns(ctx context.Context, configData []byte, group string, annotations, env, variables map[string]string, webhookData *types.WebhookData) error {
	config, err := config.ParseConfig([]byte(configData))
	if err != nil {
		return errors.Wrapf(err, "failed to parse config")
	}
	//h.log.Debugf("config: %v", util.Dump(config))

	//h.log.Debugf("pipeline: %s", createRunOpts.PipelineName)
	for _, pipeline := range config.Pipelines {
		rc := runconfig.GenRunConfig(util.DefaultUUIDGenerator{}, config, pipeline.Name, env, variables, webhookData.Branch, webhookData.Tag, webhookData.Ref)

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
