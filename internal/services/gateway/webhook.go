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
	"context"
	"fmt"
	"net/http"
	"path"

	"github.com/sorintlab/agola/internal/config"
	gitsource "github.com/sorintlab/agola/internal/gitsources"
	"github.com/sorintlab/agola/internal/gitsources/agolagit"
	"github.com/sorintlab/agola/internal/runconfig"
	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/action"
	"github.com/sorintlab/agola/internal/services/gateway/common"
	rsapi "github.com/sorintlab/agola/internal/services/runservice/scheduler/api"
	rstypes "github.com/sorintlab/agola/internal/services/runservice/types"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	defaultSSHPort = "22"

	agolaDefaultConfigDir         = ".agola"
	agolaDefaultJsonnetConfigFile = "config.jsonnet"
	agolaDefaultJsonConfigFile    = "config.json"
	agolaDefaultYamlConfigFile    = "config.yml"

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

	isUserBuild := false
	if projectID == "" {
		isUserBuild = true
	}

	defer r.Body.Close()

	var webhookData *types.WebhookData
	var sshPrivKey string
	var cloneURL string
	var sshHostKey string
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
			return http.StatusInternalServerError, "", errors.Errorf("linked account %q in user %q doesn't exist", project.LinkedAccountID, user.Name)
		}
		rs, _, err := h.configstoreClient.GetRemoteSource(ctx, la.RemoteSourceID)
		if err != nil {
			return http.StatusInternalServerError, "", errors.Wrapf(err, "failed to get remote source %q", la.RemoteSourceID)
		}

		gitSource, err = h.ah.GetGitSource(ctx, rs, user.Name, la)
		if err != nil {
			return http.StatusInternalServerError, "", errors.Wrapf(err, "failed to create gitea client")
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
			return http.StatusBadRequest, "", errors.Wrapf(err, "failed to parse webhook")
		}
		// skip nil webhook data
		// TODO(sgotti) report the reason of the skip
		if webhookData == nil {
			h.log.Infof("skipping webhook")
			return 0, "", nil
		}

		webhookData.ProjectID = projectID

		cloneURL = webhookData.SSHURL

		// get project variables
		pvars, _, err := h.configstoreClient.GetProjectVariables(ctx, project.ID, true)
		if err != nil {
			return http.StatusInternalServerError, "", errors.Wrapf(err, "failed to get project variables")
		}
		h.log.Infof("pvars: %v", util.Dump(pvars))

		// remove overriden variables
		pvars = common.FilterOverriddenVariables(pvars)
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
				secret := common.GetVarValueMatchingSecret(varval, pvar.ParentPath, secrets)
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
		webhookData, err = gitSource.ParseWebhook(r, "")
		if err != nil {
			return http.StatusBadRequest, "", errors.Wrapf(err, "failed to parse webhook")
		}
		// skip nil webhook data
		// TODO(sgotti) report the reason of the skip
		if webhookData == nil {
			h.log.Infof("skipping webhook")
			return 0, "", nil
		}

		user, _, err := h.configstoreClient.GetUser(ctx, userID)
		if err != nil {
			return http.StatusBadRequest, "", errors.Wrapf(err, "failed to get user with id %q", userID)
		}
		h.log.Debugf("user: %s", util.Dump(user))
		userID = user.ID

		cloneURL = fmt.Sprintf("%s/%s", h.apiExposedURL+"/repos", webhookData.Repo.Path)
		runType = types.RunTypeUser
	}

	h.log.Infof("webhookData: %s", util.Dump(webhookData))

	data, filename, err := h.fetchConfigFiles(gitSource, webhookData)
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

	if sshHostKey != "" {
		env["AGOLA_SSHHOSTKEY"] = sshHostKey
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
		group = common.GenRunGroup(common.GroupTypeProject, webhookData.ProjectID, webhookData)
	} else {
		group = common.GenRunGroup(common.GroupTypeUser, userID, webhookData)
	}

	if err := h.createRuns(ctx, filename, data, group, annotations, env, variables, webhookData); err != nil {
		return http.StatusInternalServerError, "", errors.Wrapf(err, "failed to create run")
	}
	//if err := gitSource.CreateStatus(webhookData.Repo.Owner, webhookData.Repo.Name, webhookData.CommitSHA, gitsource.CommitStatusPending, "localhost:8080", "build %s", "agola"); err != nil {
	//	h.log.Errorf("failed to update commit status: %v", err)
	//}

	return 0, "", nil
}

// fetchConfigFiles tries to fetch a config file in one of the supported formats. The precedence is for jsonnet, then json and then yml
// TODO(sgotti) For jsonnet, if we'll support custom import files inside the configdir, also fetch them.
func (h *webhooksHandler) fetchConfigFiles(gitSource gitsource.GitSource, webhookData *types.WebhookData) ([]byte, string, error) {
	var data []byte
	var filename string
	err := util.ExponentialBackoff(util.FetchFileBackoff, func() (bool, error) {
		for _, filename = range []string{agolaDefaultJsonnetConfigFile, agolaDefaultJsonConfigFile, agolaDefaultYamlConfigFile} {
			var err error
			data, err = gitSource.GetFile(webhookData.Repo.Path, webhookData.CommitSHA, path.Join(agolaDefaultConfigDir, filename))
			if err == nil {
				return true, nil
			}
			h.log.Errorf("get file err: %v", err)
		}
		return false, nil
	})
	if err != nil {
		return nil, "", err
	}
	return data, filename, nil
}

func (h *webhooksHandler) createRuns(ctx context.Context, filename string, configData []byte, group string, annotations, staticEnv, variables map[string]string, webhookData *types.WebhookData) error {
	setupErrors := []string{}

	var configFormat config.ConfigFormat
	switch path.Ext(filename) {
	case ".jsonnet":
		configFormat = config.ConfigFormatJsonnet
	case ".json":
		fallthrough
	case ".yml":
		configFormat = config.ConfigFormatJSON

	}
	config, err := config.ParseConfig([]byte(configData), configFormat)
	if err != nil {
		log.Errorf("failed to parse config: %+v", err)

		// create a run (per config file) with a generic error since we cannot parse
		// it and know how many runs are defined
		setupErrors = append(setupErrors, err.Error())
		createRunReq := &rsapi.RunCreateRequest{
			RunConfigTasks:    nil,
			Group:             group,
			SetupErrors:       setupErrors,
			Name:              rstypes.RunGenericSetupErrorName,
			StaticEnvironment: staticEnv,
			Annotations:       annotations,
		}

		if _, err := h.runserviceClient.CreateRun(ctx, createRunReq); err != nil {
			log.Errorf("failed to create run: %+v", err)
			return err
		}
		return nil
	}

	for _, run := range config.Runs {
		rcts := runconfig.GenRunConfigTasks(util.DefaultUUIDGenerator{}, config, run.Name, variables, webhookData.Branch, webhookData.Tag, webhookData.Ref)

		h.log.Debugf("rcts: %s", util.Dump(rcts))
		h.log.Infof("group: %s", group)
		createRunReq := &rsapi.RunCreateRequest{
			RunConfigTasks:    rcts,
			Group:             group,
			SetupErrors:       setupErrors,
			Name:              run.Name,
			StaticEnvironment: staticEnv,
			Annotations:       annotations,
		}

		if _, err := h.runserviceClient.CreateRun(ctx, createRunReq); err != nil {
			log.Errorf("failed to create run: %+v", err)
			return err
		}
	}

	return nil
}
