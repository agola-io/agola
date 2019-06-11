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

package action

import (
	"context"
	"encoding/json"
	"net/http"
	"path"

	"github.com/sorintlab/agola/internal/config"
	gitsource "github.com/sorintlab/agola/internal/gitsources"
	"github.com/sorintlab/agola/internal/runconfig"
	"github.com/sorintlab/agola/internal/services/common"
	rsapi "github.com/sorintlab/agola/internal/services/runservice/api"
	rstypes "github.com/sorintlab/agola/internal/services/runservice/types"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	errors "golang.org/x/xerrors"
)

const (
	defaultSSHPort = "22"

	agolaDefaultConfigDir         = ".agola"
	agolaDefaultJsonnetConfigFile = "config.jsonnet"
	agolaDefaultJsonConfigFile    = "config.json"
	agolaDefaultYamlConfigFile    = "config.yml"

	// List of runs annotations
	AnnotationRunType   = "run_type"
	AnnotationRefType   = "ref_type"
	AnnotationProjectID = "projectid"
	AnnotationUserID    = "userid"

	AnnotationRunCreationTrigger = "run_creation_trigger"
	AnnotationWebhookEvent       = "webhook_event"
	AnnotationWebhookSender      = "webhook_sender"

	AnnotationCommitSHA   = "commit_sha"
	AnnotationRef         = "ref"
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

func (h *ActionHandler) GetRun(ctx context.Context, runID string) (*rsapi.RunResponse, error) {
	runResp, resp, err := h.runserviceClient.GetRun(ctx, runID, nil)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}
	canGetRun, err := h.CanGetRun(ctx, runResp.RunConfig.Group)
	if err != nil {
		return nil, errors.Errorf("failed to determine permissions: %w", err)
	}
	if !canGetRun {
		return nil, util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	return runResp, nil
}

type GetRunsRequest struct {
	PhaseFilter  []string
	Group        string
	LastRun      bool
	ChangeGroups []string
	StartRunID   string
	Limit        int
	Asc          bool
}

func (h *ActionHandler) GetRuns(ctx context.Context, req *GetRunsRequest) (*rsapi.GetRunsResponse, error) {
	canGetRun, err := h.CanGetRun(ctx, req.Group)
	if err != nil {
		return nil, errors.Errorf("failed to determine permissions: %w", err)
	}
	if !canGetRun {
		return nil, util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	groups := []string{req.Group}
	runsResp, resp, err := h.runserviceClient.GetRuns(ctx, req.PhaseFilter, groups, req.LastRun, req.ChangeGroups, req.StartRunID, req.Limit, req.Asc)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}

	return runsResp, nil
}

type GetLogsRequest struct {
	RunID  string
	TaskID string
	Setup  bool
	Step   int
	Follow bool
}

func (h *ActionHandler) GetLogs(ctx context.Context, req *GetLogsRequest) (*http.Response, error) {
	runResp, resp, err := h.runserviceClient.GetRun(ctx, req.RunID, nil)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}
	canGetRun, err := h.CanGetRun(ctx, runResp.RunConfig.Group)
	if err != nil {
		return nil, errors.Errorf("failed to determine permissions: %w", err)
	}
	if !canGetRun {
		return nil, util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	resp, err = h.runserviceClient.GetLogs(ctx, req.RunID, req.TaskID, req.Setup, req.Step, req.Follow)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}

	return resp, nil
}

type RunActionType string

const (
	RunActionTypeRestart RunActionType = "restart"
	RunActionTypeCancel  RunActionType = "cancel"
	RunActionTypeStop    RunActionType = "stop"
)

type RunActionsRequest struct {
	RunID      string
	ActionType RunActionType

	// Restart
	FromStart bool
}

func (h *ActionHandler) RunAction(ctx context.Context, req *RunActionsRequest) (*rsapi.RunResponse, error) {
	runResp, resp, err := h.runserviceClient.GetRun(ctx, req.RunID, nil)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}
	canGetRun, err := h.CanDoRunActions(ctx, runResp.RunConfig.Group)
	if err != nil {
		return nil, errors.Errorf("failed to determine permissions: %w", err)
	}
	if !canGetRun {
		return nil, util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	switch req.ActionType {
	case RunActionTypeRestart:
		rsreq := &rsapi.RunCreateRequest{
			RunID:     req.RunID,
			FromStart: req.FromStart,
		}

		runResp, resp, err = h.runserviceClient.CreateRun(ctx, rsreq)
		if err != nil {
			return nil, ErrFromRemote(resp, err)
		}

	case RunActionTypeCancel:
		rsreq := &rsapi.RunActionsRequest{
			ActionType: rsapi.RunActionTypeChangePhase,
			Phase:      rstypes.RunPhaseCancelled,
		}

		resp, err = h.runserviceClient.RunActions(ctx, req.RunID, rsreq)
		if err != nil {
			return nil, ErrFromRemote(resp, err)
		}

	case RunActionTypeStop:
		rsreq := &rsapi.RunActionsRequest{
			ActionType: rsapi.RunActionTypeStop,
		}

		resp, err = h.runserviceClient.RunActions(ctx, req.RunID, rsreq)
		if err != nil {
			return nil, ErrFromRemote(resp, err)
		}

	default:
		return nil, util.NewErrBadRequest(errors.Errorf("wrong run action type %q", req.ActionType))
	}

	return runResp, nil
}

type RunTaskActionType string

const (
	RunTaskActionTypeApprove RunTaskActionType = "approve"
)

type RunTaskActionsRequest struct {
	RunID  string
	TaskID string

	ActionType RunTaskActionType
}

func (h *ActionHandler) RunTaskAction(ctx context.Context, req *RunTaskActionsRequest) error {
	runResp, resp, err := h.runserviceClient.GetRun(ctx, req.RunID, nil)
	if err != nil {
		return ErrFromRemote(resp, err)
	}
	canDoRunAction, err := h.CanDoRunActions(ctx, runResp.RunConfig.Group)
	if err != nil {
		return errors.Errorf("failed to determine permissions: %w", err)
	}
	if !canDoRunAction {
		return util.NewErrForbidden(errors.Errorf("user not authorized"))
	}
	curUserID := h.CurrentUserID(ctx)
	if curUserID == "" {
		return util.NewErrBadRequest(errors.Errorf("no logged in user"))
	}

	switch req.ActionType {
	case RunTaskActionTypeApprove:
		rt, ok := runResp.Run.Tasks[req.TaskID]
		if !ok {
			return util.NewErrBadRequest(errors.Errorf("run %q doesn't have task %q", req.RunID, req.TaskID))
		}

		approvers := []string{}
		annotations := map[string]string{}
		if rt.Annotations != nil {
			annotations = rt.Annotations
		}
		approversAnnotation, ok := annotations[common.ApproversAnnotation]
		if ok {
			if err := json.Unmarshal([]byte(approversAnnotation), &approvers); err != nil {
				return errors.Errorf("failed to unmarshal run task approvers annotation: %w", err)
			}
		}

		for _, approver := range approvers {
			if approver == curUserID {
				return util.NewErrBadRequest(errors.Errorf("user %q alredy approved the task", approver))
			}
		}
		approvers = append(approvers, curUserID)

		approversj, err := json.Marshal(approvers)
		if err != nil {
			return errors.Errorf("failed to marshal run task approvers annotation: %w", err)
		}

		annotations[common.ApproversAnnotation] = string(approversj)

		rsreq := &rsapi.RunTaskActionsRequest{
			ActionType:              rsapi.RunTaskActionTypeSetAnnotations,
			Annotations:             annotations,
			ChangeGroupsUpdateToken: runResp.ChangeGroupsUpdateToken,
		}

		resp, err := h.runserviceClient.RunTaskActions(ctx, req.RunID, req.TaskID, rsreq)
		if err != nil {
			return ErrFromRemote(resp, err)
		}

	default:
		return util.NewErrBadRequest(errors.Errorf("wrong run task action type %q", req.ActionType))
	}

	return nil
}

type CreateRunRequest struct {
	RunType            types.RunType
	RefType            types.RunRefType
	RunCreationTrigger types.RunCreationTriggerType

	Project             *types.Project
	User                *types.User
	RepoPath            string
	GitSource           gitsource.GitSource
	CommitSHA           string
	Message             string
	Branch              string
	Tag                 string
	Ref                 string
	PullRequestID       string
	SSHPrivKey          string
	SSHHostKey          string
	SkipSSHHostKeyCheck bool
	CloneURL            string

	WebhookEvent  string
	WebhookSender string

	CommitLink      string
	BranchLink      string
	TagLink         string
	PullRequestLink string

	// CompareLink is provided only when triggered by a webhook and contains the
	// commit compare link
	CompareLink string
}

func (h *ActionHandler) CreateRuns(ctx context.Context, req *CreateRunRequest) error {
	setupErrors := []string{}

	if req.CommitSHA == "" {
		return util.NewErrBadRequest(errors.Errorf("empty commit SHA"))
	}
	if req.Message == "" {
		return util.NewErrBadRequest(errors.Errorf("empty message"))
	}

	var baseGroupType common.GroupType
	var baseGroupID string
	var groupType common.GroupType
	var group string

	if req.RunType == types.RunTypeProject {
		baseGroupType = common.GroupTypeProject
		baseGroupID = req.Project.ID
	} else {
		baseGroupType = common.GroupTypeUser
		baseGroupID = req.User.ID
	}

	switch req.RefType {
	case types.RunRefTypeBranch:
		groupType = common.GroupTypeBranch
		group = req.Branch
	case types.RunRefTypeTag:
		groupType = common.GroupTypeTag
		group = req.Tag
	case types.RunRefTypePullRequest:
		groupType = common.GroupTypePullRequest
		group = req.PullRequestID
	}

	runGroup := common.GenRunGroup(baseGroupType, baseGroupID, groupType, group)

	gitURL, err := util.ParseGitURL(req.CloneURL)
	if err != nil {
		return errors.Errorf("failed to parse clone url: %w", err)
	}
	gitHost := gitURL.Hostname()
	gitPort := gitURL.Port()
	if gitPort == "" {
		gitPort = defaultSSHPort
	}

	// this env vars overrides other env vars
	env := map[string]string{
		"CI":                   "true",
		"AGOLA_SSHPRIVKEY":     req.SSHPrivKey,
		"AGOLA_REPOSITORY_URL": req.CloneURL,
		"AGOLA_GIT_HOST":       gitHost,
		"AGOLA_GIT_PORT":       gitPort,
		"AGOLA_GIT_BRANCH":     req.Branch,
		"AGOLA_GIT_TAG":        req.Tag,
		"AGOLA_GIT_REF":        req.Ref,
		"AGOLA_GIT_COMMITSHA":  req.CommitSHA,
	}

	if req.SSHHostKey != "" {
		env["AGOLA_SSHHOSTKEY"] = req.SSHHostKey
	}
	if req.SkipSSHHostKeyCheck {
		env["AGOLA_SKIPSSHHOSTKEYCHECK"] = "1"
	}

	variables := map[string]string{}
	if req.RunType == types.RunTypeProject {
		var err error
		variables, err = h.genRunVariables(ctx, req)
		if err != nil {
			return err
		}
	}

	annotations := map[string]string{
		AnnotationRunType:            string(req.RunType),
		AnnotationRefType:            string(req.RefType),
		AnnotationRunCreationTrigger: string(req.RunCreationTrigger),
		AnnotationWebhookEvent:       req.WebhookEvent,
		AnnotationWebhookSender:      req.WebhookSender,
		AnnotationCommitSHA:          req.CommitSHA,
		AnnotationRef:                req.Ref,
		AnnotationMessage:            req.Message,
		AnnotationCommitLink:         req.CommitLink,
		AnnotationCompareLink:        req.CompareLink,
	}

	if req.RunType == types.RunTypeProject {
		annotations[AnnotationProjectID] = req.Project.ID
	} else {
		annotations[AnnotationUserID] = req.User.ID
	}

	if req.Branch != "" {
		annotations[AnnotationBranch] = req.Branch
		annotations[AnnotationBranchLink] = req.BranchLink
	}
	if req.Tag != "" {
		annotations[AnnotationTag] = req.Tag
		annotations[AnnotationTagLink] = req.TagLink
	}
	if req.PullRequestID != "" {
		annotations[AnnotationPullRequestID] = req.PullRequestID
		annotations[AnnotationPullRequestLink] = req.PullRequestLink
	}

	data, filename, err := h.fetchConfigFiles(req.GitSource, req.RepoPath, req.CommitSHA)
	if err != nil {
		return util.NewErrInternal(errors.Errorf("failed to fetch config file: %w", err))
	}
	h.log.Debug("data: %s", data)

	var configFormat config.ConfigFormat
	switch path.Ext(filename) {
	case ".jsonnet":
		configFormat = config.ConfigFormatJsonnet
	case ".json":
		fallthrough
	case ".yml":
		configFormat = config.ConfigFormatJSON

	}
	config, err := config.ParseConfig([]byte(data), configFormat)
	if err != nil {
		h.log.Errorf("failed to parse config: %+v", err)

		// create a run (per config file) with a generic error since we cannot parse
		// it and know how many runs are defined
		setupErrors = append(setupErrors, err.Error())
		createRunReq := &rsapi.RunCreateRequest{
			RunConfigTasks:    nil,
			Group:             runGroup,
			SetupErrors:       setupErrors,
			Name:              rstypes.RunGenericSetupErrorName,
			StaticEnvironment: env,
			Annotations:       annotations,
		}

		if _, _, err := h.runserviceClient.CreateRun(ctx, createRunReq); err != nil {
			h.log.Errorf("failed to create run: %+v", err)
			return err
		}
		return nil
	}

	for _, run := range config.Runs {
		rcts := runconfig.GenRunConfigTasks(util.DefaultUUIDGenerator{}, config, run.Name, variables, req.Branch, req.Tag, req.Ref)

		createRunReq := &rsapi.RunCreateRequest{
			RunConfigTasks:    rcts,
			Group:             runGroup,
			SetupErrors:       setupErrors,
			Name:              run.Name,
			StaticEnvironment: env,
			Annotations:       annotations,
		}

		if _, _, err := h.runserviceClient.CreateRun(ctx, createRunReq); err != nil {
			h.log.Errorf("failed to create run: %+v", err)
			return err
		}
	}

	return nil
}

func (h *ActionHandler) fetchConfigFiles(gitSource gitsource.GitSource, repopath, commitSHA string) ([]byte, string, error) {
	var data []byte
	var filename string
	err := util.ExponentialBackoff(util.FetchFileBackoff, func() (bool, error) {
		for _, filename = range []string{agolaDefaultJsonnetConfigFile, agolaDefaultJsonConfigFile, agolaDefaultYamlConfigFile} {
			var err error
			data, err = gitSource.GetFile(repopath, commitSHA, path.Join(agolaDefaultConfigDir, filename))
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

func (h *ActionHandler) genRunVariables(ctx context.Context, req *CreateRunRequest) (map[string]string, error) {
	variables := map[string]string{}

	// get project variables
	pvars, _, err := h.configstoreClient.GetProjectVariables(ctx, req.Project.ID, true)
	if err != nil {
		return nil, errors.Errorf("failed to get project variables: %w", err)
	}
	h.log.Infof("pvars: %v", util.Dump(pvars))

	// remove overriden variables
	pvars = common.FilterOverriddenVariables(pvars)
	h.log.Infof("pvars: %v", util.Dump(pvars))

	// get project secrets
	secrets, _, err := h.configstoreClient.GetProjectSecrets(ctx, req.Project.ID, true)
	if err != nil {
		return nil, errors.Errorf("failed to get project secrets: %w", err)
	}
	h.log.Infof("secrets: %v", util.Dump(secrets))
	for _, pvar := range pvars {
		// find the value match
		var varval types.VariableValue
		for _, varval = range pvar.Values {
			h.log.Infof("varval: %v", util.Dump(varval))
			match := types.MatchWhen(varval.When, req.Branch, req.Tag, req.Ref)
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

	return variables, nil
}
