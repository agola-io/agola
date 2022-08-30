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
	"regexp"

	"agola.io/agola/internal/config"
	"agola.io/agola/internal/errors"
	gitsource "agola.io/agola/internal/gitsources"
	"agola.io/agola/internal/runconfig"
	scommon "agola.io/agola/internal/services/common"
	"agola.io/agola/internal/services/gateway/common"
	itypes "agola.io/agola/internal/services/types"
	"agola.io/agola/internal/util"
	cstypes "agola.io/agola/services/configstore/types"
	rsapitypes "agola.io/agola/services/runservice/api/types"
	rstypes "agola.io/agola/services/runservice/types"
	"agola.io/agola/services/types"
)

const (
	defaultSSHPort = "22"

	agolaDefaultConfigDir          = ".agola"
	agolaDefaultStarlarkConfigFile = "config.star"
	agolaDefaultJsonnetConfigFile  = "config.jsonnet"
	agolaDefaultJsonConfigFile     = "config.json"
	agolaDefaultYamlConfigFile     = "config.yml"

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

var (
	SkipRunMessage = regexp.MustCompile(`.*\[ci skip\].*`)
)

func (h *ActionHandler) GetRun(ctx context.Context, groupType scommon.GroupType, ref string, runNumber uint64) (*rsapitypes.RunResponse, error) {
	canGetRun, groupID, err := h.CanGetRun(ctx, groupType, ref)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to determine permissions")
	}
	if !canGetRun {
		return nil, util.NewAPIError(util.ErrForbidden, errors.Errorf("user not authorized"))
	}

	group := scommon.GenBaseRunGroup(groupType, groupID)

	runResp, _, err := h.runserviceClient.GetRunByGroup(ctx, group, runNumber, nil)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), err)
	}

	return runResp, nil
}

type GetRunsRequest struct {
	GroupType       scommon.GroupType
	Ref             string
	SubGroup        string
	PhaseFilter     []string
	ResultFilter    []string
	StartRunCounter uint64
	Limit           int
	Asc             bool
}

func (h *ActionHandler) GetRuns(ctx context.Context, req *GetRunsRequest) (*rsapitypes.GetRunsResponse, error) {
	canGetRun, groupID, err := h.CanGetRun(ctx, req.GroupType, req.Ref)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to determine permissions")
	}
	if !canGetRun {
		return nil, util.NewAPIError(util.ErrForbidden, errors.Errorf("user not authorized"))
	}

	group := scommon.GenBaseRunGroup(req.GroupType, groupID)
	group = path.Join(group, req.SubGroup)

	runsResp, _, err := h.runserviceClient.GetGroupRuns(ctx, req.PhaseFilter, req.ResultFilter, group, nil, req.StartRunCounter, req.Limit, req.Asc)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), err)
	}

	return runsResp, nil
}

type GetLogsRequest struct {
	GroupType scommon.GroupType
	Ref       string
	RunNumber uint64
	TaskID    string
	Setup     bool
	Step      int
	Follow    bool
}

func (h *ActionHandler) GetLogs(ctx context.Context, req *GetLogsRequest) (*http.Response, error) {
	canGetRun, groupID, err := h.CanGetRun(ctx, req.GroupType, req.Ref)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to determine permissions")
	}
	if !canGetRun {
		return nil, util.NewAPIError(util.ErrForbidden, errors.Errorf("user not authorized"))
	}

	group := scommon.GenBaseRunGroup(req.GroupType, groupID)

	runResp, _, err := h.runserviceClient.GetRunByGroup(ctx, group, req.RunNumber, nil)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), err)
	}

	resp, err := h.runserviceClient.GetLogs(ctx, runResp.Run.ID, req.TaskID, req.Setup, req.Step, req.Follow)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), err)
	}

	return resp, nil
}

type DeleteLogsRequest struct {
	GroupType scommon.GroupType
	Ref       string
	RunNumber uint64
	TaskID    string
	Setup     bool
	Step      int
}

func (h *ActionHandler) DeleteLogs(ctx context.Context, req *DeleteLogsRequest) error {
	canDoRunActions, groupID, err := h.CanDoRunActions(ctx, req.GroupType, req.Ref)
	if err != nil {
		return errors.Wrapf(err, "failed to determine permissions")
	}
	if !canDoRunActions {
		return util.NewAPIError(util.ErrForbidden, errors.Errorf("user not authorized"))
	}

	group := scommon.GenBaseRunGroup(req.GroupType, groupID)

	runResp, _, err := h.runserviceClient.GetRunByGroup(ctx, group, req.RunNumber, nil)
	if err != nil {
		return util.NewAPIError(util.KindFromRemoteError(err), err)
	}

	if _, err = h.runserviceClient.DeleteLogs(ctx, runResp.Run.ID, req.TaskID, req.Setup, req.Step); err != nil {
		return util.NewAPIError(util.KindFromRemoteError(err), err)
	}

	return nil
}

type RunActionType string

const (
	RunActionTypeRestart RunActionType = "restart"
	RunActionTypeCancel  RunActionType = "cancel"
	RunActionTypeStop    RunActionType = "stop"
)

type RunActionsRequest struct {
	GroupType  scommon.GroupType
	Ref        string
	RunNumber  uint64
	ActionType RunActionType

	// Restart
	FromStart bool
}

func (h *ActionHandler) RunAction(ctx context.Context, req *RunActionsRequest) (*rsapitypes.RunResponse, error) {
	canDoRunActions, groupID, err := h.CanDoRunActions(ctx, req.GroupType, req.Ref)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to determine permissions")
	}
	if !canDoRunActions {
		return nil, util.NewAPIError(util.ErrForbidden, errors.Errorf("user not authorized"))
	}

	group := scommon.GenBaseRunGroup(req.GroupType, groupID)

	runResp, _, err := h.runserviceClient.GetRunByGroup(ctx, group, req.RunNumber, nil)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), err)
	}
	runID := runResp.Run.ID

	switch req.ActionType {
	case RunActionTypeRestart:
		rsreq := &rsapitypes.RunCreateRequest{
			RunID:     runID,
			FromStart: req.FromStart,
		}

		runResp, _, err = h.runserviceClient.CreateRun(ctx, rsreq)
		if err != nil {
			return nil, util.NewAPIError(util.KindFromRemoteError(err), err)
		}

	case RunActionTypeCancel:
		rsreq := &rsapitypes.RunActionsRequest{
			ActionType: rsapitypes.RunActionTypeChangePhase,
			Phase:      rstypes.RunPhaseCancelled,
		}

		if _, err = h.runserviceClient.RunActions(ctx, runID, rsreq); err != nil {
			return nil, util.NewAPIError(util.KindFromRemoteError(err), err)
		}

	case RunActionTypeStop:
		rsreq := &rsapitypes.RunActionsRequest{
			ActionType: rsapitypes.RunActionTypeStop,
		}

		if _, err = h.runserviceClient.RunActions(ctx, runID, rsreq); err != nil {
			return nil, util.NewAPIError(util.KindFromRemoteError(err), err)
		}

	default:
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("wrong run action type %q", req.ActionType))
	}

	return runResp, nil
}

type RunTaskActionType string

const (
	RunTaskActionTypeApprove RunTaskActionType = "approve"
)

type RunTaskActionsRequest struct {
	GroupType scommon.GroupType
	Ref       string
	RunNumber uint64
	TaskID    string

	ActionType RunTaskActionType
}

func (h *ActionHandler) RunTaskAction(ctx context.Context, req *RunTaskActionsRequest) error {
	canDoRunAction, groupID, err := h.CanDoRunActions(ctx, req.GroupType, req.Ref)
	if err != nil {
		return errors.Wrapf(err, "failed to determine permissions")
	}
	if !canDoRunAction {
		return util.NewAPIError(util.ErrForbidden, errors.Errorf("user not authorized"))
	}

	group := scommon.GenBaseRunGroup(req.GroupType, groupID)

	runResp, _, err := h.runserviceClient.GetRunByGroup(ctx, group, req.RunNumber, nil)
	if err != nil {
		return util.NewAPIError(util.KindFromRemoteError(err), err)
	}

	runID := runResp.Run.ID

	curUserID := common.CurrentUserID(ctx)
	if curUserID == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("no logged in user"))
	}

	switch req.ActionType {
	case RunTaskActionTypeApprove:
		rt, ok := runResp.Run.Tasks[req.TaskID]
		if !ok {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("run %q doesn't have task %q", req.RunNumber, req.TaskID))
		}

		approvers := []string{}
		annotations := map[string]string{}
		if rt.Annotations != nil {
			annotations = rt.Annotations
		}
		approversAnnotation, ok := annotations[scommon.ApproversAnnotation]
		if ok {
			if err := json.Unmarshal([]byte(approversAnnotation), &approvers); err != nil {
				return errors.Wrapf(err, "failed to unmarshal run task approvers annotation")
			}
		}

		for _, approver := range approvers {
			if approver == curUserID {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("user %q alredy approved the task", approver))
			}
		}
		approvers = append(approvers, curUserID)

		approversj, err := json.Marshal(approvers)
		if err != nil {
			return errors.Wrapf(err, "failed to marshal run task approvers annotation")
		}

		annotations[scommon.ApproversAnnotation] = string(approversj)

		rsreq := &rsapitypes.RunTaskActionsRequest{
			ActionType:              rsapitypes.RunTaskActionTypeSetAnnotations,
			Annotations:             annotations,
			ChangeGroupsUpdateToken: runResp.ChangeGroupsUpdateToken,
		}

		if _, err := h.runserviceClient.RunTaskActions(ctx, runID, req.TaskID, rsreq); err != nil {
			return util.NewAPIError(util.KindFromRemoteError(err), err)
		}

	default:
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("wrong run task action type %q", req.ActionType))
	}

	return nil
}

type CreateRunRequest struct {
	RunType            itypes.RunType
	RefType            itypes.RunRefType
	RunCreationTrigger itypes.RunCreationTriggerType

	Project             *cstypes.Project
	User                *cstypes.User
	RepoPath            string
	GitSource           gitsource.GitSource
	CommitSHA           string
	Message             string
	Branch              string
	Tag                 string
	Ref                 string
	PullRequestID       string
	PRFromSameRepo      bool
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

	// fields only used with user direct runs
	UserRunRepoUUID string
	Variables       map[string]string
}

func (h *ActionHandler) CreateRuns(ctx context.Context, req *CreateRunRequest) error {
	setupErrors := []string{}

	if req.CommitSHA == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("empty commit SHA"))
	}
	if req.Message == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("empty message"))
	}

	var baseGroupType scommon.GroupType
	var baseGroupID string
	var groupType scommon.GroupType
	var group string

	if req.RunType == itypes.RunTypeProject {
		baseGroupType = scommon.GroupTypeProject
		baseGroupID = req.Project.ID
	} else {
		baseGroupType = scommon.GroupTypeUser
		baseGroupID = req.User.ID
	}

	switch req.RefType {
	case itypes.RunRefTypeBranch:
		groupType = scommon.GroupTypeBranch
		group = req.Branch
	case itypes.RunRefTypeTag:
		groupType = scommon.GroupTypeTag
		group = req.Tag
	case itypes.RunRefTypePullRequest:
		groupType = scommon.GroupTypePullRequest
		group = req.PullRequestID
	}

	runGroup := scommon.GenRunGroup(baseGroupType, baseGroupID, groupType, group)

	gitURL, err := util.ParseGitURL(req.CloneURL)
	if err != nil {
		return errors.Wrapf(err, "failed to parse clone url")
	}
	gitHost := gitURL.Hostname()
	gitPort := gitURL.Port()
	if gitPort == "" {
		gitPort = defaultSSHPort
	}

	// this env vars overrides other env vars
	env := map[string]string{
		"CI":                    "true",
		"AGOLA_SSHPRIVKEY":      req.SSHPrivKey,
		"AGOLA_REPOSITORY_URL":  req.CloneURL,
		"AGOLA_GIT_HOST":        gitHost,
		"AGOLA_GIT_PORT":        gitPort,
		"AGOLA_GIT_BRANCH":      req.Branch,
		"AGOLA_GIT_TAG":         req.Tag,
		"AGOLA_PULL_REQUEST_ID": req.PullRequestID,
		"AGOLA_GIT_REF_TYPE":    string(req.RefType),
		"AGOLA_GIT_REF":         req.Ref,
		"AGOLA_GIT_COMMITSHA":   req.CommitSHA,
	}

	if req.SSHHostKey != "" {
		env["AGOLA_SSHHOSTKEY"] = req.SSHHostKey
	}
	if req.SkipSSHHostKeyCheck {
		env["AGOLA_SKIPSSHHOSTKEYCHECK"] = "1"
	}

	var variables map[string]string
	if req.RunType == itypes.RunTypeProject {
		if req.RefType != itypes.RunRefTypePullRequest || req.PRFromSameRepo || req.Project.PassVarsToForkedPR {
			var err error
			variables, err = h.genRunVariables(ctx, req)
			if err != nil {
				return errors.WithStack(err)
			}
		}
	} else {
		variables = req.Variables
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

	if req.RunType == itypes.RunTypeProject {
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

	// Since user belong to the same group (the user uuid) we needed another way to differentiate the cache. We'll use the user uuid + the user run repo uuid
	var cacheGroup string
	if req.RunType == itypes.RunTypeUser {
		cacheGroup = req.User.ID + "-" + req.UserRunRepoUUID
	}

	data, filename, err := h.fetchConfigFiles(ctx, req.GitSource, req.RepoPath, req.CommitSHA)
	if err != nil {
		return util.NewAPIError(util.ErrInternal, errors.Wrapf(err, "failed to fetch config file"))
	}
	h.log.Debug().Msgf("data: %s", data)

	var configFormat config.ConfigFormat
	switch path.Ext(filename) {
	case ".star":
		configFormat = config.ConfigFormatStarlark
	case ".jsonnet":
		configFormat = config.ConfigFormatJsonnet
	case ".json":
		fallthrough
	case ".yml":
		configFormat = config.ConfigFormatJSON

	}

	configContext := &config.ConfigContext{
		RefType:       req.RefType,
		Ref:           req.Ref,
		Branch:        req.Branch,
		Tag:           req.Tag,
		PullRequestID: req.PullRequestID,
		CommitSHA:     req.CommitSHA,
	}

	config, err := config.ParseConfig([]byte(data), configFormat, configContext)
	if err != nil {
		h.log.Err(err).Msgf("failed to parse config")

		// create a run (per config file) with a generic error since we cannot parse
		// it and know how many runs are defined
		setupErrors = append(setupErrors, err.Error())
		createRunReq := &rsapitypes.RunCreateRequest{
			RunConfigTasks:    nil,
			Group:             runGroup,
			SetupErrors:       setupErrors,
			Name:              rstypes.RunGenericSetupErrorName,
			StaticEnvironment: env,
			Annotations:       annotations,
		}

		if _, _, err := h.runserviceClient.CreateRun(ctx, createRunReq); err != nil {
			h.log.Err(err).Msgf("failed to create run")
			return util.NewAPIError(util.KindFromRemoteError(err), err)
		}
		return nil
	}

	for _, run := range config.Runs {
		if SkipRunMessage.MatchString(req.Message) {
			h.log.Debug().Msgf("skipping run since special commit message")
			continue
		}

		if match := types.MatchWhen(run.When.ToWhen(), req.RefType, req.Branch, req.Tag, req.Ref); !match {
			h.log.Debug().Msgf("skipping run since when condition doesn't match")
			continue
		}

		rcts := runconfig.GenRunConfigTasks(util.DefaultUUIDGenerator{}, config, run.Name, variables, req.RefType, req.Branch, req.Tag, req.Ref)

		createRunReq := &rsapitypes.RunCreateRequest{
			RunConfigTasks:    rcts,
			Group:             runGroup,
			SetupErrors:       setupErrors,
			Name:              run.Name,
			StaticEnvironment: env,
			Annotations:       annotations,
			CacheGroup:        cacheGroup,
		}

		if _, _, err := h.runserviceClient.CreateRun(ctx, createRunReq); err != nil {
			h.log.Err(err).Msgf("failed to create run")
			return util.NewAPIError(util.KindFromRemoteError(err), err)
		}
	}

	return nil
}

func (h *ActionHandler) fetchConfigFiles(ctx context.Context, gitSource gitsource.GitSource, repopath, commitSHA string) ([]byte, string, error) {
	var data []byte
	var filename string
	err := util.ExponentialBackoff(ctx, util.FetchFileBackoff, func() (bool, error) {
		for _, filename = range []string{agolaDefaultStarlarkConfigFile, agolaDefaultJsonnetConfigFile, agolaDefaultJsonConfigFile, agolaDefaultYamlConfigFile} {
			var err error
			data, err = gitSource.GetFile(repopath, commitSHA, path.Join(agolaDefaultConfigDir, filename))
			if err == nil {
				return true, nil
			}
			h.log.Err(err).Msgf("get file err")
		}
		return false, nil
	})
	if err != nil {
		return nil, "", errors.WithStack(err)
	}
	return data, filename, nil
}

func (h *ActionHandler) genRunVariables(ctx context.Context, req *CreateRunRequest) (map[string]string, error) {
	variables := map[string]string{}

	// get project variables
	pvars, _, err := h.configstoreClient.GetProjectVariables(ctx, req.Project.ID, true)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get project variables")
	}

	// remove overriden variables
	pvars = scommon.FilterOverriddenVariables(pvars)

	// get project secrets
	secrets, _, err := h.configstoreClient.GetProjectSecrets(ctx, req.Project.ID, true)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get project secrets")
	}
	for _, pvar := range pvars {
		// find the value match
		var varval cstypes.VariableValue
		for _, varval = range pvar.Values {
			match := types.MatchWhen(varval.When, req.RefType, req.Branch, req.Tag, req.Ref)
			if !match {
				continue
			}
			// get the secret value referenced by the variable, it must be a secret at the same level or a lower level
			secret := scommon.GetVarValueMatchingSecret(varval, pvar.ParentPath, secrets)
			if secret != nil {
				varValue, ok := secret.Data[varval.SecretVar]
				if ok {
					variables[pvar.Name] = varValue
				}
			}
			break
		}
	}

	return variables, nil
}
