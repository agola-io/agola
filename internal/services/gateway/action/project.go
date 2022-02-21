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
	"fmt"
	"net/url"
	"path"

	gitsource "agola.io/agola/internal/gitsources"
	"agola.io/agola/internal/services/gateway/common"
	"agola.io/agola/internal/services/types"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	cstypes "agola.io/agola/services/configstore/types"

	errors "golang.org/x/xerrors"
)

func (h *ActionHandler) GetProject(ctx context.Context, projectRef string) (*csapitypes.Project, error) {
	project, _, err := h.configstoreClient.GetProject(ctx, projectRef)
	if err != nil {
		return nil, err
	}

	isProjectMember, err := h.IsProjectMember(ctx, project.OwnerType, project.OwnerID)
	if err != nil {
		return nil, errors.Errorf("failed to determine ownership: %w", err)
	}
	if project.GlobalVisibility == cstypes.VisibilityPublic {
		return project, nil
	}
	if !isProjectMember {
		return nil, util.NewAPIError(util.ErrForbidden, errors.Errorf("user not authorized"))
	}

	return project, nil
}

type CreateProjectRequest struct {
	Name                string
	ParentRef           string
	Visibility          cstypes.Visibility
	RemoteSourceName    string
	RepoPath            string
	SkipSSHHostKeyCheck bool
	PassVarsToForkedPR  bool
}

func (h *ActionHandler) CreateProject(ctx context.Context, req *CreateProjectRequest) (*csapitypes.Project, error) {
	curUserID := common.CurrentUserID(ctx)

	user, _, err := h.configstoreClient.GetUser(ctx, curUserID)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to get user %q: %w", curUserID, err))
	}
	parentRef := req.ParentRef
	if parentRef == "" {
		// create project in current user namespace
		parentRef = path.Join("user", user.Name)
	}

	pg, _, err := h.configstoreClient.GetProjectGroup(ctx, parentRef)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to get project group %q: %w", parentRef, err))
	}

	isProjectOwner, err := h.IsProjectOwner(ctx, pg.OwnerType, pg.OwnerID)
	if err != nil {
		return nil, errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isProjectOwner {
		return nil, util.NewAPIError(util.ErrForbidden, errors.Errorf("user not authorized"))
	}

	if !util.ValidateName(req.Name) {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid project name %q", req.Name))
	}
	if req.RemoteSourceName == "" {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("empty remote source name"))
	}
	if req.RepoPath == "" {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("empty remote repo path"))
	}

	projectPath := path.Join(pg.Path, req.Name)
	if _, _, err = h.configstoreClient.GetProject(ctx, projectPath); err != nil {
		if !util.RemoteErrorIs(err, util.ErrNotExist) {
			return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to get project %q: %w", req.Name, err))
		}
	} else {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("project %q already exists", projectPath))
	}

	rs, _, err := h.configstoreClient.GetRemoteSource(ctx, req.RemoteSourceName)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to get remote source %q: %w", req.RemoteSourceName, err))
	}
	var la *cstypes.LinkedAccount
	for _, v := range user.LinkedAccounts {
		if v.RemoteSourceID == rs.ID {
			la = v
			break
		}
	}
	if la == nil {
		return nil, errors.Errorf("user doesn't have a linked account for remote source %q", rs.Name)
	}

	gitSource, err := h.GetGitSource(ctx, rs, user.Name, la)
	if err != nil {
		return nil, errors.Errorf("failed to create gitsource client: %w", err)
	}

	repo, err := gitSource.GetRepoInfo(req.RepoPath)
	if err != nil {
		return nil, errors.Errorf("failed to get repository info from gitsource: %w", err)
	}

	h.log.Info().Msgf("generating ssh key pairs")
	privateKey, _, err := util.GenSSHKeyPair(4096)
	if err != nil {
		return nil, errors.Errorf("failed to generate ssh key pair: %w", err)
	}

	p := &cstypes.Project{
		Name: req.Name,
		Parent: cstypes.Parent{
			Type: cstypes.ConfigTypeProjectGroup,
			ID:   parentRef,
		},
		Visibility:                 req.Visibility,
		RemoteRepositoryConfigType: cstypes.RemoteRepositoryConfigTypeRemoteSource,
		RemoteSourceID:             rs.ID,
		LinkedAccountID:            la.ID,
		RepositoryID:               repo.ID,
		RepositoryPath:             req.RepoPath,
		SkipSSHHostKeyCheck:        req.SkipSSHHostKeyCheck,
		SSHPrivateKey:              string(privateKey),
		PassVarsToForkedPR:         req.PassVarsToForkedPR,
	}

	h.log.Info().Msgf("creating project")
	rp, _, err := h.configstoreClient.CreateProject(ctx, p)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to create project: %w", err))
	}
	h.log.Info().Msgf("project %s created, ID: %s", rp.Name, rp.ID)

	if serr := h.setupGitSourceRepo(ctx, rs, user, la, rp); serr != nil {
		var err error
		h.log.Err(err).Msgf("failed to setup git source repo, trying to cleanup")
		// try to cleanup gitsource configs and remove project
		// we'll log but ignore errors
		h.log.Info().Msgf("deleting project with ID: %q", rp.ID)
		if _, err := h.configstoreClient.DeleteProject(ctx, rp.ID); err != nil {
			h.log.Err(err).Msgf("failed to delete project ")
		}
		h.log.Info().Msgf("cleanup git source repo")
		if err := h.cleanupGitSourceRepo(ctx, rs, user, la, rp); err != nil {
			h.log.Err(err).Msgf("failed to cleanup git source repo")
		}
		return nil, errors.Errorf("failed to setup git source repo: %w", serr)
	}

	return rp, nil
}

type UpdateProjectRequest struct {
	Name      *string
	ParentRef *string

	Visibility         *cstypes.Visibility
	PassVarsToForkedPR *bool
}

func (h *ActionHandler) UpdateProject(ctx context.Context, projectRef string, req *UpdateProjectRequest) (*csapitypes.Project, error) {
	p, _, err := h.configstoreClient.GetProject(ctx, projectRef)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to get project %q: %w", projectRef, err))
	}

	isProjectOwner, err := h.IsProjectOwner(ctx, p.OwnerType, p.OwnerID)
	if err != nil {
		return nil, errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isProjectOwner {
		return nil, util.NewAPIError(util.ErrForbidden, errors.Errorf("user not authorized"))
	}

	if req.Name != nil {
		p.Name = *req.Name
	}
	if req.ParentRef != nil {
		p.Parent.ID = *req.ParentRef
	}
	if req.Visibility != nil {
		p.Visibility = *req.Visibility
	}
	if req.PassVarsToForkedPR != nil {
		p.PassVarsToForkedPR = *req.PassVarsToForkedPR
	}

	h.log.Info().Msgf("updating project")
	rp, _, err := h.configstoreClient.UpdateProject(ctx, p.ID, p.Project)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to update project: %w", err))
	}
	h.log.Info().Msgf("project %s updated, ID: %s", p.Name, p.ID)

	return rp, nil
}

func (h *ActionHandler) ProjectUpdateRepoLinkedAccount(ctx context.Context, projectRef string) (*csapitypes.Project, error) {
	curUserID := common.CurrentUserID(ctx)

	user, _, err := h.configstoreClient.GetUser(ctx, curUserID)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to get user %q: %w", curUserID, err))
	}

	p, _, err := h.configstoreClient.GetProject(ctx, projectRef)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to get project %q: %w", projectRef, err))
	}

	isProjectOwner, err := h.IsProjectOwner(ctx, p.OwnerType, p.OwnerID)
	if err != nil {
		return nil, errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isProjectOwner {
		return nil, util.NewAPIError(util.ErrForbidden, errors.Errorf("user not authorized"))
	}

	rs, _, err := h.configstoreClient.GetRemoteSource(ctx, p.RemoteSourceID)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to get remote source %q: %w", p.RemoteSourceID, err))
	}
	var la *cstypes.LinkedAccount
	for _, v := range user.LinkedAccounts {
		if v.RemoteSourceID == rs.ID {
			la = v
			break
		}
	}
	if la == nil {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("user doesn't have a linked account for remote source %q", rs.Name))
	}

	gitsource, err := h.GetGitSource(ctx, rs, user.Name, la)
	if err != nil {
		return nil, errors.Errorf("failed to create gitsource client: %w", err)
	}

	// check user has access to the repository
	_, err = gitsource.GetRepoInfo(p.RepositoryPath)
	if err != nil {
		return nil, errors.Errorf("failed to get repository info from gitsource: %w", err)
	}

	p.LinkedAccountID = la.ID

	h.log.Info().Msgf("updating project")
	rp, _, err := h.configstoreClient.UpdateProject(ctx, p.ID, p.Project)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to update project: %w", err))
	}
	h.log.Info().Msgf("project %s updated, ID: %s", p.Name, p.ID)

	return rp, nil
}

func (h *ActionHandler) setupGitSourceRepo(ctx context.Context, rs *cstypes.RemoteSource, user *cstypes.User, la *cstypes.LinkedAccount, project *csapitypes.Project) error {
	gitsource, err := h.GetGitSource(ctx, rs, user.Name, la)
	if err != nil {
		return errors.Errorf("failed to create gitsource client: %w", err)
	}

	pubKey, err := util.ExtractPublicKey([]byte(project.SSHPrivateKey))
	if err != nil {
		return errors.Errorf("failed to extract public key: %w", err)
	}

	webhookURL, err := h.genWebhookURL(project)
	if err != nil {
		return errors.Errorf("failed to generate webhook url: %w", err)
	}

	// generate deploy keys and webhooks containing the agola project id so we
	// can have multiple projects referencing the same remote repository and this
	// will trigger multiple different runs
	deployKeyName := fmt.Sprintf("agola deploy key - %s", project.ID)
	h.log.Info().Msgf("creating/updating deploy key: %s", deployKeyName)
	if err := gitsource.UpdateDeployKey(project.RepositoryPath, deployKeyName, string(pubKey), true); err != nil {
		return errors.Errorf("failed to create deploy key: %w", err)
	}
	h.log.Info().Msgf("deleting existing webhooks")
	if err := gitsource.DeleteRepoWebhook(project.RepositoryPath, webhookURL); err != nil {
		return errors.Errorf("failed to delete repository webhook: %w", err)
	}
	h.log.Info().Msgf("creating webhook to url: %s", webhookURL)
	if err := gitsource.CreateRepoWebhook(project.RepositoryPath, webhookURL, project.WebhookSecret); err != nil {
		return errors.Errorf("failed to create repository webhook: %w", err)
	}

	return nil
}

func (h *ActionHandler) cleanupGitSourceRepo(ctx context.Context, rs *cstypes.RemoteSource, user *cstypes.User, la *cstypes.LinkedAccount, project *csapitypes.Project) error {
	gitsource, err := h.GetGitSource(ctx, rs, user.Name, la)
	if err != nil {
		return errors.Errorf("failed to create gitsource client: %w", err)
	}

	webhookURL, err := h.genWebhookURL(project)
	if err != nil {
		return errors.Errorf("failed to generate webhook url: %w", err)
	}

	// generate deploy keys and webhooks containing the agola project id so we
	// can have multiple projects referencing the same remote repository and this
	// will trigger multiple different runs
	deployKeyName := fmt.Sprintf("agola deploy key - %s", project.ID)
	h.log.Info().Msgf("deleting deploy key: %s", deployKeyName)
	if err := gitsource.DeleteDeployKey(project.RepositoryPath, deployKeyName); err != nil {
		return errors.Errorf("failed to create deploy key: %w", err)
	}
	h.log.Info().Msgf("deleting existing webhooks")
	if err := gitsource.DeleteRepoWebhook(project.RepositoryPath, webhookURL); err != nil {
		return errors.Errorf("failed to delete repository webhook: %w", err)
	}

	return nil
}

func (h *ActionHandler) genWebhookURL(project *csapitypes.Project) (string, error) {
	baseWebhookURL := fmt.Sprintf("%s/webhooks", h.apiExposedURL)
	webhookURL, err := url.Parse(baseWebhookURL)
	if err != nil {
		return "", errors.Errorf("failed to parse base webhook url %q: %w", baseWebhookURL, err)
	}
	q := url.Values{}
	q.Add("projectid", project.ID)
	q.Add("agolaid", h.agolaID)
	webhookURL.RawQuery = q.Encode()

	return webhookURL.String(), nil
}

func (h *ActionHandler) ReconfigProject(ctx context.Context, projectRef string) error {
	p, _, err := h.configstoreClient.GetProject(ctx, projectRef)
	if err != nil {
		return util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to get project %q: %w", projectRef, err))
	}

	isProjectOwner, err := h.IsProjectOwner(ctx, p.OwnerType, p.OwnerID)
	if err != nil {
		return errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isProjectOwner {
		return util.NewAPIError(util.ErrForbidden, errors.Errorf("user not authorized"))
	}

	user, rs, la, err := h.getRemoteRepoAccessData(ctx, p.LinkedAccountID)
	if err != nil {
		return errors.Errorf("failed to get remote repo access data: %w", err)
	}

	// TODO(sgotti) update project repo path if the remote let us query by repository id

	return h.setupGitSourceRepo(ctx, rs, user, la, p)
}

func (h *ActionHandler) DeleteProject(ctx context.Context, projectRef string) error {
	p, _, err := h.configstoreClient.GetProject(ctx, projectRef)
	if err != nil {
		return util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to get project %q: %w", projectRef, err))
	}

	isProjectOwner, err := h.IsProjectOwner(ctx, p.OwnerType, p.OwnerID)
	if err != nil {
		return errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isProjectOwner {
		return util.NewAPIError(util.ErrForbidden, errors.Errorf("user not authorized"))
	}

	// get data needed for repo cleanup
	// we'll log but ignore errors
	canDoRepCleanup := true
	user, rs, la, err := h.getRemoteRepoAccessData(ctx, p.LinkedAccountID)
	if err != nil {
		canDoRepCleanup = false
		h.log.Err(err).Msgf("failed to get remote repo access data: %+v", err)
	}

	h.log.Info().Msgf("deleting project with ID: %q", p.ID)
	if _, err = h.configstoreClient.DeleteProject(ctx, projectRef); err != nil {
		return util.NewAPIError(util.KindFromRemoteError(err), err)
	}

	// try to cleanup gitsource configs
	// we'll log but ignore errors
	if canDoRepCleanup {
		h.log.Info().Msgf("cleanup git source repo")
		if err := h.cleanupGitSourceRepo(ctx, rs, user, la, p); err != nil {
			h.log.Err(err).Msgf("failed to cleanup git source repo: %+v", err)
		}
	}

	return nil
}

func (h *ActionHandler) ProjectCreateRun(ctx context.Context, projectRef, branch, tag, refName, commitSHA string) error {
	curUserID := common.CurrentUserID(ctx)

	user, _, err := h.configstoreClient.GetUser(ctx, curUserID)
	if err != nil {
		return util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to get user %q: %w", curUserID, err))
	}

	p, _, err := h.configstoreClient.GetProject(ctx, projectRef)
	if err != nil {
		return util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to get project %q: %w", projectRef, err))
	}

	isProjectOwner, err := h.IsProjectOwner(ctx, p.OwnerType, p.OwnerID)
	if err != nil {
		return errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isProjectOwner {
		return util.NewAPIError(util.ErrForbidden, errors.Errorf("user not authorized"))
	}

	rs, _, err := h.configstoreClient.GetRemoteSource(ctx, p.RemoteSourceID)
	if err != nil {
		return util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to get remote source %q: %w", p.RemoteSourceID, err))
	}
	var la *cstypes.LinkedAccount
	for _, v := range user.LinkedAccounts {
		if v.RemoteSourceID == rs.ID {
			la = v
			break
		}
	}
	if la == nil {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("user doesn't have a linked account for remote source %q", rs.Name))
	}

	gitSource, err := h.GetGitSource(ctx, rs, user.Name, la)
	if err != nil {
		return errors.Errorf("failed to create gitsource client: %w", err)
	}

	// check user has access to the repository
	repoInfo, err := gitSource.GetRepoInfo(p.RepositoryPath)
	if err != nil {
		return errors.Errorf("failed to get repository info from gitsource: %w", err)
	}

	set := 0
	if branch != "" {
		set++
	}
	if tag != "" {
		set++
	}
	if refName != "" {
		set++
	}
	if set == 0 {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("one of branch, tag or ref is required"))
	}
	if set > 1 {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("only one of branch, tag or ref can be provided"))
	}

	var refType types.RunRefType
	var message string
	var branchLink, tagLink string

	var refCommitSHA string
	if refName == "" {
		if branch != "" {
			refName = gitSource.BranchRef(branch)
		}
		if tag != "" {
			refName = gitSource.TagRef(tag)
		}
	}

	gitRefType, name, err := gitSource.RefType(refName)
	if err != nil {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("failed to get refType for ref %q: %w", refName, err))
	}
	ref, err := gitSource.GetRef(p.RepositoryPath, refName)
	if err != nil {
		return errors.Errorf("failed to get ref information from git source for ref %q: %w", refName, err)
	}
	refCommitSHA = ref.CommitSHA
	switch gitRefType {
	case gitsource.RefTypeBranch:
		branch = name
	case gitsource.RefTypeTag:
		tag = name
		// TODO(sgotti) implement manual run creation on a pull request if really needed
	default:
		return errors.Errorf("unsupported ref %q for manual run creation", refName)
	}

	// TODO(sgotti) check that the provided ref contains the provided commitSHA

	// if no commitSHA has been provided use the ref commit sha
	if commitSHA == "" && refCommitSHA != "" {
		commitSHA = refCommitSHA
	}

	commit, err := gitSource.GetCommit(p.RepositoryPath, commitSHA)
	if err != nil {
		return errors.Errorf("failed to get commit information from git source for commit sha %q: %w", commitSHA, err)
	}

	// use the commit full sha since the user could have provided a short commit sha
	commitSHA = commit.SHA

	if branch != "" {
		refType = types.RunRefTypeBranch
		message = commit.Message
		branchLink = gitSource.BranchLink(repoInfo, branch)
	}

	if tag != "" {
		refType = types.RunRefTypeTag
		message = fmt.Sprintf("Tag %s", tag)
		tagLink = gitSource.TagLink(repoInfo, tag)
	}

	// use remotesource skipSSHHostKeyCheck config and override with project config if set to true there
	skipSSHHostKeyCheck := rs.SkipSSHHostKeyCheck
	if p.SkipSSHHostKeyCheck {
		skipSSHHostKeyCheck = p.SkipSSHHostKeyCheck
	}

	req := &CreateRunRequest{
		RunType:            types.RunTypeProject,
		RefType:            refType,
		RunCreationTrigger: types.RunCreationTriggerTypeManual,

		Project:             p.Project,
		RepoPath:            p.RepositoryPath,
		GitSource:           gitSource,
		CommitSHA:           commitSHA,
		Message:             message,
		Branch:              branch,
		Tag:                 tag,
		PullRequestID:       "",
		Ref:                 refName,
		SSHPrivKey:          p.SSHPrivateKey,
		SSHHostKey:          rs.SSHHostKey,
		SkipSSHHostKeyCheck: skipSSHHostKeyCheck,
		CloneURL:            repoInfo.SSHCloneURL,

		CommitLink:      gitSource.CommitLink(repoInfo, commitSHA),
		BranchLink:      branchLink,
		TagLink:         tagLink,
		PullRequestLink: "",
	}

	return h.CreateRuns(ctx, req)
}

func (h *ActionHandler) getRemoteRepoAccessData(ctx context.Context, linkedAccountID string) (*cstypes.User, *cstypes.RemoteSource, *cstypes.LinkedAccount, error) {
	user, _, err := h.configstoreClient.GetUserByLinkedAccount(ctx, linkedAccountID)
	if err != nil {
		return nil, nil, nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to get user with linked account id %q: %w", linkedAccountID, err))
	}

	la := user.LinkedAccounts[linkedAccountID]
	if la == nil {
		return nil, nil, nil, errors.Errorf("linked account %q in user %q doesn't exist", linkedAccountID, user.Name)
	}

	rs, _, err := h.configstoreClient.GetRemoteSource(ctx, la.RemoteSourceID)
	if err != nil {
		return nil, nil, nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Errorf("failed to get remote source %q: %w", la.RemoteSourceID, err))
	}

	return user, rs, la, nil
}
