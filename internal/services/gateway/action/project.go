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

package action

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"

	gitsource "github.com/sorintlab/agola/internal/gitsources"
	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	errors "golang.org/x/xerrors"
)

func (h *ActionHandler) GetProject(ctx context.Context, projectRef string) (*csapi.Project, error) {
	project, resp, err := h.configstoreClient.GetProject(ctx, projectRef)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}

	isProjectMember, err := h.IsProjectMember(ctx, project.OwnerType, project.OwnerID)
	if err != nil {
		return nil, errors.Errorf("failed to determine ownership: %w", err)
	}
	if project.GlobalVisibility == types.VisibilityPublic {
		return project, nil
	}
	if !isProjectMember {
		return nil, util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	return project, nil
}

type CreateProjectRequest struct {
	Name                string
	ParentRef           string
	Visibility          types.Visibility
	RemoteSourceName    string
	RepoPath            string
	SkipSSHHostKeyCheck bool
}

func (h *ActionHandler) CreateProject(ctx context.Context, req *CreateProjectRequest) (*csapi.Project, error) {
	curUserID := h.CurrentUserID(ctx)

	user, resp, err := h.configstoreClient.GetUser(ctx, curUserID)
	if err != nil {
		return nil, errors.Errorf("failed to get user %q: %w", curUserID, ErrFromRemote(resp, err))
	}
	parentRef := req.ParentRef
	if parentRef == "" {
		// create project in current user namespace
		parentRef = path.Join("user", user.Name)
	}

	pg, resp, err := h.configstoreClient.GetProjectGroup(ctx, parentRef)
	if err != nil {
		return nil, errors.Errorf("failed to get project group %q: %w", parentRef, ErrFromRemote(resp, err))
	}

	isProjectOwner, err := h.IsProjectOwner(ctx, pg.OwnerType, pg.OwnerID)
	if err != nil {
		return nil, errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isProjectOwner {
		return nil, util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	if !util.ValidateName(req.Name) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid project name %q", req.Name))
	}
	if req.RemoteSourceName == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("empty remote source name"))
	}
	if req.RepoPath == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("empty remote repo path"))
	}

	projectPath := path.Join(pg.Path, req.Name)
	_, resp, err = h.configstoreClient.GetProject(ctx, projectPath)
	if err != nil {
		if resp != nil && resp.StatusCode != http.StatusNotFound {
			return nil, errors.Errorf("failed to get project %q: %w", req.Name, ErrFromRemote(resp, err))
		}
	} else {
		return nil, util.NewErrBadRequest(errors.Errorf("project %q already exists", projectPath))
	}

	rs, resp, err := h.configstoreClient.GetRemoteSource(ctx, req.RemoteSourceName)
	if err != nil {
		return nil, errors.Errorf("failed to get remote source %q: %w", req.RemoteSourceName, ErrFromRemote(resp, err))
	}
	h.log.Infof("rs: %s", util.Dump(rs))
	var la *types.LinkedAccount
	for _, v := range user.LinkedAccounts {
		if v.RemoteSourceID == rs.ID {
			la = v
			break
		}
	}
	h.log.Infof("la: %s", util.Dump(la))
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

	h.log.Infof("generating ssh key pairs")
	privateKey, _, err := util.GenSSHKeyPair(4096)
	if err != nil {
		return nil, errors.Errorf("failed to generate ssh key pair: %w", err)
	}

	p := &types.Project{
		Name: req.Name,
		Parent: types.Parent{
			Type: types.ConfigTypeProjectGroup,
			ID:   parentRef,
		},
		Visibility:                 req.Visibility,
		RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeRemoteSource,
		RemoteSourceID:             rs.ID,
		LinkedAccountID:            la.ID,
		RepositoryID:               repo.ID,
		RepositoryPath:             req.RepoPath,
		SkipSSHHostKeyCheck:        req.SkipSSHHostKeyCheck,
		SSHPrivateKey:              string(privateKey),
	}

	h.log.Infof("creating project")
	rp, resp, err := h.configstoreClient.CreateProject(ctx, p)
	if err != nil {
		return nil, errors.Errorf("failed to create project: %w", ErrFromRemote(resp, err))
	}
	h.log.Infof("project %s created, ID: %s", p.Name, p.ID)

	return rp, h.SetupProject(ctx, rs, user, la, rp)
}

type UpdateProjectRequest struct {
	Name       string
	Visibility types.Visibility
}

func (h *ActionHandler) UpdateProject(ctx context.Context, projectRef string, req *UpdateProjectRequest) (*csapi.Project, error) {
	p, resp, err := h.configstoreClient.GetProject(ctx, projectRef)
	if err != nil {
		return nil, errors.Errorf("failed to get project %q: %w", projectRef, ErrFromRemote(resp, err))
	}

	isProjectOwner, err := h.IsProjectOwner(ctx, p.OwnerType, p.OwnerID)
	if err != nil {
		return nil, errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isProjectOwner {
		return nil, util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	p.Name = req.Name
	p.Visibility = req.Visibility

	h.log.Infof("updating project")
	rp, resp, err := h.configstoreClient.UpdateProject(ctx, p.ID, p.Project)
	if err != nil {
		return nil, errors.Errorf("failed to update project: %w", ErrFromRemote(resp, err))
	}
	h.log.Infof("project %s updated, ID: %s", p.Name, p.ID)

	return rp, nil
}

func (h *ActionHandler) ProjectUpdateRepoLinkedAccount(ctx context.Context, projectRef string) (*csapi.Project, error) {
	curUserID := h.CurrentUserID(ctx)

	user, resp, err := h.configstoreClient.GetUser(ctx, curUserID)
	if err != nil {
		return nil, errors.Errorf("failed to get user %q: %w", curUserID, ErrFromRemote(resp, err))
	}

	p, resp, err := h.configstoreClient.GetProject(ctx, projectRef)
	if err != nil {
		return nil, errors.Errorf("failed to get project %q: %w", projectRef, ErrFromRemote(resp, err))
	}

	isProjectOwner, err := h.IsProjectOwner(ctx, p.OwnerType, p.OwnerID)
	if err != nil {
		return nil, errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isProjectOwner {
		return nil, util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	rs, resp, err := h.configstoreClient.GetRemoteSource(ctx, p.RemoteSourceID)
	if err != nil {
		return nil, errors.Errorf("failed to get remote source %q: %w", p.RemoteSourceID, ErrFromRemote(resp, err))
	}
	h.log.Infof("rs: %s", util.Dump(rs))
	var la *types.LinkedAccount
	for _, v := range user.LinkedAccounts {
		if v.RemoteSourceID == rs.ID {
			la = v
			break
		}
	}
	h.log.Infof("la: %s", util.Dump(la))
	if la == nil {
		return nil, util.NewErrBadRequest(errors.Errorf("user doesn't have a linked account for remote source %q", rs.Name))
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

	h.log.Infof("updating project")
	rp, resp, err := h.configstoreClient.UpdateProject(ctx, p.ID, p.Project)
	if err != nil {
		return nil, errors.Errorf("failed to update project: %w", ErrFromRemote(resp, err))
	}
	h.log.Infof("project %s updated, ID: %s", p.Name, p.ID)

	return rp, nil
}

func (h *ActionHandler) SetupProject(ctx context.Context, rs *types.RemoteSource, user *types.User, la *types.LinkedAccount, project *csapi.Project) error {
	gitsource, err := h.GetGitSource(ctx, rs, user.Name, la)
	if err != nil {
		return errors.Errorf("failed to create gitsource client: %w", err)
	}

	pubKey, err := util.ExtractPublicKey([]byte(project.SSHPrivateKey))
	if err != nil {
		return errors.Errorf("failed to extract public key: %w", err)
	}

	webhookURL, err := url.Parse(fmt.Sprintf("%s/webhooks", h.apiExposedURL))
	if err != nil {
		return errors.Errorf("failed to generate webhook url: %w", err)
	}
	q := url.Values{}
	q.Add("projectid", project.ID)
	q.Add("agolaid", h.agolaID)
	webhookURL.RawQuery = q.Encode()

	// generate deploy keys and webhooks containing the agola project id so we
	// can have multiple projects referencing the same remote repository and this
	// will trigger multiple different runs
	deployKeyName := fmt.Sprintf("agola deploy key - %s", project.ID)
	h.log.Infof("creating/updating deploy key: %s", string(pubKey))
	if err := gitsource.UpdateDeployKey(project.RepositoryPath, deployKeyName, string(pubKey), true); err != nil {
		return errors.Errorf("failed to create deploy key: %w", err)
	}
	h.log.Infof("deleting existing webhooks")
	if err := gitsource.DeleteRepoWebhook(project.RepositoryPath, webhookURL.String()); err != nil {
		return errors.Errorf("failed to delete repository webhook: %w", err)
	}
	h.log.Infof("creating webhook to url: %s", webhookURL)
	if err := gitsource.CreateRepoWebhook(project.RepositoryPath, webhookURL.String(), project.WebhookSecret); err != nil {
		return errors.Errorf("failed to create repository webhook: %w", err)
	}

	return nil
}

func (h *ActionHandler) ReconfigProject(ctx context.Context, projectRef string) error {
	p, resp, err := h.configstoreClient.GetProject(ctx, projectRef)
	if err != nil {
		return errors.Errorf("failed to get project %q: %w", projectRef, ErrFromRemote(resp, err))
	}

	isProjectOwner, err := h.IsProjectOwner(ctx, p.OwnerType, p.OwnerID)
	if err != nil {
		return errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isProjectOwner {
		return util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	user, resp, err := h.configstoreClient.GetUserByLinkedAccount(ctx, p.LinkedAccountID)
	if err != nil {
		return errors.Errorf("failed to get user with linked account id %q: %w", p.LinkedAccountID, ErrFromRemote(resp, err))
	}

	la := user.LinkedAccounts[p.LinkedAccountID]
	h.log.Infof("la: %s", util.Dump(la))
	if la == nil {
		return errors.Errorf("linked account %q in user %q doesn't exist", p.LinkedAccountID, user.Name)
	}

	rs, resp, err := h.configstoreClient.GetRemoteSource(ctx, la.RemoteSourceID)
	if err != nil {
		return errors.Errorf("failed to get remote source %q: %w", la.RemoteSourceID, ErrFromRemote(resp, err))
	}

	// TODO(sgotti) update project repo path if the remote let us query by repository id

	return h.SetupProject(ctx, rs, user, la, p)
}

func (h *ActionHandler) DeleteProject(ctx context.Context, projectRef string) error {
	p, resp, err := h.configstoreClient.GetProject(ctx, projectRef)
	if err != nil {
		return errors.Errorf("failed to get project %q: %w", projectRef, ErrFromRemote(resp, err))
	}

	isProjectOwner, err := h.IsProjectOwner(ctx, p.OwnerType, p.OwnerID)
	if err != nil {
		return errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isProjectOwner {
		return util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	resp, err = h.configstoreClient.DeleteProject(ctx, projectRef)
	if err != nil {
		return ErrFromRemote(resp, err)
	}
	return nil
}

func (h *ActionHandler) ProjectCreateRun(ctx context.Context, projectRef, branch, tag, refName, commitSHA string) error {
	curUserID := h.CurrentUserID(ctx)

	user, resp, err := h.configstoreClient.GetUser(ctx, curUserID)
	if err != nil {
		return errors.Errorf("failed to get user %q: %w", curUserID, ErrFromRemote(resp, err))
	}

	p, resp, err := h.configstoreClient.GetProject(ctx, projectRef)
	if err != nil {
		return errors.Errorf("failed to get project %q: %w", projectRef, ErrFromRemote(resp, err))
	}

	isProjectOwner, err := h.IsProjectOwner(ctx, p.OwnerType, p.OwnerID)
	if err != nil {
		return errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isProjectOwner {
		return util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	rs, resp, err := h.configstoreClient.GetRemoteSource(ctx, p.RemoteSourceID)
	if err != nil {
		return errors.Errorf("failed to get remote source %q: %w", p.RemoteSourceID, ErrFromRemote(resp, err))
	}
	h.log.Infof("rs: %s", util.Dump(rs))
	var la *types.LinkedAccount
	for _, v := range user.LinkedAccounts {
		if v.RemoteSourceID == rs.ID {
			la = v
			break
		}
	}
	h.log.Infof("la: %s", util.Dump(la))
	if la == nil {
		return util.NewErrBadRequest(errors.Errorf("user doesn't have a linked account for remote source %q", rs.Name))
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
		return util.NewErrBadRequest(errors.Errorf("one of branch, tag or ref is required"))
	}
	if set > 1 {
		return util.NewErrBadRequest(errors.Errorf("only one of branch, tag or ref can be provided"))
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
		return util.NewErrBadRequest(errors.Errorf("failed to get refType for ref %q: %w", refName, err))
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
		refType = types.RunRefTypeBranch
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
