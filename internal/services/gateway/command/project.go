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

package command

import (
	"context"
	"fmt"
	"net/url"
	"path"

	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/pkg/errors"
)

type CreateProjectRequest struct {
	CurrentUserID       string
	Name                string
	ParentID            string
	Visibility          types.Visibility
	RemoteSourceName    string
	RepoPath            string
	SkipSSHHostKeyCheck bool
}

func (c *CommandHandler) CreateProject(ctx context.Context, req *CreateProjectRequest) (*csapi.Project, error) {
	if !util.ValidateName(req.Name) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid project name %q", req.Name))
	}

	user, resp, err := c.configstoreClient.GetUser(ctx, req.CurrentUserID)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to get user %q", req.CurrentUserID))
	}

	rs, resp, err := c.configstoreClient.GetRemoteSourceByName(ctx, req.RemoteSourceName)
	if err != nil {
		c.log.Errorf("err: %+v", err)
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to get remote source %q", req.RemoteSourceName))
	}
	c.log.Infof("rs: %s", util.Dump(rs))
	var la *types.LinkedAccount
	for _, v := range user.LinkedAccounts {
		if v.RemoteSourceID == rs.ID {
			la = v
			break
		}
	}
	c.log.Infof("la: %s", util.Dump(la))
	if la == nil {
		return nil, errors.Errorf("user doesn't have a linked account for remote source %q", rs.Name)
	}

	gitsource, err := c.GetGitSource(ctx, rs, user.Name, la)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create gitsource client")
	}

	repo, err := gitsource.GetRepoInfo(req.RepoPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get repository info from gitsource")
	}

	c.log.Infof("generating ssh key pairs")
	privateKey, _, err := util.GenSSHKeyPair(4096)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to generate ssh key pair")
	}

	parentID := req.ParentID
	if parentID == "" {
		// create project in current user namespace
		parentID = path.Join("user", user.Name)
	}

	p := &types.Project{
		Name: req.Name,
		Parent: types.Parent{
			Type: types.ConfigTypeProjectGroup,
			ID:   parentID,
		},
		Visibility:          req.Visibility,
		LinkedAccountID:     la.ID,
		RepositoryID:        repo.ID,
		RepositoryPath:      req.RepoPath,
		SkipSSHHostKeyCheck: req.SkipSSHHostKeyCheck,
		SSHPrivateKey:       string(privateKey),
	}

	c.log.Infof("creating project")
	rp, resp, err := c.configstoreClient.CreateProject(ctx, p)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to create project"))
	}
	c.log.Infof("project %s created, ID: %s", p.Name, p.ID)

	return rp, c.SetupProject(ctx, rs, user, la, rp)
}

func (c *CommandHandler) SetupProject(ctx context.Context, rs *types.RemoteSource, user *types.User, la *types.LinkedAccount, project *csapi.Project) error {
	gitsource, err := c.GetGitSource(ctx, rs, user.Name, la)
	if err != nil {
		return errors.Wrapf(err, "failed to create gitsource client")
	}

	pubKey, err := util.ExtractPublicKey([]byte(project.SSHPrivateKey))
	if err != nil {
		return errors.Wrapf(err, "failed to extract public key")
	}

	webhookURL, err := url.Parse(fmt.Sprintf("%s/webhooks", c.apiExposedURL))
	if err != nil {
		return errors.Wrapf(err, "failed to generate webhook url")
	}
	q := url.Values{}
	q.Add("projectid", project.ID)
	q.Add("agolaid", c.agolaID)
	webhookURL.RawQuery = q.Encode()

	// generate deploy keys and webhooks containing the agola project id so we
	// can have multiple projects referencing the same remote repository and this
	// will trigger multiple different runs
	deployKeyName := fmt.Sprintf("agola deploy key - %s", project.ID)
	c.log.Infof("creating/updating deploy key: %s", string(pubKey))
	if err := gitsource.UpdateDeployKey(project.RepositoryPath, deployKeyName, string(pubKey), true); err != nil {
		return errors.Wrapf(err, "failed to create deploy key")
	}
	c.log.Infof("deleting existing webhooks")
	if err := gitsource.DeleteRepoWebhook(project.RepositoryPath, webhookURL.String()); err != nil {
		return errors.Wrapf(err, "failed to delete repository webhook")
	}
	c.log.Infof("creating webhook to url: %s", webhookURL)
	if err := gitsource.CreateRepoWebhook(project.RepositoryPath, webhookURL.String(), ""); err != nil {
		return errors.Wrapf(err, "failed to create repository webhook")
	}

	return nil
}

func (c *CommandHandler) ReconfigProject(ctx context.Context, projectRef string) error {
	p, resp, err := c.configstoreClient.GetProject(ctx, projectRef)
	if err != nil {
		return ErrFromRemote(resp, errors.Wrapf(err, "failed to get project %q", projectRef))
	}

	user, resp, err := c.configstoreClient.GetUserByLinkedAccount(ctx, p.LinkedAccountID)
	if err != nil {
		return ErrFromRemote(resp, errors.Wrapf(err, "failed to get user with linked account id %q", p.LinkedAccountID))
	}

	la := user.LinkedAccounts[p.LinkedAccountID]
	c.log.Infof("la: %s", util.Dump(la))
	if la == nil {
		return errors.Errorf("linked account %q in user %q doesn't exist", p.LinkedAccountID, user.Name)
	}

	rs, resp, err := c.configstoreClient.GetRemoteSource(ctx, la.RemoteSourceID)
	if err != nil {
		return ErrFromRemote(resp, errors.Wrapf(err, "failed to get remote source %q", la.RemoteSourceID))
	}

	// TODO(sgotti) update project repo path if the remote let us query by repository id

	return c.SetupProject(ctx, rs, user, la, p)
}
