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
	"strings"

	"github.com/sorintlab/agola/internal/services/gateway/common"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/pkg/errors"
)

type CreateProjectRequest struct {
	Name                string
	RemoteSourceName    string
	RepoURL             string
	UserID              string
	OwnerType           types.OwnerType
	OwnerID             string
	SkipSSHHostKeyCheck bool
}

func (c *CommandHandler) CreateProject(ctx context.Context, req *CreateProjectRequest) (*types.Project, error) {
	if !util.ValidateName(req.Name) {
		return nil, errors.Errorf("invalid project name %q", req.Name)
	}

	u, err := url.Parse(req.RepoURL)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse repo url")
	}

	repoOwner := strings.TrimPrefix(path.Dir(u.Path), "/")
	repoName := path.Base(u.Path)

	u.RawQuery = ""
	u.Path = ""
	host := u.Hostname()
	c.log.Infof("repoOwner: %s, repoName: %s", repoOwner, repoName)

	cloneURL := fmt.Sprintf("git@%s:%s/%s.git", host, repoOwner, repoName)
	c.log.Infof("cloneURL: %s", cloneURL)

	c.log.Infof("generating ssh key pairs")
	privateKey, _, err := util.GenSSHKeyPair(4096)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to generate ssh key pair")
	}

	user, _, err := c.configstoreClient.GetUser(ctx, req.UserID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user %q", req.UserID)
	}
	rs, _, err := c.configstoreClient.GetRemoteSourceByName(ctx, req.RemoteSourceName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get remote source %q", req.RemoteSourceName)
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

	p := &types.Project{
		Name:                req.Name,
		OwnerType:           types.OwnerTypeUser,
		OwnerID:             user.ID,
		LinkedAccountID:     la.ID,
		Path:                fmt.Sprintf("%s/%s", repoOwner, repoName),
		CloneURL:            cloneURL,
		SkipSSHHostKeyCheck: req.SkipSSHHostKeyCheck,
		SSHPrivateKey:       string(privateKey),
	}

	if req.OwnerType == types.OwnerTypeOrganization {
		if req.OwnerID == "" {
			return nil, errors.Errorf("ownerid must be specified when adding a project outside the current user")
		}
		p.OwnerType = req.OwnerType
		p.OwnerID = req.OwnerID
	}

	c.log.Infof("creating project")
	p, _, err = c.configstoreClient.CreateProject(ctx, p)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create project")
	}
	c.log.Infof("project %s created, ID: %s", p.Name, p.ID)

	return p, c.SetupProject(ctx, rs, la, &SetupProjectRequest{
		Project:   p,
		RepoOwner: repoOwner,
		RepoName:  repoName,
	})
}

type SetupProjectRequest struct {
	Project   *types.Project
	RepoOwner string
	RepoName  string
}

func (c *CommandHandler) SetupProject(ctx context.Context, rs *types.RemoteSource, la *types.LinkedAccount, conf *SetupProjectRequest) error {
	c.log.Infof("setupproject")

	gitsource, err := common.GetGitSource(rs, la)

	pubKey, err := util.ExtractPublicKey([]byte(conf.Project.SSHPrivateKey))
	if err != nil {
		return errors.Wrapf(err, "failed to create gitea client")
	}

	webhookURL := fmt.Sprintf("%s/webhooks?projectid=%s", c.apiExposedURL, conf.Project.ID)

	// generate deploy keys and webhooks containing the agola project id so we
	// can have multiple projects referencing the same remote repository and this
	// will trigger multiple different runs
	deployKeyName := fmt.Sprintf("agola deploy key - %s", conf.Project.ID)
	c.log.Infof("creating/updating deploy key: %s", string(pubKey))
	if err := gitsource.UpdateDeployKey(conf.RepoOwner, conf.RepoName, deployKeyName, string(pubKey), true); err != nil {
		return errors.Wrapf(err, "failed to create deploy key")
	}
	c.log.Infof("deleting existing webhooks")
	if err := gitsource.DeleteRepoWebhook(conf.RepoOwner, conf.RepoName, webhookURL); err != nil {
		return errors.Wrapf(err, "failed to delete repository webhook")
	}
	c.log.Infof("creating webhook to url: %s", webhookURL)
	if err := gitsource.CreateRepoWebhook(conf.RepoOwner, conf.RepoName, webhookURL, ""); err != nil {
		return errors.Wrapf(err, "failed to create repository webhook")
	}

	return nil
}

func (c *CommandHandler) ReconfigProject(ctx context.Context, ownerID, projectName string) error {
	p, _, err := c.configstoreClient.GetProjectByName(ctx, ownerID, projectName)
	if err != nil {
		return err
	}

	user, _, err := c.configstoreClient.GetUserByLinkedAccount(ctx, p.LinkedAccountID)
	if err != nil {
		return errors.Wrapf(err, "failed to get user with linked account id %q", p.LinkedAccountID)
	}

	la := user.LinkedAccounts[p.LinkedAccountID]
	c.log.Infof("la: %s", util.Dump(la))
	if la == nil {
		return errors.Errorf("linked account %q in user %q doesn't exist", p.LinkedAccountID, user.UserName)
	}

	rs, _, err := c.configstoreClient.GetRemoteSource(ctx, la.RemoteSourceID)
	if err != nil {
		return errors.Wrapf(err, "failed to get remote source %q", la.RemoteSourceID)
	}

	repoOwner := strings.TrimPrefix(path.Dir(p.Path), "/")
	repoName := path.Base(p.Path)

	return c.SetupProject(ctx, rs, la, &SetupProjectRequest{
		Project:   p,
		RepoOwner: repoOwner,
		RepoName:  repoName,
	})
}
