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

package gitea

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strconv"

	gitsource "github.com/sorintlab/agola/internal/gitsources"

	"code.gitea.io/sdk/gitea"
	"github.com/pkg/errors"
)

const (
	// TODO(sgotti) The gitea client doesn't provide an easy way to detect http response codes...
	// we should probably use our own client implementation

	ClientNotFound = "404 Not Found"
)

type Opts struct {
	URL        string
	Token      string
	SkipVerify bool
}

type Client struct {
	client *gitea.Client
}

// fromCommitStatus converts a gitsource commit status to a gitea commit status
func fromCommitStatus(status gitsource.CommitStatus) gitea.StatusState {
	switch status {
	case gitsource.CommitStatusPending:
		return gitea.StatusPending
	case gitsource.CommitStatusSuccess:
		return gitea.StatusSuccess
	case gitsource.CommitStatusFailed:
		return gitea.StatusFailure
	default:
		return gitea.StatusError
	}
}

func New(opts Opts) (*Client, error) {
	client := gitea.NewClient(opts.URL, opts.Token)
	if opts.SkipVerify {
		httpClient := &http.Client{}
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.SetHTTPClient(httpClient)
	}
	return &Client{
		client: client,
	}, nil
}

func (c *Client) LoginPassword(username, password string) (string, error) {
	// try to get agola access token if it already exists
	var accessToken string
	tokens, err := c.client.ListAccessTokens(username, password)
	if err == nil {
		for _, token := range tokens {
			if token.Name == "agola" {
				accessToken = token.Sha1
				break
			}
		}
	}

	// create access token
	if accessToken == "" {
		token, terr := c.client.CreateAccessToken(
			username,
			password,
			gitea.CreateAccessTokenOption{Name: "agola"},
		)
		if terr != nil {
			return "", terr
		}
		accessToken = token.Sha1
	}

	return accessToken, nil
}

func (c *Client) GetUserInfo() (*gitsource.UserInfo, error) {
	user, err := c.client.GetMyUserInfo()
	if err != nil {
		return nil, err
	}
	return &gitsource.UserInfo{
		ID:        strconv.FormatInt(user.ID, 10),
		LoginName: user.UserName,
		Email:     user.Email,
	}, nil
}

func (c *Client) GetRepoInfo(owner, reponame string) (*gitsource.RepoInfo, error) {
	repo, err := c.client.GetRepo(owner, reponame)
	if err != nil {
		return nil, err
	}
	return &gitsource.RepoInfo{
		ID:           strconv.FormatInt(repo.ID, 10),
		SSHCloneURL:  repo.SSHURL,
		HTTPCloneURL: repo.CloneURL,
	}, nil
}

func (c *Client) GetFile(owner, repo, commit, file string) ([]byte, error) {
	data, err := c.client.GetFile(owner, repo, commit, file)
	return data, err
}

func (c *Client) CreateDeployKey(owner, repo, title, pubKey string, readonly bool) error {
	_, err := c.client.CreateDeployKey(owner, repo, gitea.CreateKeyOption{
		Title:    title,
		Key:      pubKey,
		ReadOnly: readonly,
	})

	return errors.Wrapf(err, "error creating deploy key")
}

func (c *Client) UpdateDeployKey(owner, repo, title, pubKey string, readonly bool) error {
	// NOTE(sgotti) gitea has a bug where if we delete and remove the same key with
	// the same value it is correctly readded and the admin must force a
	// authorized_keys regeneration on the server. To avoid this we update it only
	// when the public key value has changed
	keys, err := c.client.ListDeployKeys(owner, repo)
	if err != nil {
		return errors.Wrapf(err, "error retrieving existing deploy keys")
	}

	for _, key := range keys {
		if key.Title == title {
			if key.Key == pubKey {
				return nil
			}
			if err := c.client.DeleteDeployKey(owner, repo, key.ID); err != nil {
				return errors.Wrapf(err, "error removing existing deploy key")
			}
		}
	}

	if _, err := c.client.CreateDeployKey(owner, repo, gitea.CreateKeyOption{
		Title:    title,
		Key:      pubKey,
		ReadOnly: readonly,
	}); err != nil {
		return errors.Wrapf(err, "error creating deploy key")
	}

	return nil
}

func (c *Client) DeleteDeployKey(owner, repo, title string) error {
	keys, err := c.client.ListDeployKeys(owner, repo)
	if err != nil {
		return errors.Wrapf(err, "error retrieving existing deploy keys")
	}

	for _, key := range keys {
		if key.Title == title {
			if err := c.client.DeleteDeployKey(owner, repo, key.ID); err != nil {
				return errors.Wrapf(err, "error removing existing deploy key")
			}
		}
	}

	return nil
}

func (c *Client) CreateRepoWebhook(owner, repo, url, secret string) error {
	opts := gitea.CreateHookOption{
		Type: "gitea",
		Config: map[string]string{
			"url":          url,
			"content_type": "json",
			"secret":       secret,
		},
		Events: []string{"push", "pull_request"},
		Active: true,
	}
	_, err := c.client.CreateRepoHook(owner, repo, opts)

	return errors.Wrapf(err, "error creating repository webhook")
}

func (c *Client) DeleteRepoWebhook(owner, repo, u string) error {
	hooks, err := c.client.ListRepoHooks(owner, repo)
	if err != nil {
		return errors.Wrapf(err, "error retrieving repository webhooks")
	}

	// match the full url so we can have multiple webhooks for different agola
	// projects
	for _, hook := range hooks {
		if hook.Config["url"] == u {
			if err := c.client.DeleteRepoHook(owner, repo, hook.ID); err != nil {
				return errors.Wrapf(err, "error deleting existing repository webhook")
			}
		}
	}

	return nil
}

// helper function to return matching hooks.
func matchingHooks(hooks []*gitea.Hook, rawurl string) *gitea.Hook {
	link, err := url.Parse(rawurl)
	if err != nil {
		return nil
	}
	for _, hook := range hooks {
		if val, ok := hook.Config["url"]; ok {
			hookurl, err := url.Parse(val)
			if err == nil && hookurl.Host == link.Host {
				return hook
			}
		}
	}
	return nil
}
