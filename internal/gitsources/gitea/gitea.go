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

package gitea

import (
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

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

func parseRepoPath(repopath string) (string, string, error) {
	parts := strings.Split(repopath, "/")
	if len(parts) != 2 {
		return "", "", errors.Errorf("wrong gitea repo path: %q", repopath)
	}
	return parts[0], parts[1], nil
}

func New(opts Opts) (*Client, error) {
	// copied from net/http until it has a clone function: https://github.com/golang/go/issues/26013
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: opts.SkipVerify},
	}
	httpClient := &http.Client{Transport: transport}

	client := gitea.NewClient(opts.URL, opts.Token)
	client.SetHTTPClient(httpClient)

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

func (c *Client) GetRepoInfo(repopath string) (*gitsource.RepoInfo, error) {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return nil, err
	}
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

func (c *Client) GetFile(repopath, commit, file string) ([]byte, error) {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return nil, err
	}
	data, err := c.client.GetFile(owner, reponame, commit, file)
	return data, err
}

func (c *Client) CreateDeployKey(repopath, title, pubKey string, readonly bool) error {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return err
	}
	_, err = c.client.CreateDeployKey(owner, reponame, gitea.CreateKeyOption{
		Title:    title,
		Key:      pubKey,
		ReadOnly: readonly,
	})

	return errors.Wrapf(err, "error creating deploy key")
}

func (c *Client) UpdateDeployKey(repopath, title, pubKey string, readonly bool) error {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return err
	}
	// NOTE(sgotti) gitea has a bug where if we delete and remove the same key with
	// the same value it is correctly readded and the admin must force a
	// authorized_keys regeneration on the server. To avoid this we update it only
	// when the public key value has changed
	keys, err := c.client.ListDeployKeys(owner, reponame)
	if err != nil {
		return errors.Wrapf(err, "error retrieving existing deploy keys")
	}

	for _, key := range keys {
		if key.Title == title {
			if key.Key == pubKey {
				return nil
			}
			if err := c.client.DeleteDeployKey(owner, reponame, key.ID); err != nil {
				return errors.Wrapf(err, "error removing existing deploy key")
			}
		}
	}

	if _, err := c.client.CreateDeployKey(owner, reponame, gitea.CreateKeyOption{
		Title:    title,
		Key:      pubKey,
		ReadOnly: readonly,
	}); err != nil {
		return errors.Wrapf(err, "error creating deploy key")
	}

	return nil
}

func (c *Client) DeleteDeployKey(repopath, title string) error {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return err
	}
	keys, err := c.client.ListDeployKeys(owner, reponame)
	if err != nil {
		return errors.Wrapf(err, "error retrieving existing deploy keys")
	}

	for _, key := range keys {
		if key.Title == title {
			if err := c.client.DeleteDeployKey(owner, reponame, key.ID); err != nil {
				return errors.Wrapf(err, "error removing existing deploy key")
			}
		}
	}

	return nil
}

func (c *Client) CreateRepoWebhook(repopath, url, secret string) error {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return err
	}

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

	_, err = c.client.CreateRepoHook(owner, reponame, opts)

	return errors.Wrapf(err, "error creating repository webhook")
}

func (c *Client) DeleteRepoWebhook(repopath, u string) error {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return err
	}
	hooks, err := c.client.ListRepoHooks(owner, reponame)
	if err != nil {
		return errors.Wrapf(err, "error retrieving repository webhooks")
	}

	// match the full url so we can have multiple webhooks for different agola
	// projects
	for _, hook := range hooks {
		if hook.Config["url"] == u {
			if err := c.client.DeleteRepoHook(owner, reponame, hook.ID); err != nil {
				return errors.Wrapf(err, "error deleting existing repository webhook")
			}
		}
	}

	return nil
}
