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

package gitlab

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/pkg/errors"
	gitsource "github.com/sorintlab/agola/internal/gitsources"
	gitlab "github.com/xanzy/go-gitlab"
	"golang.org/x/oauth2"
)

const (
	// TODO(sgotti) The gitea client doesn't provide an easy way to detect http response codes...
	// we should probably use our own client implementation

	ClientNotFound = "404 Not Found"
)

var (
	GitlabOauth2Scopes = []string{"api"}
)

type Opts struct {
	URL            string
	Token          string
	SkipVerify     bool
	Oauth2ClientID string
	Oauth2Secret   string
}

type Client struct {
	client         *gitlab.Client
	URL            string
	oauth2ClientID string
	oauth2Secret   string
}

// fromCommitStatus converts a gitsource commit status to a gitea commit status
func fromCommitStatus(status gitsource.CommitStatus) gitlab.BuildStateValue {
	switch status {
	case gitsource.CommitStatusPending:
		return gitlab.Pending
	case gitsource.CommitStatusSuccess:
		return gitlab.Success
	case gitsource.CommitStatusFailed:
		return gitlab.Failed
	default:
		panic(fmt.Errorf("unknown commit status %q", status))
	}
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
	client := gitlab.NewOAuthClient(httpClient, opts.Token)
	client.SetBaseURL(opts.URL)

	return &Client{
		client:         client,
		URL:            opts.URL,
		oauth2ClientID: opts.Oauth2ClientID,
		oauth2Secret:   opts.Oauth2Secret,
	}, nil
}

func (c *Client) oauth2Config(callbackURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.oauth2ClientID,
		ClientSecret: c.oauth2Secret,
		Scopes:       GitlabOauth2Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("%s/oauth/authorize", c.URL),
			TokenURL: fmt.Sprintf("%s/oauth/token", c.URL),
		},
		RedirectURL: callbackURL,
	}
}

func (c *Client) GetOauth2AuthorizationURL(callbackURL, state string) (string, error) {
	var config = c.oauth2Config(callbackURL)
	return config.AuthCodeURL(state), nil
}

func (c *Client) RequestOauth2Token(callbackURL, code string) (*oauth2.Token, error) {
	var config = c.oauth2Config(callbackURL)
	token, err := config.Exchange(context.TODO(), code)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot get oauth2 token")
	}
	return token, nil
}

func (c *Client) RefreshOauth2Token(refreshToken string) (*oauth2.Token, error) {
	var config = c.oauth2Config("")
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := config.TokenSource(context.TODO(), token)
	return ts.Token()
}

func (c *Client) GetRepoInfo(repopath string) (*gitsource.RepoInfo, error) {
	repo, _, err := c.client.Projects.GetProject(repopath)
	if err != nil {
		return nil, err
	}
	return &gitsource.RepoInfo{
		ID:           strconv.Itoa(repo.ID),
		SSHCloneURL:  repo.SSHURLToRepo,
		HTTPCloneURL: repo.HTTPURLToRepo,
	}, nil
}

func (c *Client) GetUserInfo() (*gitsource.UserInfo, error) {
	user, _, err := c.client.Users.CurrentUser()
	if err != nil {
		return nil, err
	}
	return &gitsource.UserInfo{
		ID:        strconv.Itoa(user.ID),
		LoginName: user.Username,
		Email:     user.Email,
	}, nil
}

func (c *Client) GetFile(repopath, commit, file string) ([]byte, error) {
	f, _, err := c.client.RepositoryFiles.GetFile(repopath, file, &gitlab.GetFileOptions{Ref: gitlab.String(commit)})
	data, err := base64.StdEncoding.DecodeString(f.Content)
	if err != nil {
		return nil, err
	}
	return data, err
}

func (c *Client) CreateDeployKey(repopath, title, pubKey string, readonly bool) error {
	_, _, err := c.client.DeployKeys.AddDeployKey(repopath, &gitlab.AddDeployKeyOptions{
		Title: gitlab.String(title),
		Key:   gitlab.String(pubKey),
	})

	return errors.Wrapf(err, "error creating deploy key")
}

func (c *Client) UpdateDeployKey(repopath, title, pubKey string, readonly bool) error {
	keys, _, err := c.client.DeployKeys.ListProjectDeployKeys(repopath, nil)
	if err != nil {
		return errors.Wrapf(err, "error retrieving existing deploy keys")
	}

	for _, key := range keys {
		if key.Title == title {
			if key.Key == pubKey {
				return nil
			}
			if _, err := c.client.DeployKeys.DeleteDeployKey(repopath, key.ID); err != nil {
				return errors.Wrapf(err, "error removing existing deploy key")
			}
		}
	}

	if _, _, err := c.client.DeployKeys.AddDeployKey(repopath, &gitlab.AddDeployKeyOptions{
		Title: &title,
		Key:   &pubKey,
	}); err != nil {
		return errors.Wrapf(err, "error creating deploy key")
	}

	return nil
}

func (c *Client) DeleteDeployKey(repopath, title string) error {
	keys, _, err := c.client.DeployKeys.ListProjectDeployKeys(repopath, nil)
	if err != nil {
		return errors.Wrapf(err, "error retrieving existing deploy keys")
	}

	for _, key := range keys {
		if key.Title == title {
			if _, err := c.client.DeployKeys.DeleteDeployKey(repopath, key.ID); err != nil {
				return errors.Wrapf(err, "error removing existing deploy key")
			}
		}
	}

	return nil
}

func (c *Client) CreateRepoWebhook(repopath, url, secret string) error {
	opts := &gitlab.AddProjectHookOptions{
		URL:                 gitlab.String(url),
		PushEvents:          gitlab.Bool(true),
		TagPushEvents:       gitlab.Bool(true),
		MergeRequestsEvents: gitlab.Bool(true),
	}
	_, _, err := c.client.Projects.AddProjectHook(repopath, opts)

	return errors.Wrapf(err, "error creating repository webhook")
}

func (c *Client) DeleteRepoWebhook(repopath, u string) error {
	hooks, _, err := c.client.Projects.ListProjectHooks(repopath, nil)
	if err != nil {
		return errors.Wrapf(err, "error retrieving repository webhooks")
	}

	// match the full url so we can have multiple webhooks for different agola
	// projects
	for _, hook := range hooks {
		if hook.URL == u {
			if _, err := c.client.Projects.DeleteProjectHook(repopath, hook.ID); err != nil {
				return errors.Wrapf(err, "error deleting existing repository webhook")
			}
		}
	}

	return nil
}

func (c *Client) CreateCommitStatus(repopath, commitSHA string, status gitsource.CommitStatus, targetURL, description, context string) error {
	_, _, err := c.client.Commits.SetCommitStatus(repopath, commitSHA, &gitlab.SetCommitStatusOptions{
		State:       fromCommitStatus(status),
		TargetURL:   gitlab.String(targetURL),
		Description: gitlab.String(description),
		Context:     gitlab.String(context),
	})
	return err
}
