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

	gitsource "github.com/sorintlab/agola/internal/gitsources"

	gitlab "github.com/xanzy/go-gitlab"
	"golang.org/x/oauth2"
	errors "golang.org/x/xerrors"
)

var (
	GitlabOauth2Scopes = []string{"api"}
)

type Opts struct {
	APIURL         string
	Token          string
	SkipVerify     bool
	Oauth2ClientID string
	Oauth2Secret   string
}

type Client struct {
	client         *gitlab.Client
	APIURL         string
	oauth2ClientID string
	oauth2Secret   string
}

// fromCommitStatus converts a gitsource commit status to a gitlab commit status
func fromCommitStatus(status gitsource.CommitStatus) gitlab.BuildStateValue {
	switch status {
	case gitsource.CommitStatusPending:
		return gitlab.Pending
	case gitsource.CommitStatusSuccess:
		return gitlab.Success
	case gitsource.CommitStatusError:
		return gitlab.Failed
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
	client.SetBaseURL(opts.APIURL)

	return &Client{
		client:         client,
		APIURL:         opts.APIURL,
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
			AuthURL:  fmt.Sprintf("%s/oauth/authorize", c.APIURL),
			TokenURL: fmt.Sprintf("%s/oauth/token", c.APIURL),
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
		return nil, errors.Errorf("cannot get oauth2 token: %w", err)
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
	rr, _, err := c.client.Projects.GetProject(repopath)
	if err != nil {
		return nil, err
	}
	return fromGitlabRepo(rr), nil
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
	if err != nil {
		return nil, err
	}
	data, err := base64.StdEncoding.DecodeString(f.Content)
	if err != nil {
		return nil, err
	}
	return data, err
}

func (c *Client) CreateDeployKey(repopath, title, pubKey string, readonly bool) error {
	if _, _, err := c.client.DeployKeys.AddDeployKey(repopath, &gitlab.AddDeployKeyOptions{
		Title: gitlab.String(title),
		Key:   gitlab.String(pubKey),
	}); err != nil {
		return errors.Errorf("error creating deploy key: %w", err)
	}

	return nil
}

func (c *Client) UpdateDeployKey(repopath, title, pubKey string, readonly bool) error {
	keys, _, err := c.client.DeployKeys.ListProjectDeployKeys(repopath, nil)
	if err != nil {
		return errors.Errorf("error retrieving existing deploy keys: %w", err)
	}

	for _, key := range keys {
		if key.Title == title {
			if key.Key == pubKey {
				return nil
			}
			if _, err := c.client.DeployKeys.DeleteDeployKey(repopath, key.ID); err != nil {
				return errors.Errorf("error removing existing deploy key: %w", err)
			}
		}
	}

	if _, _, err := c.client.DeployKeys.AddDeployKey(repopath, &gitlab.AddDeployKeyOptions{
		Title: &title,
		Key:   &pubKey,
	}); err != nil {
		return errors.Errorf("error creating deploy key: %w", err)
	}

	return nil
}

func (c *Client) DeleteDeployKey(repopath, title string) error {
	keys, _, err := c.client.DeployKeys.ListProjectDeployKeys(repopath, nil)
	if err != nil {
		return errors.Errorf("error retrieving existing deploy keys: %w", err)
	}

	for _, key := range keys {
		if key.Title == title {
			if _, err := c.client.DeployKeys.DeleteDeployKey(repopath, key.ID); err != nil {
				return errors.Errorf("error removing existing deploy key: %w", err)
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
		Token:               gitlab.String(secret),
	}
	if _, _, err := c.client.Projects.AddProjectHook(repopath, opts); err != nil {
		return errors.Errorf("error creating repository webhook: %w", err)
	}

	return nil
}

func (c *Client) DeleteRepoWebhook(repopath, u string) error {
	hooks, _, err := c.client.Projects.ListProjectHooks(repopath, nil)
	if err != nil {
		return errors.Errorf("error retrieving repository webhooks: %w", err)
	}

	// match the full url so we can have multiple webhooks for different agola
	// projects
	for _, hook := range hooks {
		if hook.URL == u {
			if _, err := c.client.Projects.DeleteProjectHook(repopath, hook.ID); err != nil {
				return errors.Errorf("error deleting existing repository webhook: %w", err)
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

func (c *Client) ListUserRepos() ([]*gitsource.RepoInfo, error) {
	// get only repos with permission greater or equal to maintainer
	opts := &gitlab.ListProjectsOptions{MinAccessLevel: gitlab.AccessLevel(gitlab.MaintainerPermissions)}
	remoteRepos, _, err := c.client.Projects.ListProjects(opts)
	if err != nil {
		return nil, err
	}

	repos := []*gitsource.RepoInfo{}

	for _, rr := range remoteRepos {
		repos = append(repos, fromGitlabRepo(rr))
	}

	return repos, nil
}

func fromGitlabRepo(rr *gitlab.Project) *gitsource.RepoInfo {
	return &gitsource.RepoInfo{
		ID:           strconv.Itoa(rr.ID),
		Path:         rr.PathWithNamespace,
		HTMLURL:      rr.WebURL,
		SSHCloneURL:  rr.SSHURLToRepo,
		HTTPCloneURL: rr.HTTPURLToRepo,
	}
}
