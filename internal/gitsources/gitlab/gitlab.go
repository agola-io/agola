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
	"path"
	"strconv"
	"time"

	"github.com/pkg/errors"
	gitsource "github.com/sorintlab/agola/internal/gitsources"
	"github.com/sorintlab/agola/internal/services/types"
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

func (c *Client) GetOauth2AuthorizationURL(callbackURL, state string) (string, error) {

	var config = &oauth2.Config{
		ClientID:     c.oauth2ClientID,
		ClientSecret: c.oauth2Secret,
		Scopes:       GitlabOauth2Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("%s/oauth/authorize", c.URL),
			TokenURL: fmt.Sprintf("%s/oauth/token", c.URL),
		},
		RedirectURL: callbackURL,
	}

	return config.AuthCodeURL(state), nil
}

func (c *Client) RequestOauth2Token(callbackURL, code string) (*oauth2.Token, error) {

	var config = &oauth2.Config{
		ClientID:     c.oauth2ClientID,
		ClientSecret: c.oauth2Secret,
		Scopes:       GitlabOauth2Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("%s/oauth/authorize", c.URL),
			TokenURL: fmt.Sprintf("%s/oauth/token", c.URL),
		},
		RedirectURL: callbackURL,
	}

	token, err := config.Exchange(context.TODO(), code)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot get oauth2 token")
	}
	return token, nil
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

func (c *Client) GetFile(owner, repo, commit, file string) ([]byte, error) {
	f, _, err := c.client.RepositoryFiles.GetFile(path.Join(owner, repo), file, &gitlab.GetFileOptions{Ref: gitlab.String(commit)})
	data, err := base64.StdEncoding.DecodeString(f.Content)
	if err != nil {
		return nil, err
	}
	return data, err
}

func (c *Client) CreateDeployKey(owner, repo, title, pubKey string, readonly bool) error {
	_, _, err := c.client.DeployKeys.AddDeployKey(path.Join(owner, repo), &gitlab.AddDeployKeyOptions{
		Title: gitlab.String(title),
		Key:   gitlab.String(pubKey),
	})

	return errors.Wrapf(err, "error creating deploy key")
}

func (c *Client) UpdateDeployKey(owner, repo, title, pubKey string, readonly bool) error {
	keys, _, err := c.client.DeployKeys.ListProjectDeployKeys(path.Join(owner, repo), nil)
	if err != nil {
		return errors.Wrapf(err, "error retrieving existing deploy keys")
	}

	for _, key := range keys {
		if key.Title == title {
			if key.Key == pubKey {
				return nil
			}
			if _, err := c.client.DeployKeys.DeleteDeployKey(path.Join(owner, repo), key.ID); err != nil {
				return errors.Wrapf(err, "error removing existing deploy key")
			}
		}
	}

	if _, _, err := c.client.DeployKeys.AddDeployKey(path.Join(owner, repo), &gitlab.AddDeployKeyOptions{
		Title: &title,
		Key:   &pubKey,
	}); err != nil {
		return errors.Wrapf(err, "error creating deploy key")
	}

	return nil
}

func (c *Client) DeleteDeployKey(owner, repo, title string) error {
	keys, _, err := c.client.DeployKeys.ListProjectDeployKeys(path.Join(owner, repo), nil)
	if err != nil {
		return errors.Wrapf(err, "error retrieving existing deploy keys")
	}

	for _, key := range keys {
		if key.Title == title {
			if _, err := c.client.DeployKeys.DeleteDeployKey(path.Join(owner, repo), key.ID); err != nil {
				return errors.Wrapf(err, "error removing existing deploy key")
			}
		}
	}

	return nil
}

func (c *Client) CreateRepoWebhook(owner, repo, url, secret string) error {
	opts := &gitlab.AddProjectHookOptions{
		URL:        gitlab.String(url),
		PushEvents: gitlab.Bool(true),
	}
	_, _, err := c.client.Projects.AddProjectHook(path.Join(owner, repo), opts)

	return errors.Wrapf(err, "error creating repository webhook")
}

func (c *Client) DeleteRepoWebhook(owner, repo, u string) error {
	hooks, _, err := c.client.Projects.ListProjectHooks(path.Join(owner, repo), nil)
	if err != nil {
		return errors.Wrapf(err, "error retrieving repository webhooks")
	}

	// match the full url so we can have multiple webhooks for different agola
	// projects
	for _, hook := range hooks {
		if hook.URL == u {
			if _, err := c.client.Projects.DeleteProjectHook(path.Join(owner, repo), hook.ID); err != nil {
				return errors.Wrapf(err, "error deleting existing repository webhook")
			}
		}
	}

	return nil
}

func (c *Client) ParseWebhook(r *http.Request) (*types.WebhookData, error) {
	hookEvent := "X-Gitea-Event"
	return nil, errors.Errorf("unknown webhook event type: %q", r.Header.Get(hookEvent))
}
