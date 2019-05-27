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
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	gitsource "github.com/sorintlab/agola/internal/gitsources"
	"golang.org/x/oauth2"

	"code.gitea.io/sdk/gitea"
	"github.com/pkg/errors"
)

const (
	// TODO(sgotti) The gitea client doesn't provide an easy way to detect http response codes...
	// we should probably use our own client implementation

	ClientNotFound = "404 Not Found"
)

var (
	// gitea corrently doesn't have any auth scope
	GiteaOauth2Scopes = []string{""}
)

type Opts struct {
	URL            string
	Token          string
	SkipVerify     bool
	Oauth2ClientID string
	Oauth2Secret   string
}

type Client struct {
	client         *gitea.Client
	URL            string
	oauth2ClientID string
	oauth2Secret   string
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
		panic(fmt.Errorf("unknown commit status %q", status))
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
		Scopes:       GiteaOauth2Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("%s/login/oauth/authorize", c.URL),
			TokenURL: fmt.Sprintf("%s/login/oauth/access_token", c.URL),
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

func (c *Client) LoginPassword(username, password, tokenName string) (string, error) {
	// try to get agola access token if it already exists
	var accessToken string
	tokens, err := c.client.ListAccessTokens(username, password)
	if err == nil {
		for _, token := range tokens {
			if token.Name == tokenName {
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
			gitea.CreateAccessTokenOption{Name: tokenName},
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
	rr, err := c.client.GetRepo(owner, reponame)
	if err != nil {
		return nil, err
	}
	return fromGiteaRepo(rr), nil
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

func (c *Client) CreateCommitStatus(repopath, commitSHA string, status gitsource.CommitStatus, targetURL, description, context string) error {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return err
	}
	_, err = c.client.CreateStatus(owner, reponame, commitSHA, gitea.CreateStatusOption{
		State:       fromCommitStatus(status),
		TargetURL:   targetURL,
		Description: description,
		Context:     context,
	})
	return err
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

func (c *Client) ListUserRepos() ([]*gitsource.RepoInfo, error) {
	remoteRepos, err := c.client.ListMyRepos()
	if err != nil {
		return nil, err
	}

	repos := []*gitsource.RepoInfo{}

	for _, rr := range remoteRepos {
		repos = append(repos, fromGiteaRepo(rr))
	}

	return repos, nil
}

func fromGiteaRepo(rr *gitea.Repository) *gitsource.RepoInfo {
	return &gitsource.RepoInfo{
		ID:           strconv.FormatInt(rr.ID, 10),
		Path:         path.Join(rr.Owner.UserName, rr.Name),
		SSHCloneURL:  rr.SSHURL,
		HTTPCloneURL: rr.CloneURL,
	}
}
