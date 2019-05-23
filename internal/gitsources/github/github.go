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

package github

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	gitsource "github.com/sorintlab/agola/internal/gitsources"

	"github.com/google/go-github/v25/github"
	"golang.org/x/oauth2"
	errors "golang.org/x/xerrors"
)

var (
	GitHubOauth2Scopes = []string{"repo"}
)

const (
	GitHubAPIURL = "https://api.github.com"
	GitHubWebURL = "https://github.com"
)

type Opts struct {
	APIURL         string
	WebURL         string
	Token          string
	SkipVerify     bool
	Oauth2ClientID string
	Oauth2Secret   string
}

type Client struct {
	client         *github.Client
	httpClient     *http.Client
	APIURL         string
	WebURL         string
	oauth2ClientID string
	oauth2Secret   string
}

// fromCommitStatus converts a gitsource commit status to a github commit status
func fromCommitStatus(status gitsource.CommitStatus) string {
	switch status {
	case gitsource.CommitStatusPending:
		return "pending"
	case gitsource.CommitStatusSuccess:
		return "success"
	case gitsource.CommitStatusError:
		return "error"
	case gitsource.CommitStatusFailed:
		return "failure"
	default:
		panic(fmt.Errorf("unknown commit status %q", status))
	}
}

func parseRepoPath(repopath string) (string, string, error) {
	parts := strings.Split(repopath, "/")
	if len(parts) != 2 {
		return "", "", errors.Errorf("wrong github repo path: %q", repopath)
	}
	return parts[0], parts[1], nil
}

type TokenTransport struct {
	token string
	rt    http.RoundTripper
}

func (t *TokenTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.token != "" {
		r.Header.Set("Authorization", "Bearer "+t.token)
	}
	return t.rt.RoundTrip(r)
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
	httpClient := &http.Client{Transport: &TokenTransport{token: opts.Token, rt: transport}}

	if opts.APIURL == GitHubAPIURL {
		opts.WebURL = GitHubWebURL
	} else {
		if opts.WebURL == "" {
			opts.WebURL = opts.APIURL
		}
	}

	client := github.NewClient(httpClient)
	client.BaseURL, _ = url.Parse(GitHubAPIURL + "/")

	return &Client{
		client:         client,
		httpClient:     httpClient,
		APIURL:         opts.APIURL,
		WebURL:         opts.WebURL,
		oauth2ClientID: opts.Oauth2ClientID,
		oauth2Secret:   opts.Oauth2Secret,
	}, nil
}

func (c *Client) oauth2Config(callbackURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.oauth2ClientID,
		ClientSecret: c.oauth2Secret,
		Scopes:       GitHubOauth2Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("%s/login/oauth/authorize", c.WebURL),
			TokenURL: fmt.Sprintf("%s/login/oauth/access_token", c.WebURL),
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

func (c *Client) GetUserInfo() (*gitsource.UserInfo, error) {
	user, _, err := c.client.Users.Get(context.TODO(), "")
	if err != nil {
		return nil, err
	}
	return &gitsource.UserInfo{
		ID:        strconv.FormatInt(*user.ID, 10),
		LoginName: *user.Login,
		Email:     *user.Email,
	}, nil
}

func (c *Client) GetRepoInfo(repopath string) (*gitsource.RepoInfo, error) {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return nil, err
	}
	rr, _, err := c.client.Repositories.Get(context.TODO(), owner, reponame)
	if err != nil {
		return nil, err
	}
	return fromGithubRepo(rr), nil
}

func (c *Client) GetFile(repopath, commit, file string) ([]byte, error) {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return nil, err
	}
	r, err := c.client.Repositories.DownloadContents(context.TODO(), owner, reponame, file, &github.RepositoryContentGetOptions{Ref: commit})
	if err != nil {
		return nil, err
	}
	defer r.Close()

	return ioutil.ReadAll(r)
}

func (c *Client) CreateDeployKey(repopath, title, pubKey string, readonly bool) error {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return err
	}
	if _, _, err = c.client.Repositories.CreateKey(context.TODO(), owner, reponame, &github.Key{
		Title:    github.String(title),
		Key:      github.String(pubKey),
		ReadOnly: github.Bool(readonly),
	}); err != nil {
		return errors.Errorf("error creating deploy key: %w", err)
	}
	return nil
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
	keys, _, err := c.client.Repositories.ListKeys(context.TODO(), owner, reponame, nil)
	if err != nil {
		return errors.Errorf("error retrieving existing deploy keys: %w", err)
	}

	for _, key := range keys {
		if *key.Title == title {
			if *key.Key == pubKey {
				return nil
			}
			if _, err := c.client.Repositories.DeleteKey(context.TODO(), owner, reponame, *key.ID); err != nil {
				return errors.Errorf("error removing existing deploy key: %w", err)
			}
		}
	}

	if _, _, err = c.client.Repositories.CreateKey(context.TODO(), owner, reponame, &github.Key{
		Title:    github.String(title),
		Key:      github.String(pubKey),
		ReadOnly: github.Bool(readonly),
	}); err != nil {
		return errors.Errorf("error creating deploy key: %w", err)
	}

	return nil
}

func (c *Client) DeleteDeployKey(repopath, title string) error {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return err
	}
	keys, _, err := c.client.Repositories.ListKeys(context.TODO(), owner, reponame, nil)
	if err != nil {
		return errors.Errorf("error retrieving existing deploy keys: %w", err)
	}

	for _, key := range keys {
		if *key.Title == title {
			if _, err := c.client.Repositories.DeleteKey(context.TODO(), owner, reponame, *key.ID); err != nil {
				return errors.Errorf("error removing existing deploy key: %w", err)
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

	hook := &github.Hook{
		Config: map[string]interface{}{
			"url":          url,
			"content_type": "json",
			"secret":       secret,
		},
		Events: []string{"push", "pull_request"},
		Active: github.Bool(true),
	}

	if _, _, err = c.client.Repositories.CreateHook(context.TODO(), owner, reponame, hook); err != nil {
		return errors.Errorf("error creating repository webhook: %w", err)
	}

	return nil
}

func (c *Client) DeleteRepoWebhook(repopath, u string) error {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return err
	}

	hooks := []*github.Hook{}

	opt := &github.ListOptions{}
	for {
		pHooks, resp, err := c.client.Repositories.ListHooks(context.TODO(), owner, reponame, opt)
		if err != nil {
			return errors.Errorf("error retrieving repository webhooks: %w", err)
		}
		hooks = append(hooks, pHooks...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	// match the full url so we can have multiple webhooks for different agola
	// projects
	for _, hook := range hooks {
		if hook.Config["url"] == u {
			if _, err := c.client.Repositories.DeleteHook(context.TODO(), owner, reponame, *hook.ID); err != nil {
				return errors.Errorf("error deleting existing repository webhook: %w", err)
			}
		}
	}

	return nil
}

func (c *Client) CreateCommitStatus(repopath, commitSHA string, status gitsource.CommitStatus, targetURL, description, statusContext string) error {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return err
	}
	_, _, err = c.client.Repositories.CreateStatus(context.TODO(), owner, reponame, commitSHA, &github.RepoStatus{
		State:       github.String(fromCommitStatus(status)),
		TargetURL:   github.String(targetURL),
		Description: github.String(description),
		Context:     github.String(statusContext),
	})
	return err
}

func (c *Client) ListUserRepos() ([]*gitsource.RepoInfo, error) {
	remoteRepos := []*github.Repository{}

	opt := &github.RepositoryListOptions{}
	for {
		pRemoteRepos, resp, err := c.client.Repositories.List(context.TODO(), "", opt)
		if err != nil {
			return nil, err
		}
		remoteRepos = append(remoteRepos, pRemoteRepos...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	repos := []*gitsource.RepoInfo{}

	for _, rr := range remoteRepos {
		repos = append(repos, fromGithubRepo(rr))
	}

	return repos, nil
}

func fromGithubRepo(rr *github.Repository) *gitsource.RepoInfo {
	return &gitsource.RepoInfo{
		ID:           strconv.FormatInt(*rr.ID, 10),
		Path:         path.Join(*rr.Owner.Login, *rr.Name),
		SSHCloneURL:  *rr.SSHURL,
		HTTPCloneURL: *rr.CloneURL,
	}
}
