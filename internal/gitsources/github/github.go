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

package github

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v50/github"
	"github.com/sorintlab/errors"
	"golang.org/x/oauth2"

	gitsource "agola.io/agola/internal/gitsources"
)

var (
	GitHubOauth2Scopes = []string{"repo"}

	branchRefPrefix     = "refs/heads/"
	tagRefPrefix        = "refs/tags/"
	pullRequestRefRegex = regexp.MustCompile("refs/pull/(.*)/head")
	pullRequestRefFmt   = "refs/pull/%s/head"
)

const (
	GitHubAPIURL = "https://api.github.com"
	GitHubWebURL = "https://github.com"

	GitHubSSHHostKey = "github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk="
)

type httpOpts struct {
	SkipVerify bool
}

type Opts struct {
	APIURL     string
	WebURL     string
	SkipVerify bool
	Token      string
}

type Client struct {
	client *github.Client
	APIURL string
	WebURL string
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
		panic(errors.Errorf("unknown commit status %q", status))
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

	//nolint:wrapcheck
	return t.rt.RoundTrip(r)
}

func newHTTPTransport(opts httpOpts) *http.Transport {
	// copied from net/http until it has a clone function: https://github.com/golang/go/issues/26013
	return &http.Transport{
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
}

func getURLs(apiURL, webURL string) (string, string) {
	isPublicGithub := false
	// TODO(sgotti) improve detection of public github url (handle also trailing slash)
	if apiURL == GitHubAPIURL {
		isPublicGithub = true
	}

	if isPublicGithub {
		webURL = GitHubWebURL
		if !strings.HasSuffix(apiURL, "/") {
			apiURL += "/"
		}
	} else {
		if webURL == "" {
			webURL = apiURL
		}
		if !strings.HasSuffix(apiURL, "/") {
			apiURL += "/"
		}
		if !strings.HasSuffix(apiURL, "/api/v3/") {
			apiURL += "api/v3/"
		}
	}

	return apiURL, webURL
}

func New(opts Opts) (*Client, error) {
	httpTransport := newHTTPTransport(httpOpts{SkipVerify: opts.SkipVerify})
	httpClient := &http.Client{Transport: &TokenTransport{token: opts.Token, rt: httpTransport}}

	apiURL, webURL := getURLs(opts.APIURL, opts.WebURL)

	client := github.NewClient(httpClient)
	client.BaseURL, _ = url.Parse(apiURL)

	return &Client{
		client: client,
		APIURL: apiURL,
		WebURL: webURL,
	}, nil
}

func (c *Client) GetUserInfo() (*gitsource.UserInfo, error) {
	user, _, err := c.client.Users.Get(context.TODO(), "")
	if err != nil {
		return nil, errors.WithStack(err)
	}

	userInfo := &gitsource.UserInfo{
		ID:        strconv.FormatInt(*user.ID, 10),
		LoginName: *user.Login,
	}
	if user.Email != nil {
		userInfo.Email = *user.Email
	}

	return userInfo, nil
}

func (c *Client) GetRepoInfo(repopath string) (*gitsource.RepoInfo, error) {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	rr, _, err := c.client.Repositories.Get(context.TODO(), owner, reponame)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return fromGithubRepo(rr), nil
}

func (c *Client) GetFile(repopath, commit, file string) ([]byte, error) {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	r, _, err := c.client.Repositories.DownloadContents(context.TODO(), owner, reponame, file, &github.RepositoryContentGetOptions{Ref: commit})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer r.Close()

	d, err := io.ReadAll(r)
	return d, errors.WithStack(err)
}

func (c *Client) CreateDeployKey(repopath, title, pubKey string, readonly bool) error {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return errors.WithStack(err)
	}
	if _, _, err = c.client.Repositories.CreateKey(context.TODO(), owner, reponame, &github.Key{
		Title:    github.String(title),
		Key:      github.String(pubKey),
		ReadOnly: github.Bool(readonly),
	}); err != nil {
		return errors.Wrapf(err, "error creating deploy key")
	}
	return nil
}

func (c *Client) UpdateDeployKey(repopath, title, pubKey string, readonly bool) error {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return errors.WithStack(err)
	}
	// NOTE(sgotti) gitea has a bug where if we delete and remove the same key with
	// the same value it is correctly readded and the admin must force a
	// authorized_keys regeneration on the server. To avoid this we update it only
	// when the public key value has changed
	keys, _, err := c.client.Repositories.ListKeys(context.TODO(), owner, reponame, nil)
	if err != nil {
		return errors.Wrapf(err, "error retrieving existing deploy keys")
	}

	for _, key := range keys {
		if *key.Title == title {
			if *key.Key == pubKey {
				return nil
			}
			if _, err := c.client.Repositories.DeleteKey(context.TODO(), owner, reponame, *key.ID); err != nil {
				return errors.Wrapf(err, "error removing existing deploy key")
			}
		}
	}

	if _, _, err = c.client.Repositories.CreateKey(context.TODO(), owner, reponame, &github.Key{
		Title:    github.String(title),
		Key:      github.String(pubKey),
		ReadOnly: github.Bool(readonly),
	}); err != nil {
		return errors.Wrapf(err, "error creating deploy key")
	}

	return nil
}

func (c *Client) DeleteDeployKey(repopath, title string) error {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return errors.WithStack(err)
	}
	keys, _, err := c.client.Repositories.ListKeys(context.TODO(), owner, reponame, nil)
	if err != nil {
		return errors.Wrapf(err, "error retrieving existing deploy keys")
	}

	for _, key := range keys {
		if *key.Title == title {
			if _, err := c.client.Repositories.DeleteKey(context.TODO(), owner, reponame, *key.ID); err != nil {
				return errors.Wrapf(err, "error removing existing deploy key")
			}
		}
	}

	return nil
}

func (c *Client) CreateRepoWebhook(repopath, url, secret string) error {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return errors.WithStack(err)
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
		return errors.Wrapf(err, "error creating repository webhook")
	}

	return nil
}

func (c *Client) DeleteRepoWebhook(repopath, u string) error {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return errors.WithStack(err)
	}

	hooks := []*github.Hook{}

	opt := &github.ListOptions{}
	for {
		pHooks, resp, err := c.client.Repositories.ListHooks(context.TODO(), owner, reponame, opt)
		if err != nil {
			return errors.Wrapf(err, "error retrieving repository webhooks")
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
				return errors.Wrapf(err, "error deleting existing repository webhook")
			}
		}
	}

	return nil
}

func (c *Client) CreateCommitStatus(repopath, commitSHA string, status gitsource.CommitStatus, targetURL, description, statusContext string) error {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return errors.WithStack(err)
	}
	_, _, err = c.client.Repositories.CreateStatus(context.TODO(), owner, reponame, commitSHA, &github.RepoStatus{
		State:       github.String(fromCommitStatus(status)),
		TargetURL:   github.String(targetURL),
		Description: github.String(description),
		Context:     github.String(statusContext),
	})
	return errors.WithStack(err)
}

func (c *Client) ListUserRepos() ([]*gitsource.RepoInfo, error) {
	remoteRepos := []*github.Repository{}

	opt := &github.RepositoryListOptions{}
	for {
		pRemoteRepos, resp, err := c.client.Repositories.List(context.TODO(), "", opt)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		remoteRepos = append(remoteRepos, pRemoteRepos...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	repos := []*gitsource.RepoInfo{}

	for _, rr := range remoteRepos {
		// keep only repos with admin permissions
		if rr.Permissions != nil {
			if !rr.Permissions["admin"] {
				continue
			}
			repos = append(repos, fromGithubRepo(rr))
		}
	}

	return repos, nil
}

func fromGithubRepo(rr *github.Repository) *gitsource.RepoInfo {
	return &gitsource.RepoInfo{
		ID:            strconv.FormatInt(*rr.ID, 10),
		Path:          path.Join(*rr.Owner.Login, *rr.Name),
		HTMLURL:       *rr.HTMLURL,
		SSHCloneURL:   *rr.SSHURL,
		HTTPCloneURL:  *rr.CloneURL,
		DefaultBranch: *rr.DefaultBranch,
	}
}

func (c *Client) GetRef(repopath, ref string) (*gitsource.Ref, error) {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	remoteRef, _, err := c.client.Git.GetRef(context.TODO(), owner, reponame, ref)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return fromGithubRef(remoteRef)
}

func fromGithubRef(remoteRef *github.Reference) (*gitsource.Ref, error) {
	t := *(remoteRef.Object.Type)
	switch t {
	case "commit":
	default:
		return nil, errors.Errorf("unsupported object type: %s", t)
	}

	return &gitsource.Ref{
		Ref:       *remoteRef.Ref,
		CommitSHA: *remoteRef.Object.SHA,
	}, nil
}

func (c *Client) RefType(ref string) (gitsource.RefType, string, error) {
	switch {
	case strings.HasPrefix(ref, branchRefPrefix):
		return gitsource.RefTypeBranch, strings.TrimPrefix(ref, branchRefPrefix), nil

	case strings.HasPrefix(ref, tagRefPrefix):
		return gitsource.RefTypeTag, strings.TrimPrefix(ref, tagRefPrefix), nil

	case pullRequestRefRegex.MatchString(ref):
		m := pullRequestRefRegex.FindStringSubmatch(ref)
		return gitsource.RefTypePullRequest, m[1], nil

	default:
		return -1, "", errors.Errorf("unsupported ref: %s", ref)
	}
}

func (c *Client) GetCommit(repopath, commitSHA string) (*gitsource.Commit, error) {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	commit, _, err := c.client.Git.GetCommit(context.TODO(), owner, reponame, commitSHA)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &gitsource.Commit{
		SHA:     *commit.SHA,
		Message: *commit.Message,
	}, nil
}

func (c *Client) BranchRef(branch string) string {
	return branchRefPrefix + branch
}

func (c *Client) TagRef(tag string) string {
	return tagRefPrefix + tag
}

func (c *Client) PullRequestRef(prID string) string {
	return fmt.Sprintf(pullRequestRefFmt, prID)
}

func (c *Client) CommitLink(repoInfo *gitsource.RepoInfo, commitSHA string) string {
	return fmt.Sprintf("%s/commit/%s", repoInfo.HTMLURL, commitSHA)
}

func (c *Client) BranchLink(repoInfo *gitsource.RepoInfo, branch string) string {
	return fmt.Sprintf("%s/src/branch/%s", repoInfo.HTMLURL, branch)
}

func (c *Client) TagLink(repoInfo *gitsource.RepoInfo, tag string) string {
	return fmt.Sprintf("%s/src/tag/%s", repoInfo.HTMLURL, tag)
}

func (c *Client) PullRequestLink(repoInfo *gitsource.RepoInfo, prID string) string {
	return fmt.Sprintf("%s/pull/%s", repoInfo.HTMLURL, prID)
}

type Oauth2Opts struct {
	APIURL         string
	WebURL         string
	SkipVerify     bool
	Oauth2ClientID string
	Oauth2Secret   string
}

type Oauth2Client struct {
	httpClient     *http.Client
	APIURL         string
	WebURL         string
	oauth2ClientID string
	oauth2Secret   string
}

func NewOauth2Client(opts Oauth2Opts) (*Oauth2Client, error) {
	httpTransport := newHTTPTransport(httpOpts{SkipVerify: opts.SkipVerify})
	httpClient := &http.Client{Transport: httpTransport}

	apiURL, webURL := getURLs(opts.APIURL, opts.WebURL)

	return &Oauth2Client{
		httpClient:     httpClient,
		APIURL:         apiURL,
		WebURL:         webURL,
		oauth2ClientID: opts.Oauth2ClientID,
		oauth2Secret:   opts.Oauth2Secret,
	}, nil
}

func (c *Oauth2Client) oauth2Config(callbackURL string) *oauth2.Config {
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

func (c *Oauth2Client) GetOauth2AuthorizationURL(callbackURL, state string) (string, error) {
	var config = c.oauth2Config(callbackURL)
	return config.AuthCodeURL(state), nil
}

func (c *Oauth2Client) RequestOauth2Token(callbackURL, code string) (*oauth2.Token, error) {
	ctx := context.TODO()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.httpClient)

	var config = c.oauth2Config(callbackURL)
	token, err := config.Exchange(ctx, code)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot get oauth2 token")
	}
	return token, nil
}

func (c *Oauth2Client) RefreshOauth2Token(refreshToken string) (*oauth2.Token, error) {
	ctx := context.TODO()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.httpClient)

	var config = c.oauth2Config("")
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := config.TokenSource(ctx, token)
	ntoken, err := ts.Token()

	return ntoken, errors.WithStack(err)
}
