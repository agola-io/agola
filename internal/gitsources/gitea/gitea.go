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
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	gitsource "agola.io/agola/internal/gitsources"

	"code.gitea.io/sdk/gitea"
	"golang.org/x/oauth2"
	errors "golang.org/x/xerrors"
)

const (
	// TODO(sgotti) The gitea client doesn't provide an easy way to detect http response codes...
	// https://gitea.com/gitea/go-sdk/issues/303

	ClientNotFound = "404 Not Found"
)

var (
	// gitea corrently doesn't have any auth scope
	GiteaOauth2Scopes = []string{""}

	branchRefPrefix     = "refs/heads/"
	tagRefPrefix        = "refs/tags/"
	pullRequestRefRegex = regexp.MustCompile("refs/pull/(.*)/head")
	pullRequestRefFmt   = "refs/pull/%s/head"
)

type Opts struct {
	APIURL         string
	Token          string
	SkipVerify     bool
	Oauth2ClientID string
	Oauth2Secret   string
}

type Client struct {
	client           *gitea.Client
	oauth2HTTPClient *http.Client
	APIURL           string
	oauth2ClientID   string
	oauth2Secret     string
}

// fromCommitStatus converts a gitsource commit status to a gitea commit status
func fromCommitStatus(status gitsource.CommitStatus) gitea.StatusState {
	switch status {
	case gitsource.CommitStatusPending:
		return gitea.StatusPending
	case gitsource.CommitStatusSuccess:
		return gitea.StatusSuccess
	case gitsource.CommitStatusError:
		return gitea.StatusError
	case gitsource.CommitStatusFailed:
		return gitea.StatusFailure
	default:
		panic(errors.Errorf("unknown commit status %q", status))
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

	client := gitea.NewClient(opts.APIURL, opts.Token)
	client.SetHTTPClient(httpClient)

	return &Client{
		client:           client,
		oauth2HTTPClient: httpClient,
		APIURL:           opts.APIURL,
		oauth2ClientID:   opts.Oauth2ClientID,
		oauth2Secret:     opts.Oauth2Secret,
	}, nil
}

func (c *Client) oauth2Config(callbackURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.oauth2ClientID,
		ClientSecret: c.oauth2Secret,
		Scopes:       GiteaOauth2Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("%s/login/oauth/authorize", c.APIURL),
			TokenURL: fmt.Sprintf("%s/login/oauth/access_token", c.APIURL),
		},
		RedirectURL: callbackURL,
	}
}

func (c *Client) GetOauth2AuthorizationURL(callbackURL, state string) (string, error) {
	var config = c.oauth2Config(callbackURL)
	return config.AuthCodeURL(state), nil
}

func (c *Client) RequestOauth2Token(callbackURL, code string) (*oauth2.Token, error) {
	ctx := context.TODO()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.oauth2HTTPClient)

	var config = c.oauth2Config(callbackURL)
	token, err := config.Exchange(ctx, code)
	if err != nil {
		return nil, errors.Errorf("cannot get oauth2 token: %w", err)
	}
	return token, nil
}

func (c *Client) RefreshOauth2Token(refreshToken string) (*oauth2.Token, error) {
	ctx := context.TODO()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.oauth2HTTPClient)

	var config = c.oauth2Config("")
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := config.TokenSource(ctx, token)
	return ts.Token()
}

func (c *Client) LoginPassword(username, password, tokenName string) (string, error) {
	// try to get agola access token if it already exists
	// use custom http call since gitea api client doesn't provide an easy way to
	// guess if the username/password login failed
	// https://gitea.com/gitea/go-sdk/issues/303

	var accessToken string

	tokens := make([]*gitea.AccessToken, 0, 10)
	req, err := http.NewRequest("GET", c.APIURL+"/api/v1"+fmt.Sprintf("/users/%s/tokens", username), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))

	resp, err := c.oauth2HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return "", gitsource.ErrUnauthorized
	}
	if resp.StatusCode/100 != 2 {
		return "", errors.Errorf("gitea api status code %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&tokens); err != nil {
		return "", err
	}
	for _, token := range tokens {
		if token.Name == tokenName {
			accessToken = token.Token
			break
		}
	}

	// create access token
	if accessToken == "" {
		c.client.SetBasicAuth(username, password)
		token, terr := c.client.CreateAccessToken(
			gitea.CreateAccessTokenOption{Name: tokenName},
		)
		if terr != nil {
			return "", terr
		}
		accessToken = token.Token
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
	if _, err = c.client.CreateDeployKey(owner, reponame, gitea.CreateKeyOption{
		Title:    title,
		Key:      pubKey,
		ReadOnly: readonly,
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
	keys, err := c.client.ListDeployKeys(owner, reponame, gitea.ListDeployKeysOptions{})
	if err != nil {
		return errors.Errorf("error retrieving existing deploy keys: %w", err)
	}

	for _, key := range keys {
		if key.Title == title {
			if key.Key == pubKey {
				return nil
			}
			if err := c.client.DeleteDeployKey(owner, reponame, key.ID); err != nil {
				return errors.Errorf("error removing existing deploy key: %w", err)
			}
		}
	}

	if _, err := c.client.CreateDeployKey(owner, reponame, gitea.CreateKeyOption{
		Title:    title,
		Key:      pubKey,
		ReadOnly: readonly,
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
	keys, err := c.client.ListDeployKeys(owner, reponame, gitea.ListDeployKeysOptions{})
	if err != nil {
		return errors.Errorf("error retrieving existing deploy keys: %w", err)
	}

	for _, key := range keys {
		if key.Title == title {
			if err := c.client.DeleteDeployKey(owner, reponame, key.ID); err != nil {
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

	if _, err = c.client.CreateRepoHook(owner, reponame, opts); err != nil {
		return errors.Errorf("error creating repository webhook: %w", err)
	}

	return nil
}

func (c *Client) DeleteRepoWebhook(repopath, u string) error {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return err
	}
	hooks, err := c.client.ListRepoHooks(owner, reponame, gitea.ListHooksOptions{})
	if err != nil {
		return errors.Errorf("error retrieving repository webhooks: %w", err)
	}

	// match the full url so we can have multiple webhooks for different agola
	// projects
	for _, hook := range hooks {
		if hook.Config["url"] == u {
			if err := c.client.DeleteRepoHook(owner, reponame, hook.ID); err != nil {
				return errors.Errorf("error deleting existing repository webhook: %w", err)
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

func (c *Client) ListUserRepos() ([]*gitsource.RepoInfo, error) {
	remoteRepos, err := c.client.ListMyRepos(gitea.ListReposOptions{})
	if err != nil {
		return nil, err
	}

	repos := []*gitsource.RepoInfo{}

	for _, rr := range remoteRepos {
		// keep only repos with admin permissions
		if !rr.Permissions.Admin {
			continue
		}
		repos = append(repos, fromGiteaRepo(rr))
	}

	return repos, nil
}

func fromGiteaRepo(rr *gitea.Repository) *gitsource.RepoInfo {
	return &gitsource.RepoInfo{
		ID:           strconv.FormatInt(rr.ID, 10),
		Path:         path.Join(rr.Owner.UserName, rr.Name),
		HTMLURL:      rr.HTMLURL,
		SSHCloneURL:  rr.SSHURL,
		HTTPCloneURL: rr.CloneURL,
	}
}

func (c *Client) GetRef(repopath, ref string) (*gitsource.Ref, error) {
	owner, reponame, err := parseRepoPath(repopath)
	if err != nil {
		return nil, err
	}

	remoteRefs, err := c.client.GetRepoRefs(owner, reponame, ref)
	if err != nil {
		return nil, err
	}
	if len(remoteRefs) == 0 {
		return nil, errors.Errorf("no ref %q for repository %q", ref, repopath)
	}
	if len(remoteRefs) != 1 {
		return nil, errors.Errorf("no exact match found for ref %q for repository %q", ref, repopath)
	}

	return fromGiteaRef(remoteRefs[0])
}

func fromGiteaRef(remoteRef *gitea.Reference) (*gitsource.Ref, error) {
	t := remoteRef.Object.Type
	switch t {
	case "commit":
	default:
		return nil, errors.Errorf("unsupported object type: %s", t)
	}

	return &gitsource.Ref{
		Ref:       remoteRef.Ref,
		CommitSHA: remoteRef.Object.SHA,
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
		return nil, err
	}

	commit, err := c.client.GetSingleCommit(owner, reponame, commitSHA)
	if err != nil {
		return nil, err
	}

	return &gitsource.Commit{
		SHA:     commit.SHA,
		Message: commit.RepoCommit.Message,
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
	return fmt.Sprintf("%s/pulls/%s", repoInfo.HTMLURL, prID)
}
