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

package agolagit

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	gitsource "agola.io/agola/internal/gitsources"
	"agola.io/agola/internal/services/types"
	errors "golang.org/x/xerrors"
)

var (
	branchRefPrefix = "refs/heads/"
	tagRefPrefix    = "refs/tags/"
)

type Client struct {
	url                   string
	client                *http.Client
	pullRequestRefRegexes []*regexp.Regexp
}

// NewClient initializes and returns a API client.
func New(url string, pullRequestRefRegexes []*regexp.Regexp) *Client {
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
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := &http.Client{Transport: transport}
	return &Client{
		url:                   strings.TrimSuffix(url, "/"),
		client:                httpClient,
		pullRequestRefRegexes: pullRequestRefRegexes,
	}
}

// SetHTTPClient replaces default http.Client with user given one.
func (c *Client) SetHTTPClient(client *http.Client) {
	c.client = client
}

func (c *Client) doRequest(method, path string, query url.Values, header http.Header, ibody io.Reader) (*http.Response, error) {
	u, err := url.Parse(c.url + "/" + path)
	if err != nil {
		return nil, err
	}
	u.RawQuery = query.Encode()

	req, err := http.NewRequest(method, u.String(), ibody)
	if err != nil {
		return nil, err
	}
	for k, v := range header {
		req.Header[k] = v
	}

	return c.client.Do(req)
}

func (c *Client) getResponse(method, path string, query url.Values, header http.Header, ibody io.Reader) (*http.Response, error) {
	resp, err := c.doRequest(method, path, query, header, ibody)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close()
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		if len(data) <= 1 {
			return resp, errors.New(resp.Status)
		}

		// TODO(sgotti) use a json error response

		return resp, errors.New(string(data))
	}

	return resp, nil
}

func (c *Client) GetUserInfo() (*gitsource.UserInfo, error) {
	return nil, nil
}

func (c *Client) GetRepoInfo(repopath string) (*gitsource.RepoInfo, error) {
	return nil, nil
}

func (c *Client) GetFile(repopath, commit, file string) ([]byte, error) {
	resp, err := c.getResponse("GET", fmt.Sprintf("%s.git/raw/%s/%s", repopath, commit, file), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	return data, err
}

func (c *Client) CreateDeployKey(repopath, title, pubKey string, readonly bool) error {
	return nil
}

func (c *Client) DeleteDeployKey(repopath, title string) error {
	return nil
}

func (c *Client) UpdateDeployKey(repopath, title, pubKey string, readonly bool) error {
	return nil
}

func (c *Client) CreateRepoWebhook(repopath, url, secret string) error {
	return nil
}

func (c *Client) ParseWebhook(r *http.Request, secret string) (*types.WebhookData, error) {
	return nil, nil
}

func (c *Client) DeleteRepoWebhook(repopath, u string) error {
	return nil
}

func (c *Client) CreateCommitStatus(repopath, commitSHA string, status gitsource.CommitStatus, targetURL, description, context string) error {
	return nil
}

func (c *Client) ListUserRepos() ([]*gitsource.RepoInfo, error) {
	return nil, nil
}

func (c *Client) GetRef(repopath, ref string) (*gitsource.Ref, error) {
	return nil, nil
}

func (c *Client) RefType(ref string) (gitsource.RefType, string, error) {
	if strings.HasPrefix(ref, branchRefPrefix) {
		return gitsource.RefTypeBranch, strings.TrimPrefix(ref, branchRefPrefix), nil
	}

	if strings.HasPrefix(ref, tagRefPrefix) {
		return gitsource.RefTypeTag, strings.TrimPrefix(ref, tagRefPrefix), nil
	}

	for _, re := range c.pullRequestRefRegexes {
		if re.MatchString(ref) {
			m := re.FindStringSubmatch(ref)
			return gitsource.RefTypePullRequest, m[1], nil
		}
	}

	return -1, "", fmt.Errorf("unsupported ref: %s", ref)
}

func (c *Client) GetCommit(repopath, commitSHA string) (*gitsource.Commit, error) {
	return nil, nil
}

func (c *Client) BranchRef(branch string) string {
	return branchRefPrefix + branch
}

func (c *Client) TagRef(tag string) string {
	return tagRefPrefix + tag
}

func (c *Client) PullRequestRef(prID string) string {
	return ""
}

func (c *Client) CommitLink(repoInfo *gitsource.RepoInfo, commitSHA string) string {
	return ""
}

func (c *Client) BranchLink(repoInfo *gitsource.RepoInfo, branch string) string {
	return ""
}

func (c *Client) TagLink(repoInfo *gitsource.RepoInfo, tag string) string {
	return ""
}

func (c *Client) PullRequestLink(repoInfo *gitsource.RepoInfo, prID string) string {
	return ""
}
