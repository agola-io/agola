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

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/sorintlab/agola/internal/services/types"

	"github.com/pkg/errors"
)

var jsonContent = http.Header{"content-type": []string{"application/json"}}

// Client represents a Gogs API client.
type Client struct {
	url    string
	client *http.Client
}

// NewClient initializes and returns a API client.
func NewClient(url string) *Client {
	return &Client{
		url:    strings.TrimSuffix(url, "/"),
		client: &http.Client{},
	}
}

// SetHTTPClient replaces default http.Client with user given one.
func (c *Client) SetHTTPClient(client *http.Client) {
	c.client = client
}

func (c *Client) doRequest(ctx context.Context, method, path string, query url.Values, header http.Header, ibody io.Reader) (*http.Response, error) {
	u, err := url.Parse(c.url + "/api/v1alpha" + path)
	if err != nil {
		return nil, err
	}
	u.RawQuery = query.Encode()

	req, err := http.NewRequest(method, u.String(), ibody)
	req = req.WithContext(ctx)
	if err != nil {
		return nil, err
	}
	for k, v := range header {
		req.Header[k] = v
	}

	return c.client.Do(req)
}

func (c *Client) getResponse(ctx context.Context, method, path string, query url.Values, header http.Header, ibody io.Reader) (*http.Response, error) {
	resp, err := c.doRequest(ctx, method, path, query, header, ibody)
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

func (c *Client) getParsedResponse(ctx context.Context, method, path string, query url.Values, header http.Header, ibody io.Reader, obj interface{}) (*http.Response, error) {
	resp, err := c.getResponse(ctx, method, path, query, header, ibody)
	if err != nil {
		return resp, err
	}
	defer resp.Body.Close()

	d := json.NewDecoder(resp.Body)

	return resp, d.Decode(obj)
}

func (c *Client) GetProjectGroup(ctx context.Context, projectGroupID string) (*types.ProjectGroup, *http.Response, error) {
	projectGroup := new(types.ProjectGroup)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projectgroups/%s", url.PathEscape(projectGroupID)), nil, jsonContent, nil, projectGroup)
	return projectGroup, resp, err
}

func (c *Client) GetProjectGroupSubgroups(ctx context.Context, projectGroupID string) ([]*types.ProjectGroup, *http.Response, error) {
	projectGroups := []*types.ProjectGroup{}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projectgroups/%s/subgroups", url.PathEscape(projectGroupID)), nil, jsonContent, nil, &projectGroups)
	return projectGroups, resp, err
}

func (c *Client) GetProjectGroupProjects(ctx context.Context, projectGroupID string) ([]*types.Project, *http.Response, error) {
	projects := []*types.Project{}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projectgroups/%s/projects", url.PathEscape(projectGroupID)), nil, jsonContent, nil, &projects)
	return projects, resp, err
}

func (c *Client) CreateProjectGroup(ctx context.Context, projectGroup *types.ProjectGroup) (*types.ProjectGroup, *http.Response, error) {
	pj, err := json.Marshal(projectGroup)
	if err != nil {
		return nil, nil, err
	}

	projectGroup = new(types.ProjectGroup)
	resp, err := c.getParsedResponse(ctx, "PUT", "/projectgroups", nil, jsonContent, bytes.NewReader(pj), projectGroup)
	return projectGroup, resp, err
}

func (c *Client) GetProject(ctx context.Context, projectID string) (*types.Project, *http.Response, error) {
	project := new(types.Project)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projects/%s", url.PathEscape(projectID)), nil, jsonContent, nil, project)
	return project, resp, err
}

func (c *Client) CreateProject(ctx context.Context, project *types.Project) (*types.Project, *http.Response, error) {
	pj, err := json.Marshal(project)
	if err != nil {
		return nil, nil, err
	}

	project = new(types.Project)
	resp, err := c.getParsedResponse(ctx, "PUT", "/projects", nil, jsonContent, bytes.NewReader(pj), project)
	return project, resp, err
}

func (c *Client) DeleteProject(ctx context.Context, projectID string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/projects/%s", url.PathEscape(projectID)), nil, jsonContent, nil)
}

func (c *Client) GetUser(ctx context.Context, userID string) (*types.User, *http.Response, error) {
	user := new(types.User)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/user/%s", userID), nil, jsonContent, nil, user)
	return user, resp, err
}

func (c *Client) GetUserByName(ctx context.Context, userName string) (*types.User, *http.Response, error) {
	user := new(types.User)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/users/%s", userName), nil, jsonContent, nil, user)
	return user, resp, err
}

func (c *Client) GetUserByToken(ctx context.Context, token string) (*types.User, *http.Response, error) {
	q := url.Values{}
	q.Add("query_type", "bytoken")
	q.Add("token", token)

	users := []*types.User{}
	resp, err := c.getParsedResponse(ctx, "GET", "/users", q, jsonContent, nil, &users)
	if err != nil {
		return nil, resp, err
	}
	return users[0], resp, err
}

func (c *Client) GetUserByLinkedAccountRemoteUserAndSource(ctx context.Context, remoteUserID, remoteSourceID string) (*types.User, *http.Response, error) {
	q := url.Values{}
	q.Add("query_type", "byremoteuser")
	q.Add("remoteuserid", remoteUserID)
	q.Add("remotesourceid", remoteSourceID)

	users := []*types.User{}
	resp, err := c.getParsedResponse(ctx, "GET", "/users", q, jsonContent, nil, &users)
	if err != nil {
		return nil, resp, err
	}
	return users[0], resp, err
}

func (c *Client) GetUserByLinkedAccount(ctx context.Context, linkedAccountID string) (*types.User, *http.Response, error) {
	q := url.Values{}
	q.Add("query_type", "bylinkedaccount")
	q.Add("linkedaccountid", linkedAccountID)

	users := []*types.User{}
	resp, err := c.getParsedResponse(ctx, "GET", "/users", q, jsonContent, nil, &users)
	if err != nil {
		return nil, resp, err
	}
	return users[0], resp, err
}

func (c *Client) CreateUser(ctx context.Context, user *types.User) (*types.User, *http.Response, error) {
	uj, err := json.Marshal(user)
	if err != nil {
		return nil, nil, err
	}

	user = new(types.User)
	resp, err := c.getParsedResponse(ctx, "PUT", "/users", nil, jsonContent, bytes.NewReader(uj), user)
	return user, resp, err
}

func (c *Client) DeleteUser(ctx context.Context, userName string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/users/%s", userName), nil, jsonContent, nil)
}

func (c *Client) GetUsers(ctx context.Context, start string, limit int, asc bool) ([]*types.User, *http.Response, error) {
	q := url.Values{}
	if start != "" {
		q.Add("start", start)
	}
	if limit > 0 {
		q.Add("limit", strconv.Itoa(limit))
	}
	if asc {
		q.Add("asc", "")
	}

	users := []*types.User{}
	resp, err := c.getParsedResponse(ctx, "GET", "/users", q, jsonContent, nil, &users)
	return users, resp, err
}

func (c *Client) CreateUserLA(ctx context.Context, userName string, req *CreateUserLARequest) (*types.LinkedAccount, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}

	la := new(types.LinkedAccount)
	resp, err := c.getParsedResponse(ctx, "PUT", fmt.Sprintf("/users/%s/linkedaccounts", userName), nil, jsonContent, bytes.NewReader(reqj), la)
	return la, resp, err
}

func (c *Client) DeleteUserLA(ctx context.Context, userName, laID string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/users/%s/linkedaccounts/%s", userName, laID), nil, jsonContent, nil)
}

func (c *Client) UpdateUserLA(ctx context.Context, userName, laID string, req *UpdateUserLARequest) (*types.LinkedAccount, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}

	la := new(types.LinkedAccount)
	resp, err := c.getParsedResponse(ctx, "PUT", fmt.Sprintf("/users/%s/linkedaccounts/%s", userName, laID), nil, jsonContent, bytes.NewReader(reqj), la)
	return la, resp, err
}

func (c *Client) CreateUserToken(ctx context.Context, userName string, req *CreateUserTokenRequest) (*CreateUserTokenResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}

	tresp := new(CreateUserTokenResponse)
	resp, err := c.getParsedResponse(ctx, "PUT", fmt.Sprintf("/users/%s/tokens", userName), nil, jsonContent, bytes.NewReader(reqj), tresp)
	return tresp, resp, err
}

func (c *Client) GetRemoteSource(ctx context.Context, rsID string) (*types.RemoteSource, *http.Response, error) {
	rs := new(types.RemoteSource)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/remotesource/%s", rsID), nil, jsonContent, nil, rs)
	return rs, resp, err
}

func (c *Client) GetRemoteSourceByName(ctx context.Context, rsName string) (*types.RemoteSource, *http.Response, error) {
	rs := new(types.RemoteSource)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/remotesources/%s", rsName), nil, jsonContent, nil, rs)
	return rs, resp, err
}

func (c *Client) GetRemoteSources(ctx context.Context, start string, limit int, asc bool) ([]*types.RemoteSource, *http.Response, error) {
	q := url.Values{}
	if start != "" {
		q.Add("start", start)
	}
	if limit > 0 {
		q.Add("limit", strconv.Itoa(limit))
	}
	if asc {
		q.Add("asc", "")
	}

	rss := []*types.RemoteSource{}
	resp, err := c.getParsedResponse(ctx, "GET", "/remotesources", q, jsonContent, nil, &rss)
	return rss, resp, err
}

func (c *Client) CreateRemoteSource(ctx context.Context, rs *types.RemoteSource) (*types.RemoteSource, *http.Response, error) {
	uj, err := json.Marshal(rs)
	if err != nil {
		return nil, nil, err
	}

	rs = new(types.RemoteSource)
	resp, err := c.getParsedResponse(ctx, "PUT", "/remotesources", nil, jsonContent, bytes.NewReader(uj), rs)
	return rs, resp, err
}

func (c *Client) DeleteRemoteSource(ctx context.Context, name string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/remotesources/%s", name), nil, jsonContent, nil)
}

func (c *Client) CreateOrg(ctx context.Context, org *types.Organization) (*types.Organization, *http.Response, error) {
	oj, err := json.Marshal(org)
	if err != nil {
		return nil, nil, err
	}

	org = new(types.Organization)
	resp, err := c.getParsedResponse(ctx, "PUT", "/orgs", nil, jsonContent, bytes.NewReader(oj), org)
	return org, resp, err
}

func (c *Client) DeleteOrg(ctx context.Context, orgname string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/orgs/%s", orgname), nil, jsonContent, nil)
}

func (c *Client) GetOrgs(ctx context.Context, start string, limit int, asc bool) ([]*types.Organization, *http.Response, error) {
	q := url.Values{}
	if start != "" {
		q.Add("start", start)
	}
	if limit > 0 {
		q.Add("limit", strconv.Itoa(limit))
	}
	if asc {
		q.Add("asc", "")
	}

	orgs := []*types.Organization{}
	resp, err := c.getParsedResponse(ctx, "GET", "/orgs", q, jsonContent, nil, &orgs)
	return orgs, resp, err
}

func (c *Client) GetOrg(ctx context.Context, orgID string) (*types.Organization, *http.Response, error) {
	org := new(types.Organization)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/org/%s", orgID), nil, jsonContent, nil, org)
	return org, resp, err
}

func (c *Client) GetOrgByName(ctx context.Context, orgname string) (*types.Organization, *http.Response, error) {
	org := new(types.Organization)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/orgs/%s", orgname), nil, jsonContent, nil, org)
	return org, resp, err
}
