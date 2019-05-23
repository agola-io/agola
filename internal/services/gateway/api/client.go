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
	"path"
	"strconv"
	"strings"

	"github.com/sorintlab/agola/internal/services/types"

	"github.com/pkg/errors"
)

var jsonContent = http.Header{"Content-Type": []string{"application/json"}}

// Client represents a Gogs API client.
type Client struct {
	url    string
	client *http.Client
	token  string
}

// NewClient initializes and returns a API client.
func NewClient(url, token string) *Client {
	return &Client{
		url:    strings.TrimSuffix(url, "/"),
		client: &http.Client{},
		token:  token,
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

	req.Header.Set("Authorization", "token "+c.token)
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
			return resp, err
		}

		errMap := make(map[string]interface{})
		if err = json.Unmarshal(data, &errMap); err != nil {
			return resp, fmt.Errorf("unknown api error (code: %d): %s", resp.StatusCode, string(data))
		}
		return resp, errors.New(errMap["message"].(string))
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

func (c *Client) GetProjectGroup(ctx context.Context, projectGroupRef string) (*ProjectGroupResponse, *http.Response, error) {
	projectGroup := new(ProjectGroupResponse)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projectgroups/%s", url.PathEscape(projectGroupRef)), nil, jsonContent, nil, projectGroup)
	return projectGroup, resp, err
}

func (c *Client) GetProjectGroupSubgroups(ctx context.Context, projectGroupRef string) ([]*ProjectGroupResponse, *http.Response, error) {
	projectGroups := []*ProjectGroupResponse{}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projectgroups/%s/subgroups", url.PathEscape(projectGroupRef)), nil, jsonContent, nil, &projectGroups)
	return projectGroups, resp, err
}

func (c *Client) GetProjectGroupProjects(ctx context.Context, projectGroupRef string) ([]*ProjectResponse, *http.Response, error) {
	projects := []*ProjectResponse{}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projectgroups/%s/projects", url.PathEscape(projectGroupRef)), nil, jsonContent, nil, &projects)
	return projects, resp, err
}

func (c *Client) GetProject(ctx context.Context, projectRef string) (*ProjectResponse, *http.Response, error) {
	project := new(ProjectResponse)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projects/%s", url.PathEscape(projectRef)), nil, jsonContent, nil, project)
	return project, resp, err
}

func (c *Client) CreateProjectGroup(ctx context.Context, req *CreateProjectGroupRequest) (*ProjectResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}

	project := new(ProjectResponse)
	resp, err := c.getParsedResponse(ctx, "POST", "/projectgroups", nil, jsonContent, bytes.NewReader(reqj), project)
	return project, resp, err
}

func (c *Client) DeleteProjectGroup(ctx context.Context, projectGroupRef string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/projectgroups/%s", url.PathEscape(projectGroupRef)), nil, jsonContent, nil)
}

func (c *Client) CreateProject(ctx context.Context, req *CreateProjectRequest) (*ProjectResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}

	project := new(ProjectResponse)
	resp, err := c.getParsedResponse(ctx, "POST", "/projects", nil, jsonContent, bytes.NewReader(reqj), project)
	return project, resp, err
}

func (c *Client) CreateProjectGroupSecret(ctx context.Context, projectGroupRef string, req *CreateSecretRequest) (*SecretResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}

	secret := new(SecretResponse)
	resp, err := c.getParsedResponse(ctx, "POST", path.Join("/projectgroups", url.PathEscape(projectGroupRef), "secrets"), nil, jsonContent, bytes.NewReader(reqj), secret)
	return secret, resp, err
}

func (c *Client) DeleteProjectGroupSecret(ctx context.Context, projectGroupRef, secretName string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", path.Join("/projectgroups", url.PathEscape(projectGroupRef), "secrets", secretName), nil, jsonContent, nil)
}

func (c *Client) CreateProjectSecret(ctx context.Context, projectRef string, req *CreateSecretRequest) (*SecretResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}

	secret := new(SecretResponse)
	resp, err := c.getParsedResponse(ctx, "POST", path.Join("/projects", url.PathEscape(projectRef), "secrets"), nil, jsonContent, bytes.NewReader(reqj), secret)
	return secret, resp, err
}

func (c *Client) DeleteProjectSecret(ctx context.Context, projectRef, secretName string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", path.Join("/projects", url.PathEscape(projectRef), "secrets", secretName), nil, jsonContent, nil)
}

func (c *Client) CreateProjectGroupVariable(ctx context.Context, projectGroupRef string, req *CreateVariableRequest) (*VariableResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}

	variable := new(VariableResponse)
	resp, err := c.getParsedResponse(ctx, "POST", path.Join("/projectgroups", url.PathEscape(projectGroupRef), "variables"), nil, jsonContent, bytes.NewReader(reqj), variable)
	return variable, resp, err
}

func (c *Client) DeleteProjectGroupVariable(ctx context.Context, projectGroupRef, variableName string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", path.Join("/projectgroups", url.PathEscape(projectGroupRef), "variables", variableName), nil, jsonContent, nil)
}

func (c *Client) CreateProjectVariable(ctx context.Context, projectRef string, req *CreateVariableRequest) (*VariableResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}

	variable := new(VariableResponse)
	resp, err := c.getParsedResponse(ctx, "POST", path.Join("/projects", url.PathEscape(projectRef), "variables"), nil, jsonContent, bytes.NewReader(reqj), variable)
	return variable, resp, err
}

func (c *Client) DeleteProjectVariable(ctx context.Context, projectRef, variableName string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", path.Join("/projects", url.PathEscape(projectRef), "variables", variableName), nil, jsonContent, nil)
}

func (c *Client) DeleteProject(ctx context.Context, projectRef string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/projects/%s", url.PathEscape(projectRef)), nil, jsonContent, nil)
}

func (c *Client) ReconfigProject(ctx context.Context, projectRef string) (*http.Response, error) {
	return c.getResponse(ctx, "PUT", fmt.Sprintf("/projects/%s/reconfig", url.PathEscape(projectRef)), nil, jsonContent, nil)
}

func (c *Client) GetCurrentUser(ctx context.Context) (*UserResponse, *http.Response, error) {
	user := new(UserResponse)
	resp, err := c.getParsedResponse(ctx, "GET", "/user", nil, jsonContent, nil, user)
	return user, resp, err
}

func (c *Client) GetUser(ctx context.Context, userRef string) (*UserResponse, *http.Response, error) {
	user := new(UserResponse)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/users/%s", userRef), nil, jsonContent, nil, user)
	return user, resp, err
}

func (c *Client) GetUsers(ctx context.Context, start string, limit int, asc bool) ([]*UserResponse, *http.Response, error) {
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

	users := []*UserResponse{}
	resp, err := c.getParsedResponse(ctx, "GET", "/users", q, jsonContent, nil, &users)
	return users, resp, err
}

func (c *Client) CreateUser(ctx context.Context, req *CreateUserRequest) (*UserResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}

	user := new(UserResponse)
	resp, err := c.getParsedResponse(ctx, "POST", "/users", nil, jsonContent, bytes.NewReader(reqj), user)
	return user, resp, err
}

func (c *Client) DeleteUser(ctx context.Context, userRef string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/users/%s", userRef), nil, jsonContent, nil)
}

func (c *Client) CreateUserLA(ctx context.Context, userRef string, req *CreateUserLARequest) (*CreateUserLAResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}

	la := new(CreateUserLAResponse)
	resp, err := c.getParsedResponse(ctx, "POST", fmt.Sprintf("/users/%s/linkedaccounts", userRef), nil, jsonContent, bytes.NewReader(reqj), la)
	return la, resp, err
}

func (c *Client) DeleteUserLA(ctx context.Context, userRef, laID string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/users/%s/linkedaccounts/%s", userRef, laID), nil, jsonContent, nil)
}

func (c *Client) RegisterUser(ctx context.Context, req *RegisterUserRequest) (*RegisterUserResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}

	res := new(RegisterUserResponse)
	resp, err := c.getParsedResponse(ctx, "POST", "/register", nil, jsonContent, bytes.NewReader(reqj), res)
	return res, resp, err
}

func (c *Client) CreateUserToken(ctx context.Context, userRef string, req *CreateUserTokenRequest) (*CreateUserTokenResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}

	tresp := new(CreateUserTokenResponse)
	resp, err := c.getParsedResponse(ctx, "POST", fmt.Sprintf("/users/%s/tokens", userRef), nil, jsonContent, bytes.NewReader(reqj), tresp)
	return tresp, resp, err
}

func (c *Client) DeleteUserToken(ctx context.Context, userRef, tokenName string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/users/%s/tokens/%s", userRef, tokenName), nil, jsonContent, nil)
}

func (c *Client) GetRun(ctx context.Context, runID string) (*RunResponse, *http.Response, error) {
	run := new(RunResponse)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/runs/%s", runID), nil, jsonContent, nil, run)
	return run, resp, err
}

func (c *Client) GetRuns(ctx context.Context, phaseFilter, groups, runGroups []string, start string, limit int, asc bool) ([]*RunsResponse, *http.Response, error) {
	q := url.Values{}
	for _, phase := range phaseFilter {
		q.Add("phase", phase)
	}
	for _, group := range groups {
		q.Add("group", group)
	}
	for _, runGroup := range runGroups {
		q.Add("rungroup", runGroup)
	}
	if start != "" {
		q.Add("start", start)
	}
	if limit > 0 {
		q.Add("limit", strconv.Itoa(limit))
	}
	if asc {
		q.Add("asc", "")
	}

	getRunsResponse := []*RunsResponse{}
	resp, err := c.getParsedResponse(ctx, "GET", "/runs", q, jsonContent, nil, getRunsResponse)
	return getRunsResponse, resp, err
}

func (c *Client) GetRemoteSource(ctx context.Context, rsRef string) (*RemoteSourceResponse, *http.Response, error) {
	rs := new(RemoteSourceResponse)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/remotesources/%s", rsRef), nil, jsonContent, nil, rs)
	return rs, resp, err
}

func (c *Client) GetRemoteSources(ctx context.Context, start string, limit int, asc bool) ([]*RemoteSourceResponse, *http.Response, error) {
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

	rss := []*RemoteSourceResponse{}
	resp, err := c.getParsedResponse(ctx, "GET", "/remotesources", q, jsonContent, nil, &rss)
	return rss, resp, err
}

func (c *Client) CreateRemoteSource(ctx context.Context, req *CreateRemoteSourceRequest) (*RemoteSourceResponse, *http.Response, error) {
	rsj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}

	rs := new(RemoteSourceResponse)
	resp, err := c.getParsedResponse(ctx, "POST", "/remotesources", nil, jsonContent, bytes.NewReader(rsj), rs)
	return rs, resp, err
}

func (c *Client) UpdateRemoteSource(ctx context.Context, rsRef string, req *UpdateRemoteSourceRequest) (*RemoteSourceResponse, *http.Response, error) {
	rsj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}

	rs := new(RemoteSourceResponse)
	resp, err := c.getParsedResponse(ctx, "PUT", fmt.Sprintf("/remotesources/%s", rsRef), nil, jsonContent, bytes.NewReader(rsj), rs)
	return rs, resp, err
}

func (c *Client) DeleteRemoteSource(ctx context.Context, rsRef string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/remotesources/%s", rsRef), nil, jsonContent, nil)
}

func (c *Client) CreateOrg(ctx context.Context, req *CreateOrgRequest) (*OrgResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}

	org := new(OrgResponse)
	resp, err := c.getParsedResponse(ctx, "POST", "/orgs", nil, jsonContent, bytes.NewReader(reqj), org)
	return org, resp, err
}

func (c *Client) DeleteOrg(ctx context.Context, orgRef string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/orgs/%s", orgRef), nil, jsonContent, nil)
}

func (c *Client) AddOrgMember(ctx context.Context, orgRef, userRef string, role types.MemberRole) (*AddOrgMemberResponse, *http.Response, error) {
	req := &AddOrgMemberRequest{
		Role: role,
	}
	omj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}

	res := new(AddOrgMemberResponse)
	resp, err := c.getParsedResponse(ctx, "PUT", fmt.Sprintf("/orgs/%s/members/%s", orgRef, userRef), nil, jsonContent, bytes.NewReader(omj), res)
	return res, resp, err
}

func (c *Client) RemoveOrgMember(ctx context.Context, orgRef, userRef string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/orgs/%s/members/%s", orgRef, userRef), nil, jsonContent, nil)
}

func (c *Client) GetOrgMembers(ctx context.Context, orgRef string) (*OrgMembersResponse, *http.Response, error) {
	res := &OrgMembersResponse{}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/orgs/%s/members", orgRef), nil, jsonContent, nil, &res)
	return res, resp, err
}
