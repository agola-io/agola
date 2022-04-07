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

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/util"
	gwapitypes "agola.io/agola/services/gateway/api/types"
)

var jsonContent = http.Header{"Content-Type": []string{"application/json"}}

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
		return nil, errors.WithStack(err)
	}
	u.RawQuery = query.Encode()
	req, err := http.NewRequest(method, u.String(), ibody)
	req = req.WithContext(ctx)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	req.Header.Set("Authorization", "token "+c.token)
	for k, v := range header {
		req.Header[k] = v
	}

	res, err := c.client.Do(req)

	return res, errors.WithStack(err)
}

func (c *Client) getResponse(ctx context.Context, method, path string, query url.Values, header http.Header, ibody io.Reader) (*http.Response, error) {
	resp, err := c.doRequest(ctx, method, path, query, header, ibody)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if err := util.ErrFromRemote(resp); err != nil {
		return resp, errors.WithStack(err)
	}

	return resp, nil
}

func (c *Client) getParsedResponse(ctx context.Context, method, path string, query url.Values, header http.Header, ibody io.Reader, obj interface{}) (*http.Response, error) {
	resp, err := c.getResponse(ctx, method, path, query, header, ibody)
	if err != nil {
		return resp, errors.WithStack(err)
	}
	defer resp.Body.Close()

	d := json.NewDecoder(resp.Body)

	return resp, errors.WithStack(d.Decode(obj))
}

func (c *Client) GetProjectGroup(ctx context.Context, projectGroupRef string) (*gwapitypes.ProjectGroupResponse, *http.Response, error) {
	projectGroup := new(gwapitypes.ProjectGroupResponse)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projectgroups/%s", url.PathEscape(projectGroupRef)), nil, jsonContent, nil, projectGroup)
	return projectGroup, resp, errors.WithStack(err)
}

func (c *Client) GetProjectGroupSubgroups(ctx context.Context, projectGroupRef string) ([]*gwapitypes.ProjectGroupResponse, *http.Response, error) {
	projectGroups := []*gwapitypes.ProjectGroupResponse{}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projectgroups/%s/subgroups", url.PathEscape(projectGroupRef)), nil, jsonContent, nil, &projectGroups)
	return projectGroups, resp, errors.WithStack(err)
}

func (c *Client) GetProjectGroupProjects(ctx context.Context, projectGroupRef string) ([]*gwapitypes.ProjectResponse, *http.Response, error) {
	projects := []*gwapitypes.ProjectResponse{}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projectgroups/%s/projects", url.PathEscape(projectGroupRef)), nil, jsonContent, nil, &projects)
	return projects, resp, errors.WithStack(err)
}

func (c *Client) GetProject(ctx context.Context, projectRef string) (*gwapitypes.ProjectResponse, *http.Response, error) {
	project := new(gwapitypes.ProjectResponse)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projects/%s", url.PathEscape(projectRef)), nil, jsonContent, nil, project)
	return project, resp, errors.WithStack(err)
}

func (c *Client) CreateProjectGroup(ctx context.Context, req *gwapitypes.CreateProjectGroupRequest) (*gwapitypes.ProjectResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	projectGroup := new(gwapitypes.ProjectResponse)
	resp, err := c.getParsedResponse(ctx, "POST", "/projectgroups", nil, jsonContent, bytes.NewReader(reqj), projectGroup)
	return projectGroup, resp, errors.WithStack(err)
}

func (c *Client) UpdateProjectGroup(ctx context.Context, projectGroupRef string, req *gwapitypes.UpdateProjectGroupRequest) (*gwapitypes.ProjectResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	projectGroup := new(gwapitypes.ProjectResponse)
	resp, err := c.getParsedResponse(ctx, "PUT", path.Join("/projectgroups", url.PathEscape(projectGroupRef)), nil, jsonContent, bytes.NewReader(reqj), projectGroup)
	return projectGroup, resp, errors.WithStack(err)
}

func (c *Client) DeleteProjectGroup(ctx context.Context, projectGroupRef string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/projectgroups/%s", url.PathEscape(projectGroupRef)), nil, jsonContent, nil)
}

func (c *Client) CreateProject(ctx context.Context, req *gwapitypes.CreateProjectRequest) (*gwapitypes.ProjectResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	project := new(gwapitypes.ProjectResponse)
	resp, err := c.getParsedResponse(ctx, "POST", "/projects", nil, jsonContent, bytes.NewReader(reqj), project)
	return project, resp, errors.WithStack(err)
}

func (c *Client) UpdateProject(ctx context.Context, projectRef string, req *gwapitypes.UpdateProjectRequest) (*gwapitypes.ProjectResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	project := new(gwapitypes.ProjectResponse)
	resp, err := c.getParsedResponse(ctx, "PUT", path.Join("/projects", url.PathEscape(projectRef)), nil, jsonContent, bytes.NewReader(reqj), project)
	return project, resp, errors.WithStack(err)
}

func (c *Client) CreateProjectGroupSecret(ctx context.Context, projectGroupRef string, req *gwapitypes.CreateSecretRequest) (*gwapitypes.SecretResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	secret := new(gwapitypes.SecretResponse)
	resp, err := c.getParsedResponse(ctx, "POST", path.Join("/projectgroups", url.PathEscape(projectGroupRef), "secrets"), nil, jsonContent, bytes.NewReader(reqj), secret)
	return secret, resp, errors.WithStack(err)
}

func (c *Client) UpdateProjectGroupSecret(ctx context.Context, projectGroupRef, secretName string, req *gwapitypes.UpdateSecretRequest) (*gwapitypes.SecretResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	secret := new(gwapitypes.SecretResponse)
	resp, err := c.getParsedResponse(ctx, "PUT", path.Join("/projectgroups", url.PathEscape(projectGroupRef), "secrets", secretName), nil, jsonContent, bytes.NewReader(reqj), secret)
	return secret, resp, errors.WithStack(err)
}

func (c *Client) DeleteProjectGroupSecret(ctx context.Context, projectGroupRef, secretName string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", path.Join("/projectgroups", url.PathEscape(projectGroupRef), "secrets", secretName), nil, jsonContent, nil)
}

func (c *Client) GetProjectGroupSecrets(ctx context.Context, projectRef string, tree, removeoverridden bool) ([]*gwapitypes.SecretResponse, *http.Response, error) {
	secrets := []*gwapitypes.SecretResponse{}
	q := url.Values{}
	if tree {
		q.Add("tree", "")
	}
	if removeoverridden {
		q.Add("removeoverridden", "")
	}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projectgroups/%s/secrets", url.PathEscape(projectRef)), q, jsonContent, nil, &secrets)
	return secrets, resp, errors.WithStack(err)
}

func (c *Client) CreateProjectSecret(ctx context.Context, projectRef string, req *gwapitypes.CreateSecretRequest) (*gwapitypes.SecretResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	secret := new(gwapitypes.SecretResponse)
	resp, err := c.getParsedResponse(ctx, "POST", path.Join("/projects", url.PathEscape(projectRef), "secrets"), nil, jsonContent, bytes.NewReader(reqj), secret)
	return secret, resp, errors.WithStack(err)
}

func (c *Client) UpdateProjectSecret(ctx context.Context, projectRef, secretName string, req *gwapitypes.UpdateSecretRequest) (*gwapitypes.SecretResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	secret := new(gwapitypes.SecretResponse)
	resp, err := c.getParsedResponse(ctx, "PUT", path.Join("/projects", url.PathEscape(projectRef), "secrets", secretName), nil, jsonContent, bytes.NewReader(reqj), secret)
	return secret, resp, errors.WithStack(err)
}

func (c *Client) DeleteProjectSecret(ctx context.Context, projectRef, secretName string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", path.Join("/projects", url.PathEscape(projectRef), "secrets", secretName), nil, jsonContent, nil)
}

func (c *Client) GetProjectSecrets(ctx context.Context, projectRef string, tree, removeoverridden bool) ([]*gwapitypes.SecretResponse, *http.Response, error) {
	secrets := []*gwapitypes.SecretResponse{}
	q := url.Values{}
	if tree {
		q.Add("tree", "")
	}
	if removeoverridden {
		q.Add("removeoverridden", "")
	}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projects/%s/secrets", url.PathEscape(projectRef)), q, jsonContent, nil, &secrets)
	return secrets, resp, errors.WithStack(err)
}

func (c *Client) CreateProjectGroupVariable(ctx context.Context, projectGroupRef string, req *gwapitypes.CreateVariableRequest) (*gwapitypes.VariableResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	variable := new(gwapitypes.VariableResponse)
	resp, err := c.getParsedResponse(ctx, "POST", path.Join("/projectgroups", url.PathEscape(projectGroupRef), "variables"), nil, jsonContent, bytes.NewReader(reqj), variable)
	return variable, resp, errors.WithStack(err)
}

func (c *Client) UpdateProjectGroupVariable(ctx context.Context, projectGroupRef, variableName string, req *gwapitypes.UpdateVariableRequest) (*gwapitypes.VariableResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	variable := new(gwapitypes.VariableResponse)
	resp, err := c.getParsedResponse(ctx, "PUT", path.Join("/projectgroups", url.PathEscape(projectGroupRef), "variables", variableName), nil, jsonContent, bytes.NewReader(reqj), variable)
	return variable, resp, errors.WithStack(err)
}

func (c *Client) DeleteProjectGroupVariable(ctx context.Context, projectGroupRef, variableName string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", path.Join("/projectgroups", url.PathEscape(projectGroupRef), "variables", variableName), nil, jsonContent, nil)
}

func (c *Client) GetProjectGroupVariables(ctx context.Context, projectRef string, tree, removeoverridden bool) ([]*gwapitypes.VariableResponse, *http.Response, error) {
	variables := []*gwapitypes.VariableResponse{}
	q := url.Values{}
	if tree {
		q.Add("tree", "")
	}
	if removeoverridden {
		q.Add("removeoverridden", "")
	}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projectgroups/%s/variables", url.PathEscape(projectRef)), q, jsonContent, nil, &variables)
	return variables, resp, errors.WithStack(err)
}

func (c *Client) CreateProjectVariable(ctx context.Context, projectRef string, req *gwapitypes.CreateVariableRequest) (*gwapitypes.VariableResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	variable := new(gwapitypes.VariableResponse)
	resp, err := c.getParsedResponse(ctx, "POST", path.Join("/projects", url.PathEscape(projectRef), "variables"), nil, jsonContent, bytes.NewReader(reqj), variable)
	return variable, resp, errors.WithStack(err)
}

func (c *Client) UpdateProjectVariable(ctx context.Context, projectRef, variableName string, req *gwapitypes.UpdateVariableRequest) (*gwapitypes.VariableResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	variable := new(gwapitypes.VariableResponse)
	resp, err := c.getParsedResponse(ctx, "PUT", path.Join("/projects", url.PathEscape(projectRef), "variables", variableName), nil, jsonContent, bytes.NewReader(reqj), variable)
	return variable, resp, errors.WithStack(err)
}

func (c *Client) DeleteProjectVariable(ctx context.Context, projectRef, variableName string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", path.Join("/projects", url.PathEscape(projectRef), "variables", variableName), nil, jsonContent, nil)
}

func (c *Client) GetProjectVariables(ctx context.Context, projectRef string, tree, removeoverridden bool) ([]*gwapitypes.VariableResponse, *http.Response, error) {
	variables := []*gwapitypes.VariableResponse{}
	q := url.Values{}
	if tree {
		q.Add("tree", "")
	}
	if removeoverridden {
		q.Add("removeoverridden", "")
	}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projects/%s/variables", url.PathEscape(projectRef)), q, jsonContent, nil, &variables)
	return variables, resp, errors.WithStack(err)
}

func (c *Client) DeleteProject(ctx context.Context, projectRef string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/projects/%s", url.PathEscape(projectRef)), nil, jsonContent, nil)
}

func (c *Client) ProjectCreateRun(ctx context.Context, projectRef string, req *gwapitypes.ProjectCreateRunRequest) (*http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return c.getResponse(ctx, "POST", fmt.Sprintf("/projects/%s/createrun", url.PathEscape(projectRef)), nil, jsonContent, bytes.NewReader(reqj))
}

func (c *Client) ReconfigProject(ctx context.Context, projectRef string) (*http.Response, error) {
	return c.getResponse(ctx, "PUT", fmt.Sprintf("/projects/%s/reconfig", url.PathEscape(projectRef)), nil, jsonContent, nil)
}

func (c *Client) GetCurrentUser(ctx context.Context) (*gwapitypes.PrivateUserResponse, *http.Response, error) {
	user := new(gwapitypes.PrivateUserResponse)
	resp, err := c.getParsedResponse(ctx, "GET", "/user", nil, jsonContent, nil, user)
	return user, resp, errors.WithStack(err)
}

func (c *Client) GetUser(ctx context.Context, userRef string) (*gwapitypes.UserResponse, *http.Response, error) {
	user := new(gwapitypes.UserResponse)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/users/%s", userRef), nil, jsonContent, nil, user)
	return user, resp, errors.WithStack(err)
}

func (c *Client) GetUsers(ctx context.Context, start string, limit int, asc bool) ([]*gwapitypes.UserResponse, *http.Response, error) {
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

	users := []*gwapitypes.UserResponse{}
	resp, err := c.getParsedResponse(ctx, "GET", "/users", q, jsonContent, nil, &users)
	return users, resp, errors.WithStack(err)
}

func (c *Client) CreateUser(ctx context.Context, req *gwapitypes.CreateUserRequest) (*gwapitypes.UserResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	user := new(gwapitypes.UserResponse)
	resp, err := c.getParsedResponse(ctx, "POST", "/users", nil, jsonContent, bytes.NewReader(reqj), user)
	return user, resp, errors.WithStack(err)
}

func (c *Client) DeleteUser(ctx context.Context, userRef string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/users/%s", userRef), nil, jsonContent, nil)
}

func (c *Client) UserCreateRun(ctx context.Context, req *gwapitypes.UserCreateRunRequest) (*http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return c.getResponse(ctx, "POST", "/user/createrun", nil, jsonContent, bytes.NewReader(reqj))
}

func (c *Client) CreateUserLA(ctx context.Context, userRef string, req *gwapitypes.CreateUserLARequest) (*gwapitypes.CreateUserLAResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	la := new(gwapitypes.CreateUserLAResponse)
	resp, err := c.getParsedResponse(ctx, "POST", fmt.Sprintf("/users/%s/linkedaccounts", userRef), nil, jsonContent, bytes.NewReader(reqj), la)
	return la, resp, errors.WithStack(err)
}

func (c *Client) DeleteUserLA(ctx context.Context, userRef, laID string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/users/%s/linkedaccounts/%s", userRef, laID), nil, jsonContent, nil)
}

func (c *Client) RegisterUser(ctx context.Context, req *gwapitypes.RegisterUserRequest) (*gwapitypes.RegisterUserResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	res := new(gwapitypes.RegisterUserResponse)
	resp, err := c.getParsedResponse(ctx, "POST", "/auth/register", nil, jsonContent, bytes.NewReader(reqj), res)
	return res, resp, errors.WithStack(err)
}

func (c *Client) CreateUserToken(ctx context.Context, userRef string, req *gwapitypes.CreateUserTokenRequest) (*gwapitypes.CreateUserTokenResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	tresp := new(gwapitypes.CreateUserTokenResponse)
	resp, err := c.getParsedResponse(ctx, "POST", fmt.Sprintf("/users/%s/tokens", userRef), nil, jsonContent, bytes.NewReader(reqj), tresp)
	return tresp, resp, errors.WithStack(err)
}

func (c *Client) DeleteUserToken(ctx context.Context, userRef, tokenName string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/users/%s/tokens/%s", userRef, tokenName), nil, jsonContent, nil)
}

func (c *Client) GetProjectRun(ctx context.Context, projectRef string, runNumber uint64) (*gwapitypes.RunResponse, *http.Response, error) {
	return c.getRun(ctx, "projects", projectRef, runNumber)
}

func (c *Client) GetUserRun(ctx context.Context, userRef string, runNumber uint64) (*gwapitypes.RunResponse, *http.Response, error) {
	return c.getRun(ctx, "users", userRef, runNumber)
}

func (c *Client) getRun(ctx context.Context, groupType, groupRef string, runNumber uint64) (*gwapitypes.RunResponse, *http.Response, error) {
	run := new(gwapitypes.RunResponse)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/%s/%s/runs/%d", groupType, url.PathEscape(groupRef), runNumber), nil, jsonContent, nil, run)
	return run, resp, errors.WithStack(err)
}

func (c *Client) GetProjectRunTask(ctx context.Context, projectRef string, runNumber uint64, taskID string) (*gwapitypes.RunTaskResponse, *http.Response, error) {
	return c.getRunTask(ctx, "projects", projectRef, runNumber, taskID)
}

func (c *Client) GetUserRunTask(ctx context.Context, userRef string, runNumber uint64, taskID string) (*gwapitypes.RunTaskResponse, *http.Response, error) {
	return c.getRunTask(ctx, "users", userRef, runNumber, taskID)
}

func (c *Client) getRunTask(ctx context.Context, groupType, groupRef string, runNumber uint64, taskID string) (*gwapitypes.RunTaskResponse, *http.Response, error) {
	task := new(gwapitypes.RunTaskResponse)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/%s/%s/runs/%d/tasks/%s", groupType, url.PathEscape(groupRef), runNumber, taskID), nil, jsonContent, nil, task)
	return task, resp, errors.WithStack(err)
}

func (c *Client) GetProjectRuns(ctx context.Context, projectRef string, phaseFilter, resultFilter []string, start uint64, limit int, asc bool) ([]*gwapitypes.RunsResponse, *http.Response, error) {
	return c.getRuns(ctx, "projects", projectRef, phaseFilter, resultFilter, start, limit, asc)
}

func (c *Client) GetUserRuns(ctx context.Context, userRef string, phaseFilter, resultFilter []string, start uint64, limit int, asc bool) ([]*gwapitypes.RunsResponse, *http.Response, error) {
	return c.getRuns(ctx, "users", userRef, phaseFilter, resultFilter, start, limit, asc)
}

func (c *Client) getRuns(ctx context.Context, groupType, groupRef string, phaseFilter, resultFilter []string, start uint64, limit int, asc bool) ([]*gwapitypes.RunsResponse, *http.Response, error) {
	q := url.Values{}
	for _, phase := range phaseFilter {
		q.Add("phase", phase)
	}
	for _, result := range resultFilter {
		q.Add("result", result)
	}
	if start > 0 {
		q.Add("start", strconv.FormatUint(start, 10))
	}
	if limit > 0 {
		q.Add("limit", strconv.Itoa(limit))
	}
	if asc {
		q.Add("asc", "")
	}

	getRunsResponse := []*gwapitypes.RunsResponse{}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/%s/%s/runs", groupType, url.PathEscape(groupRef)), q, jsonContent, nil, &getRunsResponse)
	return getRunsResponse, resp, errors.WithStack(err)
}

func (c *Client) GetProjectLogs(ctx context.Context, projectRef string, runNumber uint64, taskID string, setup bool, step int, follow bool) (*http.Response, error) {
	return c.getLogs(ctx, "projects", projectRef, runNumber, taskID, setup, step, follow)
}

func (c *Client) GetUserLogs(ctx context.Context, userRef string, runNumber uint64, taskID string, setup bool, step int, follow bool) (*http.Response, error) {
	return c.getLogs(ctx, "users", userRef, runNumber, taskID, setup, step, follow)
}

func (c *Client) getLogs(ctx context.Context, groupType, groupRef string, runNumber uint64, taskID string, setup bool, step int, follow bool) (*http.Response, error) {
	q := url.Values{}
	if setup {
		q.Add("setup", "")
	} else {
		q.Add("step", strconv.Itoa(step))
	}
	if follow {
		q.Add("follow", "")
	}
	return c.getResponse(ctx, "GET", fmt.Sprintf("/%s/%s/runs/%d/tasks/%s/logs", groupType, url.PathEscape(groupRef), runNumber, taskID), q, nil, nil)
}

func (c *Client) DeleteProjectLogs(ctx context.Context, projectRef string, runNumber uint64, taskID string, setup bool, step int) (*http.Response, error) {
	return c.deleteLogs(ctx, "projects", projectRef, runNumber, taskID, setup, step)
}

func (c *Client) DeleteUserLogs(ctx context.Context, userRef string, runNumber uint64, taskID string, setup bool, step int) (*http.Response, error) {
	return c.deleteLogs(ctx, "users", userRef, runNumber, taskID, setup, step)
}

func (c *Client) deleteLogs(ctx context.Context, groupType, groupRef string, runNumber uint64, taskID string, setup bool, step int) (*http.Response, error) {
	q := url.Values{}
	if setup {
		q.Add("setup", "")
	} else {
		q.Add("step", strconv.Itoa(step))
	}

	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/%s/%s/runs/%d/tasks/%s/logs", groupType, url.PathEscape(groupRef), runNumber, taskID), q, nil, nil)
}

func (c *Client) GetRemoteSource(ctx context.Context, rsRef string) (*gwapitypes.RemoteSourceResponse, *http.Response, error) {
	rs := new(gwapitypes.RemoteSourceResponse)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/remotesources/%s", rsRef), nil, jsonContent, nil, rs)
	return rs, resp, errors.WithStack(err)
}

func (c *Client) GetRemoteSources(ctx context.Context, start string, limit int, asc bool) ([]*gwapitypes.RemoteSourceResponse, *http.Response, error) {
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

	rss := []*gwapitypes.RemoteSourceResponse{}
	resp, err := c.getParsedResponse(ctx, "GET", "/remotesources", q, jsonContent, nil, &rss)
	return rss, resp, errors.WithStack(err)
}

func (c *Client) CreateRemoteSource(ctx context.Context, req *gwapitypes.CreateRemoteSourceRequest) (*gwapitypes.RemoteSourceResponse, *http.Response, error) {
	rsj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	rs := new(gwapitypes.RemoteSourceResponse)
	resp, err := c.getParsedResponse(ctx, "POST", "/remotesources", nil, jsonContent, bytes.NewReader(rsj), rs)
	return rs, resp, errors.WithStack(err)
}

func (c *Client) UpdateRemoteSource(ctx context.Context, rsRef string, req *gwapitypes.UpdateRemoteSourceRequest) (*gwapitypes.RemoteSourceResponse, *http.Response, error) {
	rsj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	rs := new(gwapitypes.RemoteSourceResponse)
	resp, err := c.getParsedResponse(ctx, "PUT", fmt.Sprintf("/remotesources/%s", rsRef), nil, jsonContent, bytes.NewReader(rsj), rs)
	return rs, resp, errors.WithStack(err)
}

func (c *Client) DeleteRemoteSource(ctx context.Context, rsRef string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/remotesources/%s", rsRef), nil, jsonContent, nil)
}

func (c *Client) CreateOrg(ctx context.Context, req *gwapitypes.CreateOrgRequest) (*gwapitypes.OrgResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	org := new(gwapitypes.OrgResponse)
	resp, err := c.getParsedResponse(ctx, "POST", "/orgs", nil, jsonContent, bytes.NewReader(reqj), org)
	return org, resp, errors.WithStack(err)
}

func (c *Client) DeleteOrg(ctx context.Context, orgRef string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/orgs/%s", orgRef), nil, jsonContent, nil)
}

func (c *Client) AddOrgMember(ctx context.Context, orgRef, userRef string, role gwapitypes.MemberRole) (*gwapitypes.AddOrgMemberResponse, *http.Response, error) {
	req := &gwapitypes.AddOrgMemberRequest{
		Role: role,
	}
	omj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	res := new(gwapitypes.AddOrgMemberResponse)
	resp, err := c.getParsedResponse(ctx, "PUT", fmt.Sprintf("/orgs/%s/members/%s", orgRef, userRef), nil, jsonContent, bytes.NewReader(omj), res)
	return res, resp, errors.WithStack(err)
}

func (c *Client) RemoveOrgMember(ctx context.Context, orgRef, userRef string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/orgs/%s/members/%s", orgRef, userRef), nil, jsonContent, nil)
}

func (c *Client) GetOrgMembers(ctx context.Context, orgRef string) (*gwapitypes.OrgMembersResponse, *http.Response, error) {
	res := &gwapitypes.OrgMembersResponse{}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/orgs/%s/members", orgRef), nil, jsonContent, nil, &res)
	return res, resp, errors.WithStack(err)
}

func (c *Client) GetVersion(ctx context.Context) (*gwapitypes.VersionResponse, *http.Response, error) {
	res := &gwapitypes.VersionResponse{}
	resp, err := c.getParsedResponse(ctx, "GET", "/version", nil, jsonContent, nil, &res)
	return res, resp, errors.WithStack(err)
}

func (c *Client) GetUserOrgs(ctx context.Context) ([]*gwapitypes.UserOrgsResponse, *http.Response, error) {
	userOrgs := []*gwapitypes.UserOrgsResponse{}
	resp, err := c.getParsedResponse(ctx, "GET", "/user/orgs", nil, jsonContent, nil, &userOrgs)
	return userOrgs, resp, errors.WithStack(err)
}
