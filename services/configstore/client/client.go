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
	"strconv"
	"strings"

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	cstypes "agola.io/agola/services/configstore/types"
)

var jsonContent = http.Header{"Content-Type": []string{"application/json"}}

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
		return nil, errors.WithStack(err)
	}
	u.RawQuery = query.Encode()

	req, err := http.NewRequest(method, u.String(), ibody)
	req = req.WithContext(ctx)
	if err != nil {
		return nil, errors.WithStack(err)
	}
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

func (c *Client) GetProjectGroup(ctx context.Context, projectGroupRef string) (*csapitypes.ProjectGroup, *http.Response, error) {
	projectGroup := new(csapitypes.ProjectGroup)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projectgroups/%s", url.PathEscape(projectGroupRef)), nil, jsonContent, nil, projectGroup)
	return projectGroup, resp, errors.WithStack(err)
}

func (c *Client) GetProjectGroupSubgroups(ctx context.Context, projectGroupRef string) ([]*csapitypes.ProjectGroup, *http.Response, error) {
	projectGroups := []*csapitypes.ProjectGroup{}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projectgroups/%s/subgroups", url.PathEscape(projectGroupRef)), nil, jsonContent, nil, &projectGroups)
	return projectGroups, resp, errors.WithStack(err)
}

func (c *Client) GetProjectGroupProjects(ctx context.Context, projectGroupRef string) ([]*csapitypes.Project, *http.Response, error) {
	projects := []*csapitypes.Project{}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projectgroups/%s/projects", url.PathEscape(projectGroupRef)), nil, jsonContent, nil, &projects)
	return projects, resp, errors.WithStack(err)
}

func (c *Client) CreateProjectGroup(ctx context.Context, req *csapitypes.CreateUpdateProjectGroupRequest) (*csapitypes.ProjectGroup, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resProjectGroup := new(csapitypes.ProjectGroup)
	resp, err := c.getParsedResponse(ctx, "POST", "/projectgroups", nil, jsonContent, bytes.NewReader(reqj), resProjectGroup)
	return resProjectGroup, resp, errors.WithStack(err)
}

func (c *Client) UpdateProjectGroup(ctx context.Context, projectGroupRef string, req *csapitypes.CreateUpdateProjectGroupRequest) (*csapitypes.ProjectGroup, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resProjectGroup := new(csapitypes.ProjectGroup)
	resp, err := c.getParsedResponse(ctx, "PUT", fmt.Sprintf("/projectgroups/%s", url.PathEscape(projectGroupRef)), nil, jsonContent, bytes.NewReader(reqj), resProjectGroup)
	return resProjectGroup, resp, errors.WithStack(err)
}

func (c *Client) DeleteProjectGroup(ctx context.Context, projectGroupRef string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/projectgroups/%s", url.PathEscape(projectGroupRef)), nil, jsonContent, nil)
}

func (c *Client) GetProject(ctx context.Context, projectRef string) (*csapitypes.Project, *http.Response, error) {
	project := new(csapitypes.Project)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projects/%s", url.PathEscape(projectRef)), nil, jsonContent, nil, project)
	return project, resp, errors.WithStack(err)
}

func (c *Client) CreateProject(ctx context.Context, req *csapitypes.CreateUpdateProjectRequest) (*csapitypes.Project, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resProject := new(csapitypes.Project)
	resp, err := c.getParsedResponse(ctx, "POST", "/projects", nil, jsonContent, bytes.NewReader(reqj), resProject)
	return resProject, resp, errors.WithStack(err)
}

func (c *Client) UpdateProject(ctx context.Context, projectRef string, req *csapitypes.CreateUpdateProjectRequest) (*csapitypes.Project, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resProject := new(csapitypes.Project)
	resp, err := c.getParsedResponse(ctx, "PUT", fmt.Sprintf("/projects/%s", url.PathEscape(projectRef)), nil, jsonContent, bytes.NewReader(reqj), resProject)
	return resProject, resp, errors.WithStack(err)
}

func (c *Client) DeleteProject(ctx context.Context, projectRef string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/projects/%s", url.PathEscape(projectRef)), nil, jsonContent, nil)
}

func (c *Client) GetProjectGroupSecrets(ctx context.Context, projectGroupRef string, tree bool) ([]*csapitypes.Secret, *http.Response, error) {
	q := url.Values{}
	if tree {
		q.Add("tree", "")
	}

	secrets := []*csapitypes.Secret{}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projectgroups/%s/secrets", url.PathEscape(projectGroupRef)), q, jsonContent, nil, &secrets)
	return secrets, resp, errors.WithStack(err)
}

func (c *Client) GetProjectSecrets(ctx context.Context, projectRef string, tree bool) ([]*csapitypes.Secret, *http.Response, error) {
	q := url.Values{}
	if tree {
		q.Add("tree", "")
	}

	secrets := []*csapitypes.Secret{}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projects/%s/secrets", url.PathEscape(projectRef)), q, jsonContent, nil, &secrets)
	return secrets, resp, errors.WithStack(err)
}

func (c *Client) CreateProjectGroupSecret(ctx context.Context, projectGroupRef string, req *csapitypes.CreateUpdateSecretRequest) (*csapitypes.Secret, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resSecret := new(csapitypes.Secret)
	resp, err := c.getParsedResponse(ctx, "POST", fmt.Sprintf("/projectgroups/%s/secrets", url.PathEscape(projectGroupRef)), nil, jsonContent, bytes.NewReader(reqj), resSecret)
	return resSecret, resp, errors.WithStack(err)
}

func (c *Client) CreateProjectSecret(ctx context.Context, projectRef string, req *csapitypes.CreateUpdateSecretRequest) (*csapitypes.Secret, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resSecret := new(csapitypes.Secret)
	resp, err := c.getParsedResponse(ctx, "POST", fmt.Sprintf("/projects/%s/secrets", url.PathEscape(projectRef)), nil, jsonContent, bytes.NewReader(reqj), resSecret)
	return resSecret, resp, errors.WithStack(err)
}

func (c *Client) UpdateProjectGroupSecret(ctx context.Context, projectGroupRef, secretName string, req *csapitypes.CreateUpdateSecretRequest) (*csapitypes.Secret, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resSecret := new(csapitypes.Secret)
	resp, err := c.getParsedResponse(ctx, "PUT", fmt.Sprintf("/projectgroups/%s/secrets/%s", url.PathEscape(projectGroupRef), secretName), nil, jsonContent, bytes.NewReader(reqj), resSecret)
	return resSecret, resp, errors.WithStack(err)
}

func (c *Client) UpdateProjectSecret(ctx context.Context, projectRef, secretName string, req *csapitypes.CreateUpdateSecretRequest) (*csapitypes.Secret, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resSecret := new(csapitypes.Secret)
	resp, err := c.getParsedResponse(ctx, "PUT", fmt.Sprintf("/projects/%s/secrets/%s", url.PathEscape(projectRef), secretName), nil, jsonContent, bytes.NewReader(reqj), resSecret)
	return resSecret, resp, errors.WithStack(err)
}

func (c *Client) DeleteProjectGroupSecret(ctx context.Context, projectGroupRef, secretName string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/projectgroups/%s/secrets/%s", url.PathEscape(projectGroupRef), secretName), nil, jsonContent, nil)
}

func (c *Client) DeleteProjectSecret(ctx context.Context, projectRef, secretName string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/projects/%s/secrets/%s", url.PathEscape(projectRef), secretName), nil, jsonContent, nil)
}

func (c *Client) GetProjectGroupVariables(ctx context.Context, projectGroupRef string, tree bool) ([]*csapitypes.Variable, *http.Response, error) {
	q := url.Values{}
	if tree {
		q.Add("tree", "")
	}

	variables := []*csapitypes.Variable{}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projectgroups/%s/variables", url.PathEscape(projectGroupRef)), q, jsonContent, nil, &variables)
	return variables, resp, errors.WithStack(err)
}

func (c *Client) GetProjectVariables(ctx context.Context, projectRef string, tree bool) ([]*csapitypes.Variable, *http.Response, error) {
	q := url.Values{}
	if tree {
		q.Add("tree", "")
	}

	variables := []*csapitypes.Variable{}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/projects/%s/variables", url.PathEscape(projectRef)), q, jsonContent, nil, &variables)
	return variables, resp, errors.WithStack(err)
}

func (c *Client) CreateProjectGroupVariable(ctx context.Context, projectGroupRef string, req *csapitypes.CreateUpdateVariableRequest) (*csapitypes.Variable, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resVariable := new(csapitypes.Variable)
	resp, err := c.getParsedResponse(ctx, "POST", fmt.Sprintf("/projectgroups/%s/variables", url.PathEscape(projectGroupRef)), nil, jsonContent, bytes.NewReader(reqj), resVariable)
	return resVariable, resp, errors.WithStack(err)
}

func (c *Client) UpdateProjectGroupVariable(ctx context.Context, projectGroupRef, variableName string, req *csapitypes.CreateUpdateVariableRequest) (*csapitypes.Variable, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resVariable := new(csapitypes.Variable)
	resp, err := c.getParsedResponse(ctx, "PUT", fmt.Sprintf("/projectgroups/%s/variables/%s", url.PathEscape(projectGroupRef), variableName), nil, jsonContent, bytes.NewReader(reqj), resVariable)
	return resVariable, resp, errors.WithStack(err)
}

func (c *Client) CreateProjectVariable(ctx context.Context, projectRef string, req *csapitypes.CreateUpdateVariableRequest) (*csapitypes.Variable, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resVariable := new(csapitypes.Variable)
	resp, err := c.getParsedResponse(ctx, "POST", fmt.Sprintf("/projects/%s/variables", url.PathEscape(projectRef)), nil, jsonContent, bytes.NewReader(reqj), resVariable)
	return resVariable, resp, errors.WithStack(err)
}

func (c *Client) UpdateProjectVariable(ctx context.Context, projectRef, variableName string, req *csapitypes.CreateUpdateVariableRequest) (*csapitypes.Variable, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resVariable := new(csapitypes.Variable)
	resp, err := c.getParsedResponse(ctx, "PUT", fmt.Sprintf("/projects/%s/variables/%s", url.PathEscape(projectRef), variableName), nil, jsonContent, bytes.NewReader(reqj), resVariable)
	return resVariable, resp, errors.WithStack(err)
}

func (c *Client) DeleteProjectGroupVariable(ctx context.Context, projectGroupRef, variableName string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/projectgroups/%s/variables/%s", url.PathEscape(projectGroupRef), variableName), nil, jsonContent, nil)
}

func (c *Client) DeleteProjectVariable(ctx context.Context, projectRef, variableName string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/projects/%s/variables/%s", url.PathEscape(projectRef), variableName), nil, jsonContent, nil)
}

func (c *Client) GetUser(ctx context.Context, userRef string) (*cstypes.User, *http.Response, error) {
	user := new(cstypes.User)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/users/%s", userRef), nil, jsonContent, nil, user)
	return user, resp, errors.WithStack(err)
}

func (c *Client) GetUserByToken(ctx context.Context, token string) (*cstypes.User, *http.Response, error) {
	q := url.Values{}
	q.Add("query_type", "bytoken")
	q.Add("token", token)

	users := []*cstypes.User{}
	resp, err := c.getParsedResponse(ctx, "GET", "/users", q, jsonContent, nil, &users)
	if err != nil {
		return nil, resp, errors.WithStack(err)
	}
	return users[0], resp, errors.WithStack(err)
}

func (c *Client) GetUserByLinkedAccountRemoteUserAndSource(ctx context.Context, remoteUserID, remoteSourceID string) (*cstypes.User, *http.Response, error) {
	q := url.Values{}
	q.Add("query_type", "byremoteuser")
	q.Add("remoteuserid", remoteUserID)
	q.Add("remotesourceid", remoteSourceID)

	users := []*cstypes.User{}
	resp, err := c.getParsedResponse(ctx, "GET", "/users", q, jsonContent, nil, &users)
	if err != nil {
		return nil, resp, errors.WithStack(err)
	}
	return users[0], resp, errors.WithStack(err)
}

func (c *Client) GetUserByLinkedAccount(ctx context.Context, linkedAccountID string) (*cstypes.User, *http.Response, error) {
	q := url.Values{}
	q.Add("query_type", "bylinkedaccount")
	q.Add("linkedaccountid", linkedAccountID)

	users := []*cstypes.User{}
	resp, err := c.getParsedResponse(ctx, "GET", "/users", q, jsonContent, nil, &users)
	if err != nil {
		return nil, resp, errors.WithStack(err)
	}
	return users[0], resp, errors.WithStack(err)
}

func (c *Client) CreateUser(ctx context.Context, req *csapitypes.CreateUserRequest) (*cstypes.User, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	user := new(cstypes.User)
	resp, err := c.getParsedResponse(ctx, "POST", "/users", nil, jsonContent, bytes.NewReader(reqj), user)
	return user, resp, errors.WithStack(err)
}

func (c *Client) UpdateUser(ctx context.Context, userRef string, req *csapitypes.UpdateUserRequest) (*cstypes.User, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	user := new(cstypes.User)
	resp, err := c.getParsedResponse(ctx, "PUT", fmt.Sprintf("/users/%s", userRef), nil, jsonContent, bytes.NewReader(reqj), user)
	return user, resp, errors.WithStack(err)
}

func (c *Client) DeleteUser(ctx context.Context, userRef string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/users/%s", userRef), nil, jsonContent, nil)
}

func (c *Client) GetUsers(ctx context.Context, start string, limit int, asc bool) ([]*cstypes.User, *http.Response, error) {
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

	users := []*cstypes.User{}
	resp, err := c.getParsedResponse(ctx, "GET", "/users", q, jsonContent, nil, &users)
	return users, resp, errors.WithStack(err)
}

func (c *Client) GetUserLinkedAccounts(ctx context.Context, userRef string) ([]*cstypes.LinkedAccount, *http.Response, error) {
	linkedAccounts := []*cstypes.LinkedAccount{}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/users/%s/linkedaccounts", userRef), nil, jsonContent, nil, &linkedAccounts)
	return linkedAccounts, resp, errors.WithStack(err)
}

func (c *Client) CreateUserLA(ctx context.Context, userRef string, req *csapitypes.CreateUserLARequest) (*cstypes.LinkedAccount, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	la := new(cstypes.LinkedAccount)
	resp, err := c.getParsedResponse(ctx, "POST", fmt.Sprintf("/users/%s/linkedaccounts", userRef), nil, jsonContent, bytes.NewReader(reqj), la)
	return la, resp, errors.WithStack(err)
}

func (c *Client) DeleteUserLA(ctx context.Context, userRef, laID string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/users/%s/linkedaccounts/%s", userRef, laID), nil, jsonContent, nil)
}

func (c *Client) UpdateUserLA(ctx context.Context, userRef, laID string, req *csapitypes.UpdateUserLARequest) (*cstypes.LinkedAccount, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	la := new(cstypes.LinkedAccount)
	resp, err := c.getParsedResponse(ctx, "PUT", fmt.Sprintf("/users/%s/linkedaccounts/%s", userRef, laID), nil, jsonContent, bytes.NewReader(reqj), la)
	return la, resp, errors.WithStack(err)
}

func (c *Client) GetUserTokens(ctx context.Context, userRef string) ([]*cstypes.UserToken, *http.Response, error) {
	tokens := []*cstypes.UserToken{}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/users/%s/tokens", userRef), nil, jsonContent, nil, &tokens)
	return tokens, resp, errors.WithStack(err)
}

func (c *Client) CreateUserToken(ctx context.Context, userRef string, req *csapitypes.CreateUserTokenRequest) (*csapitypes.CreateUserTokenResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	tresp := new(csapitypes.CreateUserTokenResponse)
	resp, err := c.getParsedResponse(ctx, "POST", fmt.Sprintf("/users/%s/tokens", userRef), nil, jsonContent, bytes.NewReader(reqj), tresp)
	return tresp, resp, errors.WithStack(err)
}

func (c *Client) DeleteUserToken(ctx context.Context, userRef, tokenName string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/users/%s/tokens/%s", userRef, tokenName), nil, jsonContent, nil)
}

func (c *Client) GetUserOrgs(ctx context.Context, userRef string) ([]*csapitypes.UserOrgsResponse, *http.Response, error) {
	userOrgs := []*csapitypes.UserOrgsResponse{}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/users/%s/orgs", userRef), nil, jsonContent, nil, &userOrgs)
	return userOrgs, resp, errors.WithStack(err)
}

func (c *Client) GetRemoteSource(ctx context.Context, rsRef string) (*cstypes.RemoteSource, *http.Response, error) {
	rs := new(cstypes.RemoteSource)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/remotesources/%s", rsRef), nil, jsonContent, nil, rs)
	return rs, resp, errors.WithStack(err)
}

func (c *Client) GetRemoteSources(ctx context.Context, start string, limit int, asc bool) ([]*cstypes.RemoteSource, *http.Response, error) {
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

	rss := []*cstypes.RemoteSource{}
	resp, err := c.getParsedResponse(ctx, "GET", "/remotesources", q, jsonContent, nil, &rss)
	return rss, resp, errors.WithStack(err)
}

func (c *Client) CreateRemoteSource(ctx context.Context, req *csapitypes.CreateUpdateRemoteSourceRequest) (*cstypes.RemoteSource, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	rs := new(cstypes.RemoteSource)
	resp, err := c.getParsedResponse(ctx, "POST", "/remotesources", nil, jsonContent, bytes.NewReader(reqj), rs)
	return rs, resp, errors.WithStack(err)
}

func (c *Client) UpdateRemoteSource(ctx context.Context, remoteSourceRef string, req *csapitypes.CreateUpdateRemoteSourceRequest) (*cstypes.RemoteSource, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resRemoteSource := new(cstypes.RemoteSource)
	resp, err := c.getParsedResponse(ctx, "PUT", fmt.Sprintf("/remotesources/%s", url.PathEscape(remoteSourceRef)), nil, jsonContent, bytes.NewReader(reqj), resRemoteSource)
	return resRemoteSource, resp, errors.WithStack(err)
}

func (c *Client) DeleteRemoteSource(ctx context.Context, rsRef string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/remotesources/%s", rsRef), nil, jsonContent, nil)
}

func (c *Client) CreateOrg(ctx context.Context, req *csapitypes.CreateOrgRequest) (*cstypes.Organization, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	org := new(cstypes.Organization)
	resp, err := c.getParsedResponse(ctx, "POST", "/orgs", nil, jsonContent, bytes.NewReader(reqj), org)
	return org, resp, errors.WithStack(err)
}

func (c *Client) DeleteOrg(ctx context.Context, orgRef string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/orgs/%s", orgRef), nil, jsonContent, nil)
}

func (c *Client) AddOrgMember(ctx context.Context, orgRef, userRef string, role cstypes.MemberRole) (*cstypes.OrganizationMember, *http.Response, error) {
	req := &csapitypes.AddOrgMemberRequest{
		Role: role,
	}
	omj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	orgmember := new(cstypes.OrganizationMember)
	resp, err := c.getParsedResponse(ctx, "PUT", fmt.Sprintf("/orgs/%s/members/%s", orgRef, userRef), nil, jsonContent, bytes.NewReader(omj), orgmember)
	return orgmember, resp, errors.WithStack(err)
}

func (c *Client) RemoveOrgMember(ctx context.Context, orgRef, userRef string) (*http.Response, error) {
	return c.getResponse(ctx, "DELETE", fmt.Sprintf("/orgs/%s/members/%s", orgRef, userRef), nil, jsonContent, nil)
}

func (c *Client) GetOrgs(ctx context.Context, start string, limit int, asc bool) ([]*cstypes.Organization, *http.Response, error) {
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

	orgs := []*cstypes.Organization{}
	resp, err := c.getParsedResponse(ctx, "GET", "/orgs", q, jsonContent, nil, &orgs)
	return orgs, resp, errors.WithStack(err)
}

func (c *Client) GetOrg(ctx context.Context, orgRef string) (*cstypes.Organization, *http.Response, error) {
	org := new(cstypes.Organization)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/orgs/%s", orgRef), nil, jsonContent, nil, org)
	return org, resp, errors.WithStack(err)
}

func (c *Client) GetOrgMembers(ctx context.Context, orgRef string) ([]*csapitypes.OrgMemberResponse, *http.Response, error) {
	orgMembers := []*csapitypes.OrgMemberResponse{}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/orgs/%s/members", orgRef), nil, jsonContent, nil, &orgMembers)
	return orgMembers, resp, errors.WithStack(err)
}
