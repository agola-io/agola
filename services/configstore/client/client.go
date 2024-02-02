// Copyright 2023 Sorint.lab
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

	"github.com/sorintlab/errors"

	"agola.io/agola/internal/util"
	"agola.io/agola/services/common"
	csapitypes "agola.io/agola/services/configstore/api/types"
	cstypes "agola.io/agola/services/configstore/types"
)

const (
	agolaHasMoreHeader = "X-Agola-HasMore"
)

type ListOptions struct {
	Limit         int
	SortDirection cstypes.SortDirection
}

func (o *ListOptions) Add(q url.Values) {
	if o == nil {
		return
	}

	if o.Limit != 0 {
		q.Add("limit", strconv.Itoa(o.Limit))
	}

	switch o.SortDirection {
	case cstypes.SortDirectionDesc:
		q.Add("sortdirection", "desc")
	case cstypes.SortDirectionAsc:
		q.Add("sortdirection", "asc")
	}
}

type Response struct {
	*http.Response

	HasMore bool
}

type Client struct {
	*common.Client
}

// NewClient initializes and returns a API client.
func NewClient(url, token string) *Client {
	c := common.NewClient(url+"/api/v1alpha", token)
	return &Client{c}
}

func (c *Client) GetResponse(ctx context.Context, method, path string, query url.Values, contentLength int64, header http.Header, ibody io.Reader) (*Response, error) {
	cresp, err := c.Client.DoRequest(ctx, method, path, query, contentLength, header, ibody)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	resp := &Response{Response: cresp}

	if err := util.ErrFromRemote(resp.Response); err != nil {
		return resp, errors.WithStack(err)
	}

	hasMore := false
	hasMoreValue := resp.Header.Get(agolaHasMoreHeader)
	if hasMoreValue != "" {
		hasMore, err = strconv.ParseBool(hasMoreValue)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	resp.HasMore = hasMore

	return resp, nil
}

func (c *Client) GetParsedResponse(ctx context.Context, method, path string, query url.Values, header http.Header, ibody io.Reader, obj interface{}) (*Response, error) {
	resp, err := c.GetResponse(ctx, method, path, query, -1, header, ibody)
	if err != nil {
		return resp, errors.WithStack(err)
	}
	defer resp.Body.Close()

	d := json.NewDecoder(resp.Body)

	return resp, errors.WithStack(d.Decode(obj))
}

func (c *Client) GetProjectGroup(ctx context.Context, projectGroupRef string) (*csapitypes.ProjectGroup, *Response, error) {
	projectGroup := new(csapitypes.ProjectGroup)
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/projectgroups/%s", url.PathEscape(projectGroupRef)), nil, common.JSONContent, nil, projectGroup)
	return projectGroup, resp, errors.WithStack(err)
}

func (c *Client) GetProjectGroupSubgroups(ctx context.Context, projectGroupRef string) ([]*csapitypes.ProjectGroup, *Response, error) {
	projectGroups := []*csapitypes.ProjectGroup{}
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/projectgroups/%s/subgroups", url.PathEscape(projectGroupRef)), nil, common.JSONContent, nil, &projectGroups)
	return projectGroups, resp, errors.WithStack(err)
}

func (c *Client) GetProjectGroupProjects(ctx context.Context, projectGroupRef string) ([]*csapitypes.Project, *Response, error) {
	projects := []*csapitypes.Project{}
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/projectgroups/%s/projects", url.PathEscape(projectGroupRef)), nil, common.JSONContent, nil, &projects)
	return projects, resp, errors.WithStack(err)
}

func (c *Client) CreateProjectGroup(ctx context.Context, req *csapitypes.CreateUpdateProjectGroupRequest) (*csapitypes.ProjectGroup, *Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resProjectGroup := new(csapitypes.ProjectGroup)
	resp, err := c.GetParsedResponse(ctx, "POST", "/projectgroups", nil, common.JSONContent, bytes.NewReader(reqj), resProjectGroup)
	return resProjectGroup, resp, errors.WithStack(err)
}

func (c *Client) UpdateProjectGroup(ctx context.Context, projectGroupRef string, req *csapitypes.CreateUpdateProjectGroupRequest) (*csapitypes.ProjectGroup, *Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resProjectGroup := new(csapitypes.ProjectGroup)
	resp, err := c.GetParsedResponse(ctx, "PUT", fmt.Sprintf("/projectgroups/%s", url.PathEscape(projectGroupRef)), nil, common.JSONContent, bytes.NewReader(reqj), resProjectGroup)
	return resProjectGroup, resp, errors.WithStack(err)
}

func (c *Client) DeleteProjectGroup(ctx context.Context, projectGroupRef string) (*Response, error) {
	resp, err := c.GetResponse(ctx, "DELETE", fmt.Sprintf("/projectgroups/%s", url.PathEscape(projectGroupRef)), nil, -1, common.JSONContent, nil)
	return resp, errors.WithStack(err)
}

func (c *Client) GetProject(ctx context.Context, projectRef string) (*csapitypes.Project, *Response, error) {
	project := new(csapitypes.Project)
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/projects/%s", url.PathEscape(projectRef)), nil, common.JSONContent, nil, project)
	return project, resp, errors.WithStack(err)
}

func (c *Client) CreateProject(ctx context.Context, req *csapitypes.CreateUpdateProjectRequest) (*csapitypes.Project, *Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resProject := new(csapitypes.Project)
	resp, err := c.GetParsedResponse(ctx, "POST", "/projects", nil, common.JSONContent, bytes.NewReader(reqj), resProject)
	return resProject, resp, errors.WithStack(err)
}

func (c *Client) UpdateProject(ctx context.Context, projectRef string, req *csapitypes.CreateUpdateProjectRequest) (*csapitypes.Project, *Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resProject := new(csapitypes.Project)
	resp, err := c.GetParsedResponse(ctx, "PUT", fmt.Sprintf("/projects/%s", url.PathEscape(projectRef)), nil, common.JSONContent, bytes.NewReader(reqj), resProject)
	return resProject, resp, errors.WithStack(err)
}

func (c *Client) DeleteProject(ctx context.Context, projectRef string) (*Response, error) {
	resp, err := c.GetResponse(ctx, "DELETE", fmt.Sprintf("/projects/%s", url.PathEscape(projectRef)), nil, -1, common.JSONContent, nil)
	return resp, errors.WithStack(err)
}

func (c *Client) GetProjectGroupSecrets(ctx context.Context, projectGroupRef string, tree bool) ([]*csapitypes.Secret, *Response, error) {
	q := url.Values{}
	if tree {
		q.Add("tree", "")
	}

	secrets := []*csapitypes.Secret{}
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/projectgroups/%s/secrets", url.PathEscape(projectGroupRef)), q, common.JSONContent, nil, &secrets)
	return secrets, resp, errors.WithStack(err)
}

func (c *Client) GetProjectSecrets(ctx context.Context, projectRef string, tree bool) ([]*csapitypes.Secret, *Response, error) {
	q := url.Values{}
	if tree {
		q.Add("tree", "")
	}

	secrets := []*csapitypes.Secret{}
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/projects/%s/secrets", url.PathEscape(projectRef)), q, common.JSONContent, nil, &secrets)
	return secrets, resp, errors.WithStack(err)
}

func (c *Client) CreateProjectGroupSecret(ctx context.Context, projectGroupRef string, req *csapitypes.CreateUpdateSecretRequest) (*csapitypes.Secret, *Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resSecret := new(csapitypes.Secret)
	resp, err := c.GetParsedResponse(ctx, "POST", fmt.Sprintf("/projectgroups/%s/secrets", url.PathEscape(projectGroupRef)), nil, common.JSONContent, bytes.NewReader(reqj), resSecret)
	return resSecret, resp, errors.WithStack(err)
}

func (c *Client) CreateProjectSecret(ctx context.Context, projectRef string, req *csapitypes.CreateUpdateSecretRequest) (*csapitypes.Secret, *Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resSecret := new(csapitypes.Secret)
	resp, err := c.GetParsedResponse(ctx, "POST", fmt.Sprintf("/projects/%s/secrets", url.PathEscape(projectRef)), nil, common.JSONContent, bytes.NewReader(reqj), resSecret)
	return resSecret, resp, errors.WithStack(err)
}

func (c *Client) UpdateProjectGroupSecret(ctx context.Context, projectGroupRef, secretName string, req *csapitypes.CreateUpdateSecretRequest) (*csapitypes.Secret, *Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resSecret := new(csapitypes.Secret)
	resp, err := c.GetParsedResponse(ctx, "PUT", fmt.Sprintf("/projectgroups/%s/secrets/%s", url.PathEscape(projectGroupRef), secretName), nil, common.JSONContent, bytes.NewReader(reqj), resSecret)
	return resSecret, resp, errors.WithStack(err)
}

func (c *Client) UpdateProjectSecret(ctx context.Context, projectRef, secretName string, req *csapitypes.CreateUpdateSecretRequest) (*csapitypes.Secret, *Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resSecret := new(csapitypes.Secret)
	resp, err := c.GetParsedResponse(ctx, "PUT", fmt.Sprintf("/projects/%s/secrets/%s", url.PathEscape(projectRef), secretName), nil, common.JSONContent, bytes.NewReader(reqj), resSecret)
	return resSecret, resp, errors.WithStack(err)
}

func (c *Client) DeleteProjectGroupSecret(ctx context.Context, projectGroupRef, secretName string) (*Response, error) {
	resp, err := c.GetResponse(ctx, "DELETE", fmt.Sprintf("/projectgroups/%s/secrets/%s", url.PathEscape(projectGroupRef), secretName), nil, -1, common.JSONContent, nil)
	return resp, errors.WithStack(err)
}

func (c *Client) DeleteProjectSecret(ctx context.Context, projectRef, secretName string) (*Response, error) {
	resp, err := c.GetResponse(ctx, "DELETE", fmt.Sprintf("/projects/%s/secrets/%s", url.PathEscape(projectRef), secretName), nil, -1, common.JSONContent, nil)
	return resp, errors.WithStack(err)
}

func (c *Client) GetProjectGroupVariables(ctx context.Context, projectGroupRef string, tree bool) ([]*csapitypes.Variable, *Response, error) {
	q := url.Values{}
	if tree {
		q.Add("tree", "")
	}

	variables := []*csapitypes.Variable{}
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/projectgroups/%s/variables", url.PathEscape(projectGroupRef)), q, common.JSONContent, nil, &variables)
	return variables, resp, errors.WithStack(err)
}

func (c *Client) GetProjectVariables(ctx context.Context, projectRef string, tree bool) ([]*csapitypes.Variable, *Response, error) {
	q := url.Values{}
	if tree {
		q.Add("tree", "")
	}

	variables := []*csapitypes.Variable{}
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/projects/%s/variables", url.PathEscape(projectRef)), q, common.JSONContent, nil, &variables)
	return variables, resp, errors.WithStack(err)
}

func (c *Client) CreateProjectGroupVariable(ctx context.Context, projectGroupRef string, req *csapitypes.CreateUpdateVariableRequest) (*csapitypes.Variable, *Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resVariable := new(csapitypes.Variable)
	resp, err := c.GetParsedResponse(ctx, "POST", fmt.Sprintf("/projectgroups/%s/variables", url.PathEscape(projectGroupRef)), nil, common.JSONContent, bytes.NewReader(reqj), resVariable)
	return resVariable, resp, errors.WithStack(err)
}

func (c *Client) UpdateProjectGroupVariable(ctx context.Context, projectGroupRef, variableName string, req *csapitypes.CreateUpdateVariableRequest) (*csapitypes.Variable, *Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resVariable := new(csapitypes.Variable)
	resp, err := c.GetParsedResponse(ctx, "PUT", fmt.Sprintf("/projectgroups/%s/variables/%s", url.PathEscape(projectGroupRef), variableName), nil, common.JSONContent, bytes.NewReader(reqj), resVariable)
	return resVariable, resp, errors.WithStack(err)
}

func (c *Client) CreateProjectVariable(ctx context.Context, projectRef string, req *csapitypes.CreateUpdateVariableRequest) (*csapitypes.Variable, *Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resVariable := new(csapitypes.Variable)
	resp, err := c.GetParsedResponse(ctx, "POST", fmt.Sprintf("/projects/%s/variables", url.PathEscape(projectRef)), nil, common.JSONContent, bytes.NewReader(reqj), resVariable)
	return resVariable, resp, errors.WithStack(err)
}

func (c *Client) UpdateProjectVariable(ctx context.Context, projectRef, variableName string, req *csapitypes.CreateUpdateVariableRequest) (*csapitypes.Variable, *Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resVariable := new(csapitypes.Variable)
	resp, err := c.GetParsedResponse(ctx, "PUT", fmt.Sprintf("/projects/%s/variables/%s", url.PathEscape(projectRef), variableName), nil, common.JSONContent, bytes.NewReader(reqj), resVariable)
	return resVariable, resp, errors.WithStack(err)
}

func (c *Client) DeleteProjectGroupVariable(ctx context.Context, projectGroupRef, variableName string) (*Response, error) {
	resp, err := c.GetResponse(ctx, "DELETE", fmt.Sprintf("/projectgroups/%s/variables/%s", url.PathEscape(projectGroupRef), variableName), nil, -1, common.JSONContent, nil)
	return resp, errors.WithStack(err)
}

func (c *Client) DeleteProjectVariable(ctx context.Context, projectRef, variableName string) (*Response, error) {
	resp, err := c.GetResponse(ctx, "DELETE", fmt.Sprintf("/projects/%s/variables/%s", url.PathEscape(projectRef), variableName), nil, -1, common.JSONContent, nil)
	return resp, errors.WithStack(err)
}

func (c *Client) GetUser(ctx context.Context, userRef string) (*cstypes.User, *Response, error) {
	user := new(cstypes.User)
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/users/%s", userRef), nil, common.JSONContent, nil, user)
	return user, resp, errors.WithStack(err)
}

func (c *Client) GetUserByToken(ctx context.Context, token string) (*cstypes.User, *Response, error) {
	q := url.Values{}
	q.Add("query_type", "bytoken")
	q.Add("token", token)

	users := []*cstypes.User{}
	resp, err := c.GetParsedResponse(ctx, "GET", "/users", q, common.JSONContent, nil, &users)
	if err != nil {
		return nil, resp, errors.WithStack(err)
	}
	return users[0], resp, errors.WithStack(err)
}

func (c *Client) GetUserByLinkedAccountRemoteUserAndSource(ctx context.Context, remoteUserID, remoteSourceID string) (*cstypes.User, *Response, error) {
	q := url.Values{}
	q.Add("query_type", "byremoteuser")
	q.Add("remoteuserid", remoteUserID)
	q.Add("remotesourceid", remoteSourceID)

	users := []*cstypes.User{}
	resp, err := c.GetParsedResponse(ctx, "GET", "/users", q, common.JSONContent, nil, &users)
	if err != nil {
		return nil, resp, errors.WithStack(err)
	}
	return users[0], resp, errors.WithStack(err)
}

func (c *Client) GetUserByLinkedAccount(ctx context.Context, linkedAccountID string) (*cstypes.User, *Response, error) {
	q := url.Values{}
	q.Add("query_type", "bylinkedaccount")
	q.Add("linkedaccountid", linkedAccountID)

	users := []*cstypes.User{}
	resp, err := c.GetParsedResponse(ctx, "GET", "/users", q, common.JSONContent, nil, &users)
	if err != nil {
		return nil, resp, errors.WithStack(err)
	}
	return users[0], resp, errors.WithStack(err)
}

func (c *Client) CreateUser(ctx context.Context, req *csapitypes.CreateUserRequest) (*cstypes.User, *Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	user := new(cstypes.User)
	resp, err := c.GetParsedResponse(ctx, "POST", "/users", nil, common.JSONContent, bytes.NewReader(reqj), user)
	return user, resp, errors.WithStack(err)
}

func (c *Client) UpdateUser(ctx context.Context, userRef string, req *csapitypes.UpdateUserRequest) (*cstypes.User, *Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	user := new(cstypes.User)
	resp, err := c.GetParsedResponse(ctx, "PUT", fmt.Sprintf("/users/%s", userRef), nil, common.JSONContent, bytes.NewReader(reqj), user)
	return user, resp, errors.WithStack(err)
}

func (c *Client) DeleteUser(ctx context.Context, userRef string) (*Response, error) {
	resp, err := c.GetResponse(ctx, "DELETE", fmt.Sprintf("/users/%s", userRef), nil, -1, common.JSONContent, nil)
	return resp, errors.WithStack(err)
}

type GetUsersOptions struct {
	*ListOptions

	StartUserName string
}

func (o *GetUsersOptions) Add(q url.Values) {
	if o == nil {
		return
	}

	o.ListOptions.Add(q)

	if o.StartUserName != "" {
		q.Add("startusername", o.StartUserName)
	}
}

func (c *Client) GetUsers(ctx context.Context, opts *GetUsersOptions) ([]*cstypes.User, *Response, error) {
	q := url.Values{}
	opts.Add(q)

	users := []*cstypes.User{}
	resp, err := c.GetParsedResponse(ctx, "GET", "/users", q, common.JSONContent, nil, &users)
	return users, resp, errors.WithStack(err)
}

func (c *Client) GetUserLinkedAccounts(ctx context.Context, userRef string) ([]*cstypes.LinkedAccount, *Response, error) {
	linkedAccounts := []*cstypes.LinkedAccount{}
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/users/%s/linkedaccounts", userRef), nil, common.JSONContent, nil, &linkedAccounts)
	return linkedAccounts, resp, errors.WithStack(err)
}

func (c *Client) CreateUserLA(ctx context.Context, userRef string, req *csapitypes.CreateUserLARequest) (*cstypes.LinkedAccount, *Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	la := new(cstypes.LinkedAccount)
	resp, err := c.GetParsedResponse(ctx, "POST", fmt.Sprintf("/users/%s/linkedaccounts", userRef), nil, common.JSONContent, bytes.NewReader(reqj), la)
	return la, resp, errors.WithStack(err)
}

func (c *Client) DeleteUserLA(ctx context.Context, userRef, laID string) (*Response, error) {
	resp, err := c.GetResponse(ctx, "DELETE", fmt.Sprintf("/users/%s/linkedaccounts/%s", userRef, laID), nil, -1, common.JSONContent, nil)
	return resp, errors.WithStack(err)
}

func (c *Client) UpdateUserLA(ctx context.Context, userRef, laID string, req *csapitypes.UpdateUserLARequest) (*cstypes.LinkedAccount, *Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	la := new(cstypes.LinkedAccount)
	resp, err := c.GetParsedResponse(ctx, "PUT", fmt.Sprintf("/users/%s/linkedaccounts/%s", userRef, laID), nil, common.JSONContent, bytes.NewReader(reqj), la)
	return la, resp, errors.WithStack(err)
}

func (c *Client) GetUserTokens(ctx context.Context, userRef string) ([]*cstypes.UserToken, *Response, error) {
	tokens := []*cstypes.UserToken{}
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/users/%s/tokens", userRef), nil, common.JSONContent, nil, &tokens)
	return tokens, resp, errors.WithStack(err)
}

func (c *Client) CreateUserToken(ctx context.Context, userRef string, req *csapitypes.CreateUserTokenRequest) (*csapitypes.CreateUserTokenResponse, *Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	tresp := new(csapitypes.CreateUserTokenResponse)
	resp, err := c.GetParsedResponse(ctx, "POST", fmt.Sprintf("/users/%s/tokens", userRef), nil, common.JSONContent, bytes.NewReader(reqj), tresp)
	return tresp, resp, errors.WithStack(err)
}

func (c *Client) DeleteUserToken(ctx context.Context, userRef, tokenName string) (*Response, error) {
	resp, err := c.GetResponse(ctx, "DELETE", fmt.Sprintf("/users/%s/tokens/%s", userRef, tokenName), nil, -1, common.JSONContent, nil)
	return resp, errors.WithStack(err)
}

func (c *Client) GetUserOrg(ctx context.Context, userRef, orgRef string) (*csapitypes.UserOrgResponse, *Response, error) {
	userOrg := new(csapitypes.UserOrgResponse)
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/users/%s/orgs/%s", userRef, orgRef), nil, common.JSONContent, nil, &userOrg)
	return userOrg, resp, errors.WithStack(err)
}

type GetUserOrgsOptions struct {
	*ListOptions

	StartOrgName string
}

func (o *GetUserOrgsOptions) Add(q url.Values) {
	o.ListOptions.Add(q)

	if o.StartOrgName != "" {
		q.Add("startorgname", o.StartOrgName)
	}
}

func (c *Client) GetUserOrgs(ctx context.Context, userRef string, opts *GetUserOrgsOptions) ([]*csapitypes.UserOrgResponse, *Response, error) {
	q := url.Values{}
	opts.Add(q)

	userOrgs := []*csapitypes.UserOrgResponse{}
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/users/%s/orgs", userRef), q, common.JSONContent, nil, &userOrgs)
	return userOrgs, resp, errors.WithStack(err)
}

func (c *Client) GetRemoteSource(ctx context.Context, rsRef string) (*cstypes.RemoteSource, *Response, error) {
	rs := new(cstypes.RemoteSource)
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/remotesources/%s", rsRef), nil, common.JSONContent, nil, rs)
	return rs, resp, errors.WithStack(err)
}

type GetRemoteSourcesOptions struct {
	*ListOptions

	StartRemoteSourceName string
}

func (o *GetRemoteSourcesOptions) Add(q url.Values) {
	o.ListOptions.Add(q)

	if o.StartRemoteSourceName != "" {
		q.Add("startremotesourcename", o.StartRemoteSourceName)
	}
}

func (c *Client) GetRemoteSources(ctx context.Context, opts *GetRemoteSourcesOptions) ([]*cstypes.RemoteSource, *Response, error) {
	q := url.Values{}
	opts.Add(q)

	rss := []*cstypes.RemoteSource{}
	resp, err := c.GetParsedResponse(ctx, "GET", "/remotesources", q, common.JSONContent, nil, &rss)
	return rss, resp, errors.WithStack(err)
}

func (c *Client) CreateRemoteSource(ctx context.Context, req *csapitypes.CreateUpdateRemoteSourceRequest) (*cstypes.RemoteSource, *Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	rs := new(cstypes.RemoteSource)
	resp, err := c.GetParsedResponse(ctx, "POST", "/remotesources", nil, common.JSONContent, bytes.NewReader(reqj), rs)
	return rs, resp, errors.WithStack(err)
}

func (c *Client) UpdateRemoteSource(ctx context.Context, remoteSourceRef string, req *csapitypes.CreateUpdateRemoteSourceRequest) (*cstypes.RemoteSource, *Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	resRemoteSource := new(cstypes.RemoteSource)
	resp, err := c.GetParsedResponse(ctx, "PUT", fmt.Sprintf("/remotesources/%s", url.PathEscape(remoteSourceRef)), nil, common.JSONContent, bytes.NewReader(reqj), resRemoteSource)
	return resRemoteSource, resp, errors.WithStack(err)
}

func (c *Client) DeleteRemoteSource(ctx context.Context, rsRef string) (*Response, error) {
	resp, err := c.GetResponse(ctx, "DELETE", fmt.Sprintf("/remotesources/%s", rsRef), nil, -1, common.JSONContent, nil)
	return resp, errors.WithStack(err)
}

func (c *Client) GetLinkedAccountByRemoteUserAndSource(ctx context.Context, remoteUserID, remoteSourceID string) (*cstypes.LinkedAccount, *Response, error) {
	q := url.Values{}
	q.Add("query_type", "byremoteuser")
	q.Add("remoteuserid", remoteUserID)
	q.Add("remotesourceid", remoteSourceID)

	linkedAccounts := []*cstypes.LinkedAccount{}
	resp, err := c.GetParsedResponse(ctx, "GET", "/linkedaccounts", q, common.JSONContent, nil, &linkedAccounts)
	if err != nil {
		return nil, resp, errors.WithStack(err)
	}
	return linkedAccounts[0], resp, errors.WithStack(err)
}

func (c *Client) CreateOrg(ctx context.Context, req *csapitypes.CreateOrgRequest) (*cstypes.Organization, *Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	org := new(cstypes.Organization)
	resp, err := c.GetParsedResponse(ctx, "POST", "/orgs", nil, common.JSONContent, bytes.NewReader(reqj), org)
	return org, resp, errors.WithStack(err)
}

func (c *Client) DeleteOrg(ctx context.Context, orgRef string) (*Response, error) {
	resp, err := c.GetResponse(ctx, "DELETE", fmt.Sprintf("/orgs/%s", orgRef), nil, -1, common.JSONContent, nil)
	return resp, errors.WithStack(err)
}

func (c *Client) UpdateOrg(ctx context.Context, orgRef string, req *csapitypes.UpdateOrgRequest) (*cstypes.Organization, *Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	org := new(cstypes.Organization)
	resp, err := c.GetParsedResponse(ctx, "PUT", fmt.Sprintf("/orgs/%s", orgRef), nil, common.JSONContent, bytes.NewReader(reqj), org)
	return org, resp, errors.WithStack(err)
}

func (c *Client) AddOrgMember(ctx context.Context, orgRef, userRef string, role cstypes.MemberRole) (*cstypes.OrganizationMember, *Response, error) {
	req := &csapitypes.AddOrgMemberRequest{
		Role: role,
	}
	omj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	orgmember := new(cstypes.OrganizationMember)
	resp, err := c.GetParsedResponse(ctx, "PUT", fmt.Sprintf("/orgs/%s/members/%s", orgRef, userRef), nil, common.JSONContent, bytes.NewReader(omj), orgmember)
	return orgmember, resp, errors.WithStack(err)
}

func (c *Client) RemoveOrgMember(ctx context.Context, orgRef, userRef string) (*Response, error) {
	resp, err := c.GetResponse(ctx, "DELETE", fmt.Sprintf("/orgs/%s/members/%s", orgRef, userRef), nil, -1, common.JSONContent, nil)
	return resp, errors.WithStack(err)
}

type GetOrgsOptions struct {
	*ListOptions

	StartOrgName string

	Visibilities []cstypes.Visibility
}

func (o *GetOrgsOptions) Add(q url.Values) {
	o.ListOptions.Add(q)

	if o.StartOrgName != "" {
		q.Add("startorgname", o.StartOrgName)
	}
	for _, v := range o.Visibilities {
		q.Add("visibilities", string(v))
	}
}

func (c *Client) GetOrgs(ctx context.Context, opts *GetOrgsOptions) ([]*cstypes.Organization, *Response, error) {
	q := url.Values{}
	opts.Add(q)

	orgs := []*cstypes.Organization{}
	resp, err := c.GetParsedResponse(ctx, "GET", "/orgs", q, common.JSONContent, nil, &orgs)
	return orgs, resp, errors.WithStack(err)
}

func (c *Client) GetOrg(ctx context.Context, orgRef string) (*cstypes.Organization, *Response, error) {
	org := new(cstypes.Organization)
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/orgs/%s", orgRef), nil, common.JSONContent, nil, org)
	return org, resp, errors.WithStack(err)
}

type GetOrgMembersOptions struct {
	*ListOptions

	StartUserName string
}

func (o *GetOrgMembersOptions) Add(q url.Values) {
	o.ListOptions.Add(q)

	if o.StartUserName != "" {
		q.Add("startusername", o.StartUserName)
	}
}

func (c *Client) GetOrgMembers(ctx context.Context, orgRef string, opts *GetOrgMembersOptions) ([]*csapitypes.OrgMemberResponse, *Response, error) {
	q := url.Values{}
	opts.Add(q)

	orgMembers := []*csapitypes.OrgMemberResponse{}
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/orgs/%s/members", orgRef), q, common.JSONContent, nil, &orgMembers)
	return orgMembers, resp, errors.WithStack(err)
}

func (c *Client) GetUserOrgInvitations(ctx context.Context, userRef string, limit int) ([]*cstypes.OrgInvitation, *Response, error) {
	q := url.Values{}
	if limit > 0 {
		q.Add("limit", strconv.Itoa(limit))
	}

	orgInvitations := []*cstypes.OrgInvitation{}
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/users/%s/org_invitations", userRef), q, common.JSONContent, nil, &orgInvitations)
	return orgInvitations, resp, errors.WithStack(err)
}

func (c *Client) GetOrgInvitations(ctx context.Context, orgRef string, limit int) ([]*cstypes.OrgInvitation, *Response, error) {
	q := url.Values{}
	if limit > 0 {
		q.Add("limit", strconv.Itoa(limit))
	}

	orgInvitations := []*cstypes.OrgInvitation{}
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/orgs/%s/invitations", orgRef), q, common.JSONContent, nil, &orgInvitations)
	return orgInvitations, resp, errors.WithStack(err)
}

func (c *Client) CreateOrgInvitation(ctx context.Context, orgRef string, req *csapitypes.CreateOrgInvitationRequest) (*cstypes.OrgInvitation, *Response, error) {
	oj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}

	orgInvitation := new(cstypes.OrgInvitation)
	resp, err := c.GetParsedResponse(ctx, "POST", fmt.Sprintf("/orgs/%s/invitations", orgRef), nil, common.JSONContent, bytes.NewReader(oj), orgInvitation)
	return orgInvitation, resp, errors.WithStack(err)
}

func (c *Client) DeleteOrgInvitation(ctx context.Context, orgRef string, userRef string) (*Response, error) {
	resp, err := c.GetResponse(ctx, "DELETE", fmt.Sprintf("/orgs/%s/invitations/%s", orgRef, userRef), nil, -1, common.JSONContent, nil)
	return resp, errors.WithStack(err)
}

func (c *Client) GetOrgInvitation(ctx context.Context, orgRef string, userRef string) (*cstypes.OrgInvitation, *Response, error) {
	orgInvitation := new(cstypes.OrgInvitation)
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/orgs/%s/invitations/%s", orgRef, userRef), nil, common.JSONContent, nil, orgInvitation)
	return orgInvitation, resp, errors.WithStack(err)
}

func (c *Client) UserOrgInvitationAction(ctx context.Context, userRef string, orgRef string, req *csapitypes.OrgInvitationActionRequest) (*Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	resp, err := c.GetResponse(ctx, "PUT", fmt.Sprintf("/orgs/%s/invitations/%s/actions", orgRef, userRef), nil, -1, common.JSONContent, bytes.NewReader(reqj))
	return resp, errors.WithStack(err)
}

func (c *Client) GetMaintenanceStatus(ctx context.Context) (*csapitypes.MaintenanceStatusResponse, *Response, error) {
	maintenanceStatus := new(csapitypes.MaintenanceStatusResponse)
	resp, err := c.GetParsedResponse(ctx, "GET", "/maintenance", nil, common.JSONContent, nil, maintenanceStatus)
	return maintenanceStatus, resp, errors.WithStack(err)
}

func (c *Client) EnableMaintenance(ctx context.Context) (*Response, error) {
	resp, err := c.GetResponse(ctx, "PUT", "/maintenance", nil, -1, common.JSONContent, nil)
	return resp, errors.WithStack(err)
}

func (c *Client) DisableMaintenance(ctx context.Context) (*Response, error) {
	resp, err := c.GetResponse(ctx, "DELETE", "/maintenance", nil, -1, common.JSONContent, nil)
	return resp, errors.WithStack(err)
}

func (c *Client) Export(ctx context.Context) (*Response, error) {
	resp, err := c.GetResponse(ctx, "GET", "/export", nil, -1, common.JSONContent, nil)
	return resp, errors.WithStack(err)
}

func (c *Client) Import(ctx context.Context, r io.Reader) (*Response, error) {
	resp, err := c.GetResponse(ctx, "POST", "/import", nil, -1, common.JSONContent, r)
	return resp, errors.WithStack(err)
}
