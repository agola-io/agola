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

package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/sorintlab/errors"

	"agola.io/agola/internal/util"
	gwapitypes "agola.io/agola/services/gateway/api/types"
)

var jsonContent = http.Header{"Content-Type": []string{"application/json"}}

type CookieClient struct {
	url    string
	client *http.Client
}

func newCookieClient(url string) *CookieClient {
	return &CookieClient{
		url:    strings.TrimSuffix(url, "/"),
		client: &http.Client{},
	}
}

func (c *CookieClient) doRequest(ctx context.Context, method, path string, query url.Values, header http.Header, cookies []*http.Cookie, ibody io.Reader) (*http.Response, error) {
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

	for _, c := range cookies {
		req.AddCookie(c)
	}

	res, err := c.client.Do(req)

	return res, errors.WithStack(err)
}

func (c *CookieClient) getResponse(ctx context.Context, method, path string, query url.Values, header http.Header, cookies []*http.Cookie, ibody io.Reader) (*http.Response, error) {
	resp, err := c.doRequest(ctx, method, path, query, header, cookies, ibody)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if err := util.ErrFromRemote(resp); err != nil {
		return resp, errors.WithStack(err)
	}

	return resp, nil
}

func (c *CookieClient) getParsedResponse(ctx context.Context, method, path string, query url.Values, header http.Header, cookies []*http.Cookie, ibody io.Reader, obj interface{}) (*http.Response, error) {
	resp, err := c.getResponse(ctx, method, path, query, header, cookies, ibody)
	if err != nil {
		return resp, errors.WithStack(err)
	}
	defer resp.Body.Close()

	d := json.NewDecoder(resp.Body)

	return resp, errors.WithStack(d.Decode(obj))
}

func (c *CookieClient) Login(ctx context.Context, req *gwapitypes.LoginUserRequest, cookies []*http.Cookie) (*gwapitypes.LoginUserResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	loginResponse := new(gwapitypes.LoginUserResponse)
	resp, err := c.getParsedResponse(ctx, "POST", "/auth/login", nil, jsonContent, cookies, bytes.NewReader(reqj), loginResponse)
	return loginResponse, resp, errors.WithStack(err)
}

func (c *CookieClient) GetCurrentUser(ctx context.Context, cookies []*http.Cookie) (*gwapitypes.PrivateUserResponse, *http.Response, error) {
	user := new(gwapitypes.PrivateUserResponse)
	resp, err := c.getParsedResponse(ctx, "GET", "/user", nil, jsonContent, cookies, nil, user)
	return user, resp, errors.WithStack(err)
}

func (c *CookieClient) CreateOrg(ctx context.Context, req *gwapitypes.CreateOrgRequest, header http.Header, cookies []*http.Cookie) (*gwapitypes.OrgResponse, *http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	for k, v := range jsonContent {
		header[k] = v
	}

	org := new(gwapitypes.OrgResponse)
	resp, err := c.getParsedResponse(ctx, "POST", "/orgs", nil, header, cookies, bytes.NewReader(reqj), org)
	return org, resp, errors.WithStack(err)
}
