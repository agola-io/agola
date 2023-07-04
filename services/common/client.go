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

package common

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/sorintlab/errors"

	"agola.io/agola/internal/util"
)

var JSONContent = http.Header{"Content-Type": []string{"application/json"}}

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

func (c *Client) doRequest(ctx context.Context, method, path string, query url.Values, contentLength int64, header http.Header, ibody io.Reader) (*http.Response, error) {
	u, err := url.Parse(c.url + path)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	u.RawQuery = query.Encode()

	req, err := http.NewRequest(method, u.String(), ibody)
	req = req.WithContext(ctx)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if c.token != "" {
		req.Header.Set("Authorization", "token "+c.token)
	}

	for k, v := range header {
		req.Header[k] = v
	}

	if contentLength >= 0 {
		req.ContentLength = contentLength
	}

	res, err := c.client.Do(req)

	return res, errors.WithStack(err)
}

func (c *Client) GetResponse(ctx context.Context, method, path string, query url.Values, contentLength int64, header http.Header, ibody io.Reader) (*http.Response, error) {
	resp, err := c.doRequest(ctx, method, path, query, contentLength, header, ibody)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if err := util.ErrFromRemote(resp); err != nil {
		return resp, errors.WithStack(err)
	}

	return resp, nil
}

func (c *Client) GetParsedResponse(ctx context.Context, method, path string, query url.Values, header http.Header, ibody io.Reader, obj interface{}) (*http.Response, error) {
	resp, err := c.GetResponse(ctx, method, path, query, -1, header, ibody)
	if err != nil {
		return resp, errors.WithStack(err)
	}
	defer resp.Body.Close()

	d := json.NewDecoder(resp.Body)

	return resp, errors.WithStack(d.Decode(obj))
}
