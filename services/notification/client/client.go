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
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/pkg/errors"

	"agola.io/agola/internal/util"
	"agola.io/agola/services/common"
)

const (
	agolaHasMoreHeader = "X-Agola-HasMore"
)

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
