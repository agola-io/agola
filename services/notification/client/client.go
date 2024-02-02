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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/pkg/errors"

	"agola.io/agola/internal/util"
	"agola.io/agola/services/common"
	"agola.io/agola/services/notification/types"
)

const (
	agolaHasMoreHeader = "X-Agola-HasMore"
)

type ListOptions struct {
	Limit         int
	SortDirection types.SortDirection
}

func (o *ListOptions) Add(q url.Values) {
	if o == nil {
		return
	}

	if o.Limit != 0 {
		q.Add("limit", strconv.Itoa(o.Limit))
	}

	switch o.SortDirection {
	case types.SortDirectionDesc:
		q.Add("sortdirection", "desc")
	case types.SortDirectionAsc:
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

type GetProjectRunWebhookDeliveriesOptions struct {
	*ListOptions

	StartSequence        uint64
	DeliveryStatusFilter []string
}

func (o *GetProjectRunWebhookDeliveriesOptions) Add(q url.Values) {
	o.ListOptions.Add(q)

	if o.StartSequence > 0 {
		q.Add("startsequence", strconv.FormatUint(o.StartSequence, 10))
	}
}

func (c *Client) GetProjectRunWebhookDeliveries(ctx context.Context, projectID string, opts *GetProjectRunWebhookDeliveriesOptions) ([]*types.RunWebhookDelivery, *Response, error) {
	q := url.Values{}
	opts.Add(q)

	for _, deliveryStatus := range opts.DeliveryStatusFilter {
		q.Add("deliverystatus", deliveryStatus)
	}

	runWebhookDeliveries := []*types.RunWebhookDelivery{}
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/projects/%s/runwebhookdeliveries", projectID), q, common.JSONContent, nil, &runWebhookDeliveries)
	return runWebhookDeliveries, resp, errors.WithStack(err)
}

func (c *Client) RunWebhookRedelivery(ctx context.Context, projectID, runWebhookDeliveryID string) (*Response, error) {
	resp, err := c.GetResponse(ctx, "PUT", fmt.Sprintf("/projects/%s/runwebhookdeliveries/%s/redelivery", projectID, runWebhookDeliveryID), nil, -1, common.JSONContent, nil)
	return resp, errors.WithStack(err)
}

type GetProjectCommitStatusDeliveriesOptions struct {
	*ListOptions

	StartSequence        uint64
	DeliveryStatusFilter []string
}

func (o *GetProjectCommitStatusDeliveriesOptions) Add(q url.Values) {
	o.ListOptions.Add(q)

	if o.StartSequence > 0 {
		q.Add("startsequence", strconv.FormatUint(o.StartSequence, 10))
	}
}

func (c *Client) GetProjectCommitStatusDeliveries(ctx context.Context, projectID string, opts *GetProjectCommitStatusDeliveriesOptions) ([]*types.CommitStatusDelivery, *Response, error) {
	q := url.Values{}
	opts.Add(q)

	for _, deliveryStatus := range opts.DeliveryStatusFilter {
		q.Add("deliverystatus", deliveryStatus)
	}

	commitStatusDeliveries := []*types.CommitStatusDelivery{}
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/projects/%s/commitstatusdeliveries", projectID), q, common.JSONContent, nil, &commitStatusDeliveries)
	return commitStatusDeliveries, resp, errors.WithStack(err)
}

func (c *Client) CommitStatusRedelivery(ctx context.Context, projectID, commitStatusDeliveryID string) (*Response, error) {
	resp, err := c.GetResponse(ctx, "PUT", fmt.Sprintf("/projects/%s/commitstatusdeliveries/%s/redelivery", projectID, commitStatusDeliveryID), nil, -1, common.JSONContent, nil)
	return resp, errors.WithStack(err)
}
