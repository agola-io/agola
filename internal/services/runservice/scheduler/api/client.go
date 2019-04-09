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

	"github.com/pkg/errors"
	rstypes "github.com/sorintlab/agola/internal/services/runservice/types"
)

var jsonContent = http.Header{"Content-Type": []string{"application/json"}}

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

func (c *Client) SendExecutorStatus(ctx context.Context, executor *rstypes.Executor) (*http.Response, error) {
	executorj, err := json.Marshal(executor)
	if err != nil {
		return nil, err
	}
	return c.getResponse(ctx, "POST", fmt.Sprintf("/executor/%s", executor.ID), nil, jsonContent, bytes.NewReader(executorj))
}

func (c *Client) SendExecutorTaskStatus(ctx context.Context, executorID string, et *rstypes.ExecutorTask) (*http.Response, error) {
	etj, err := json.Marshal(et)
	if err != nil {
		return nil, err
	}
	return c.getResponse(ctx, "POST", fmt.Sprintf("/executor/%s/tasks/%s", executorID, et.ID), nil, jsonContent, bytes.NewReader(etj))
}

func (c *Client) GetExecutorTask(ctx context.Context, executorID, etID string) (*rstypes.ExecutorTask, *http.Response, error) {
	et := new(rstypes.ExecutorTask)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/executor/%s/tasks/%s", executorID, etID), nil, jsonContent, nil, et)
	return et, resp, err
}

func (c *Client) GetExecutorTasks(ctx context.Context, executorID string) ([]*rstypes.ExecutorTask, *http.Response, error) {
	ets := []*rstypes.ExecutorTask{}
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/executor/%s/tasks", executorID), nil, jsonContent, nil, &ets)
	return ets, resp, err
}

func (c *Client) GetArchive(ctx context.Context, taskID string, step int) (*http.Response, error) {
	q := url.Values{}
	q.Add("taskid", taskID)
	q.Add("step", strconv.Itoa(step))

	return c.getResponse(ctx, "GET", "/executor/archives", q, nil, nil)
}

func (c *Client) GetRuns(ctx context.Context, phaseFilter, groups []string, lastRun bool, changeGroups []string, start string, limit int, asc bool) (*GetRunsResponse, *http.Response, error) {
	q := url.Values{}
	for _, phase := range phaseFilter {
		q.Add("phase", phase)
	}
	for _, group := range groups {
		q.Add("group", group)
	}
	if lastRun {
		q.Add("lastrun", "")
	}
	for _, changeGroup := range changeGroups {
		q.Add("changegroup", changeGroup)
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

	getRunsResponse := new(GetRunsResponse)
	resp, err := c.getParsedResponse(ctx, "GET", "/runs", q, jsonContent, nil, getRunsResponse)
	return getRunsResponse, resp, err
}

func (c *Client) GetQueuedRuns(ctx context.Context, start string, limit int) (*GetRunsResponse, *http.Response, error) {
	return c.GetRuns(ctx, []string{"queued"}, []string{}, false, nil, start, limit, true)
}

func (c *Client) GetGroupQueuedRuns(ctx context.Context, group string, limit int, changeGroups []string) (*GetRunsResponse, *http.Response, error) {
	return c.GetRuns(ctx, []string{"queued"}, []string{group}, false, changeGroups, "", limit, false)
}

func (c *Client) GetGroupRunningRuns(ctx context.Context, group string, limit int, changeGroups []string) (*GetRunsResponse, *http.Response, error) {
	return c.GetRuns(ctx, []string{"running"}, []string{group}, false, changeGroups, "", limit, false)
}

func (c *Client) GetGroupFirstQueuedRuns(ctx context.Context, group string, changeGroups []string) (*GetRunsResponse, *http.Response, error) {
	return c.GetRuns(ctx, []string{"queued"}, []string{group}, false, changeGroups, "", 1, true)
}

func (c *Client) CreateRun(ctx context.Context, req *RunCreateRequest) (*http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	return c.getResponse(ctx, "POST", "/runs", nil, jsonContent, bytes.NewReader(reqj))
}

func (c *Client) RunActions(ctx context.Context, runID string, req *RunActionsRequest) (*http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	return c.getResponse(ctx, "PUT", fmt.Sprintf("/runs/%s/actions", runID), nil, jsonContent, bytes.NewReader(reqj))
}

func (c *Client) StartRun(ctx context.Context, runID string, changeGroupsUpdateToken string) (*http.Response, error) {
	req := &RunActionsRequest{
		ActionType:              RunActionTypeChangePhase,
		Phase:                   rstypes.RunPhaseRunning,
		ChangeGroupsUpdateToken: changeGroupsUpdateToken,
	}

	return c.RunActions(ctx, runID, req)
}

func (c *Client) RunTaskActions(ctx context.Context, runID, taskID string, req *RunTaskActionsRequest) (*http.Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	return c.getResponse(ctx, "PUT", fmt.Sprintf("/runs/%s/tasks/%s/actions", runID, taskID), nil, jsonContent, bytes.NewReader(reqj))
}

func (c *Client) ApproveRunTask(ctx context.Context, runID, taskID string, approvalAnnotations map[string]string, changeGroupsUpdateToken string) (*http.Response, error) {
	req := &RunTaskActionsRequest{
		ActionType:              RunTaskActionTypeApprove,
		ApprovalAnnotations:     approvalAnnotations,
		ChangeGroupsUpdateToken: changeGroupsUpdateToken,
	}

	return c.RunTaskActions(ctx, runID, taskID, req)
}

func (c *Client) GetRun(ctx context.Context, runID string) (*RunResponse, *http.Response, error) {
	runResponse := new(RunResponse)
	resp, err := c.getParsedResponse(ctx, "GET", fmt.Sprintf("/runs/%s", runID), nil, jsonContent, nil, runResponse)
	return runResponse, resp, err
}

func (c *Client) GetLogs(ctx context.Context, runID, taskID string, setup bool, step int, follow, stream bool) (*http.Response, error) {
	q := url.Values{}
	q.Add("runid", runID)
	q.Add("taskid", taskID)
	if setup {
		q.Add("setup", "")
	} else {
		q.Add("step", strconv.Itoa(step))
	}
	if follow {
		q.Add("follow", "")
	}
	if stream {
		q.Add("stream", "")
	}

	return c.getResponse(ctx, "GET", "/logs", q, nil, nil)
}
