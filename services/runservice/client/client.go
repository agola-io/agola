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
	rsapitypes "agola.io/agola/services/runservice/api/types"
	rstypes "agola.io/agola/services/runservice/types"
)

const (
	agolaHasMoreHeader = "X-Agola-HasMore"
)

type ListOptions struct {
	Limit         int
	SortDirection rstypes.SortDirection
}

func (o *ListOptions) Add(q url.Values) {
	if o == nil {
		return
	}

	if o.Limit != 0 {
		q.Add("limit", strconv.Itoa(o.Limit))
	}

	switch o.SortDirection {
	case rstypes.SortDirectionDesc:
		q.Add("sortdirection", "desc")
	case rstypes.SortDirectionAsc:
		fallthrough
	default:
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

func (c *Client) SendExecutorStatus(ctx context.Context, executorID string, executor *rsapitypes.ExecutorStatus) (*Response, error) {
	executorj, err := json.Marshal(executor)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	resp, err := c.GetResponse(ctx, "POST", fmt.Sprintf("/executor/%s", executorID), nil, -1, common.JSONContent, bytes.NewReader(executorj))
	return resp, errors.WithStack(err)
}

func (c *Client) SendExecutorTaskStatus(ctx context.Context, executorID, etID string, et *rsapitypes.ExecutorTaskStatus) (*Response, error) {
	etj, err := json.Marshal(et)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	resp, err := c.GetResponse(ctx, "POST", fmt.Sprintf("/executor/%s/tasks/%s", executorID, etID), nil, -1, common.JSONContent, bytes.NewReader(etj))
	return resp, errors.WithStack(err)
}

func (c *Client) GetExecutorTask(ctx context.Context, executorID, etID string) (*rsapitypes.ExecutorTask, *Response, error) {
	et := new(rsapitypes.ExecutorTask)
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/executor/%s/tasks/%s", executorID, etID), nil, common.JSONContent, nil, et)
	return et, resp, errors.WithStack(err)
}

func (c *Client) GetExecutorTasks(ctx context.Context, executorID string) ([]*rsapitypes.ExecutorTask, *Response, error) {
	ets := []*rsapitypes.ExecutorTask{}
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/executor/%s/tasks", executorID), nil, common.JSONContent, nil, &ets)
	return ets, resp, errors.WithStack(err)
}

func (c *Client) GetArchive(ctx context.Context, taskID string, step int) (*Response, error) {
	q := url.Values{}
	q.Add("taskid", taskID)
	q.Add("step", strconv.Itoa(step))

	resp, err := c.GetResponse(ctx, "GET", "/executor/archives", q, -1, nil, nil)
	return resp, errors.WithStack(err)
}

func (c *Client) CheckCache(ctx context.Context, key string, prefix bool) (*Response, error) {
	q := url.Values{}
	if prefix {
		q.Add("prefix", "")
	}

	resp, err := c.GetResponse(ctx, "HEAD", fmt.Sprintf("/executor/caches/%s", url.PathEscape(key)), q, -1, nil, nil)
	return resp, errors.WithStack(err)
}

func (c *Client) GetCache(ctx context.Context, key string, prefix bool) (*Response, error) {
	q := url.Values{}
	if prefix {
		q.Add("prefix", "")
	}

	resp, err := c.GetResponse(ctx, "GET", fmt.Sprintf("/executor/caches/%s", url.PathEscape(key)), q, -1, nil, nil)
	return resp, errors.WithStack(err)
}

func (c *Client) PutCache(ctx context.Context, key string, size int64, r io.Reader) (*Response, error) {

	resp, err := c.GetResponse(ctx, "POST", fmt.Sprintf("/executor/caches/%s", url.PathEscape(key)), nil, size, nil, r)
	return resp, errors.WithStack(err)
}

type GetRunsOptions struct {
	*ListOptions

	PhaseFilter      []string
	ResultFilter     []string
	Groups           []string
	LastRun          bool
	ChangeGroups     []string
	StartRunSequence uint64
}

func (o *GetRunsOptions) Add(q url.Values) {
	o.ListOptions.Add(q)

	for _, phase := range o.PhaseFilter {
		q.Add("phase", phase)
	}
	for _, result := range o.ResultFilter {
		q.Add("result", result)
	}
	for _, group := range o.Groups {
		q.Add("group", group)
	}
	if o.LastRun {
		q.Add("lastrun", "")
	}
	for _, changeGroup := range o.ChangeGroups {
		q.Add("changegroup", changeGroup)
	}
	if o.StartRunSequence > 0 {
		q.Add("start", strconv.FormatUint(o.StartRunSequence, 10))
	}
}

func (c *Client) GetRuns(ctx context.Context, opts *GetRunsOptions) (*rsapitypes.GetGroupRunsResponse, *Response, error) {
	q := url.Values{}
	opts.Add(q)

	getRunsResponse := new(rsapitypes.GetGroupRunsResponse)
	resp, err := c.GetParsedResponse(ctx, "GET", "/runs", q, common.JSONContent, nil, getRunsResponse)
	return getRunsResponse, resp, errors.WithStack(err)
}

func (c *Client) GetQueuedRuns(ctx context.Context, startRunSequence uint64, limit int, changeGroups []string) (*rsapitypes.GetGroupRunsResponse, *Response, error) {
	opts := &GetRunsOptions{
		PhaseFilter:      []string{"queued"},
		ChangeGroups:     changeGroups,
		StartRunSequence: startRunSequence,
		ListOptions:      &ListOptions{Limit: limit, SortDirection: rstypes.SortDirectionAsc},
	}

	return c.GetRuns(ctx, opts)
}

func (c *Client) GetRunningRuns(ctx context.Context, startRunSequence uint64, limit int, changeGroups []string) (*rsapitypes.GetGroupRunsResponse, *Response, error) {
	opts := &GetRunsOptions{
		PhaseFilter:      []string{"running"},
		ChangeGroups:     changeGroups,
		StartRunSequence: startRunSequence,
		ListOptions:      &ListOptions{Limit: limit, SortDirection: rstypes.SortDirectionAsc},
	}

	return c.GetRuns(ctx, opts)
}

func (c *Client) GetGroupQueuedRuns(ctx context.Context, group string, limit int, changeGroups []string) (*rsapitypes.GetGroupRunsResponse, *Response, error) {
	opts := &GetRunsOptions{
		PhaseFilter:  []string{"queued"},
		Groups:       []string{group},
		ChangeGroups: changeGroups,
		ListOptions:  &ListOptions{Limit: limit, SortDirection: rstypes.SortDirectionDesc},
	}

	return c.GetRuns(ctx, opts)
}

func (c *Client) GetGroupRunningRuns(ctx context.Context, group string, limit int, changeGroups []string) (*rsapitypes.GetGroupRunsResponse, *Response, error) {
	opts := &GetRunsOptions{
		PhaseFilter:  []string{"running"},
		Groups:       []string{group},
		ChangeGroups: changeGroups,
		ListOptions:  &ListOptions{Limit: limit, SortDirection: rstypes.SortDirectionDesc},
	}

	return c.GetRuns(ctx, opts)
}

func (c *Client) GetGroupFirstQueuedRuns(ctx context.Context, group string, changeGroups []string) (*rsapitypes.GetGroupRunsResponse, *Response, error) {
	opts := &GetRunsOptions{
		PhaseFilter:  []string{"queued"},
		Groups:       []string{group},
		ChangeGroups: changeGroups,
		ListOptions:  &ListOptions{Limit: 1, SortDirection: rstypes.SortDirectionAsc},
	}

	return c.GetRuns(ctx, opts)
}

func (c *Client) GetGroupLastRun(ctx context.Context, group string, changeGroups []string) (*rsapitypes.GetGroupRunsResponse, *Response, error) {
	opts := &GetRunsOptions{
		Groups:       []string{group},
		ChangeGroups: changeGroups,
		ListOptions:  &ListOptions{Limit: 1, SortDirection: rstypes.SortDirectionDesc},
	}

	return c.GetRuns(ctx, opts)
}

func (c *Client) GetGroupRuns(ctx context.Context, phaseFilter, resultFilter []string, group string, changeGroups []string, startRunCounter uint64, limit int, asc bool) (*rsapitypes.GetGroupRunsResponse, *Response, error) {
	q := url.Values{}
	for _, phase := range phaseFilter {
		q.Add("phase", phase)
	}
	for _, result := range resultFilter {
		q.Add("result", result)
	}
	for _, changeGroup := range changeGroups {
		q.Add("changegroup", changeGroup)
	}
	if startRunCounter > 0 {
		q.Add("start", strconv.FormatUint(startRunCounter, 10))
	}
	if limit > 0 {
		q.Add("limit", strconv.Itoa(limit))
	}
	if asc {
		q.Add("asc", "")
	}

	getRunsResponse := new(rsapitypes.GetGroupRunsResponse)
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/runs/group/%s", url.PathEscape(group)), q, common.JSONContent, nil, getRunsResponse)
	return getRunsResponse, resp, errors.WithStack(err)
}

func (c *Client) CreateRun(ctx context.Context, req *rsapitypes.RunCreateRequest) (*rsapitypes.RunResponse, *Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	res := new(rsapitypes.RunResponse)
	resp, err := c.GetParsedResponse(ctx, "POST", "/runs", nil, common.JSONContent, bytes.NewReader(reqj), res)
	return res, resp, errors.WithStack(err)
}

func (c *Client) RunActions(ctx context.Context, runID string, req *rsapitypes.RunActionsRequest) (*Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	resp, err := c.GetResponse(ctx, "PUT", fmt.Sprintf("/runs/%s/actions", runID), nil, -1, common.JSONContent, bytes.NewReader(reqj))
	return resp, errors.WithStack(err)
}

func (c *Client) StartRun(ctx context.Context, runID string, changeGroupsUpdateToken string) (*Response, error) {
	req := &rsapitypes.RunActionsRequest{
		ActionType:              rsapitypes.RunActionTypeChangePhase,
		Phase:                   rstypes.RunPhaseRunning,
		ChangeGroupsUpdateToken: changeGroupsUpdateToken,
	}

	return c.RunActions(ctx, runID, req)
}

func (c *Client) RunTaskActions(ctx context.Context, runID, taskID string, req *rsapitypes.RunTaskActionsRequest) (*Response, error) {
	reqj, err := json.Marshal(req)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	resp, err := c.GetResponse(ctx, "PUT", fmt.Sprintf("/runs/%s/tasks/%s/actions", runID, taskID), nil, -1, common.JSONContent, bytes.NewReader(reqj))
	return resp, errors.WithStack(err)
}

func (c *Client) RunTaskSetAnnotations(ctx context.Context, runID, taskID string, annotations map[string]string, changeGroupsUpdateToken string) (*Response, error) {
	req := &rsapitypes.RunTaskActionsRequest{
		ActionType:              rsapitypes.RunTaskActionTypeSetAnnotations,
		Annotations:             annotations,
		ChangeGroupsUpdateToken: changeGroupsUpdateToken,
	}

	return c.RunTaskActions(ctx, runID, taskID, req)
}

func (c *Client) ApproveRunTask(ctx context.Context, runID, taskID string, changeGroupsUpdateToken string) (*Response, error) {
	req := &rsapitypes.RunTaskActionsRequest{
		ActionType:              rsapitypes.RunTaskActionTypeApprove,
		ChangeGroupsUpdateToken: changeGroupsUpdateToken,
	}

	return c.RunTaskActions(ctx, runID, taskID, req)
}

func (c *Client) GetRun(ctx context.Context, runID string, changeGroups []string) (*rsapitypes.RunResponse, *Response, error) {
	q := url.Values{}
	for _, changeGroup := range changeGroups {
		q.Add("changegroup", changeGroup)
	}

	runResponse := new(rsapitypes.RunResponse)
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/runs/%s", runID), q, common.JSONContent, nil, runResponse)
	return runResponse, resp, errors.WithStack(err)
}

func (c *Client) GetRunByGroup(ctx context.Context, group string, runNumber uint64, changeGroups []string) (*rsapitypes.RunResponse, *Response, error) {
	q := url.Values{}
	for _, changeGroup := range changeGroups {
		q.Add("changegroup", changeGroup)
	}

	runResponse := new(rsapitypes.RunResponse)
	resp, err := c.GetParsedResponse(ctx, "GET", fmt.Sprintf("/runs/group/%s/%d", url.PathEscape(group), runNumber), q, common.JSONContent, nil, runResponse)
	return runResponse, resp, errors.WithStack(err)
}

func (c *Client) GetLogs(ctx context.Context, runID, taskID string, setup bool, step int, follow bool) (*Response, error) {
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

	resp, err := c.GetResponse(ctx, "GET", "/logs", q, -1, nil, nil)
	return resp, errors.WithStack(err)
}

func (c *Client) DeleteLogs(ctx context.Context, runID, taskID string, setup bool, step int) (*Response, error) {
	q := url.Values{}
	q.Add("runid", runID)
	q.Add("taskid", taskID)
	if setup {
		q.Add("setup", "")
	} else {
		q.Add("step", strconv.Itoa(step))
	}

	resp, err := c.GetResponse(ctx, "DELETE", "/logs", q, -1, nil, nil)
	return resp, errors.WithStack(err)
}

func (c *Client) GetRunEvents(ctx context.Context, afterSequence uint64) (*Response, error) {
	q := url.Values{}
	q.Add("afterSequence", strconv.FormatUint(afterSequence, 10))

	resp, err := c.GetResponse(ctx, "GET", "/runs/events", q, -1, nil, nil)
	return resp, errors.WithStack(err)
}

func (c *Client) GetMaintenanceStatus(ctx context.Context) (*rsapitypes.MaintenanceStatusResponse, *Response, error) {
	maintenanceStatus := new(rsapitypes.MaintenanceStatusResponse)
	resp, err := c.GetParsedResponse(ctx, "GET", "/maintenance", nil, common.JSONContent, nil, maintenanceStatus)
	return maintenanceStatus, resp, errors.WithStack(err)
}

func (c *Client) EnableMaintenance(ctx context.Context) (*Response, error) {
	resp, err := c.GetResponse(ctx, "PUT", "/maintenance", nil, -1, nil, nil)
	return resp, errors.WithStack(err)
}

func (c *Client) DisableMaintenance(ctx context.Context) (*Response, error) {
	resp, err := c.GetResponse(ctx, "DELETE", "/maintenance", nil, -1, nil, nil)
	return resp, errors.WithStack(err)
}

func (c *Client) Export(ctx context.Context) (*Response, error) {
	resp, err := c.GetResponse(ctx, "GET", "/export", nil, -1, nil, nil)
	return resp, errors.WithStack(err)
}

func (c *Client) Import(ctx context.Context, r io.Reader) (*Response, error) {
	resp, err := c.GetResponse(ctx, "POST", "/import", nil, -1, nil, r)
	return resp, errors.WithStack(err)
}
