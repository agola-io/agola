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
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/common"
	serrors "agola.io/agola/internal/services/errors"
	"agola.io/agola/internal/services/gateway/action"
	"agola.io/agola/internal/util"
	gwapitypes "agola.io/agola/services/gateway/api/types"
	rstypes "agola.io/agola/services/runservice/types"
)

func createRunResponse(r *rstypes.Run, rc *rstypes.RunConfig) *gwapitypes.RunResponse {
	run := &gwapitypes.RunResponse{
		Number:      r.Counter,
		Name:        r.Name,
		Annotations: r.Annotations,
		Phase:       r.Phase,
		Result:      r.Result,
		Stopping:    r.Stop,
		SetupErrors: rc.SetupErrors,

		Tasks:                make(map[string]*gwapitypes.RunResponseTask),
		TasksWaitingApproval: r.TasksWaitingApproval(),

		EnqueueTime: r.EnqueueTime,
		StartTime:   r.StartTime,
		EndTime:     r.EndTime,
	}

	run.CanRestartFromScratch, _ = r.CanRestartFromScratch()
	run.CanRestartFromFailedTasks, _ = r.CanRestartFromFailedTasks()

	for name, rt := range r.Tasks {
		rct := rc.Tasks[rt.ID]
		run.Tasks[name] = createRunResponseTask(r, rt, rct)
	}

	return run
}

func createRunResponseTask(r *rstypes.Run, rt *rstypes.RunTask, rct *rstypes.RunConfigTask) *gwapitypes.RunResponseTask {
	t := &gwapitypes.RunResponseTask{
		ID:       rt.ID,
		Name:     rct.Name,
		Status:   rt.Status,
		Timedout: rt.Timedout,

		StartTime: rt.StartTime,
		EndTime:   rt.EndTime,

		WaitingApproval:     rt.WaitingApproval,
		Approved:            rt.Approved,
		ApprovalAnnotations: rt.Annotations,

		Level:   rct.Level,
		Depends: rct.Depends,

		TaskTimeoutInterval: rct.TaskTimeoutInterval,
	}

	return t
}

func createRunTaskResponse(rt *rstypes.RunTask, rct *rstypes.RunConfigTask) *gwapitypes.RunTaskResponse {
	t := &gwapitypes.RunTaskResponse{
		ID:         rt.ID,
		Name:       rct.Name,
		Status:     rt.Status,
		Timedout:   rt.Timedout,
		Containers: []gwapitypes.RunTaskResponseContainer{},

		WaitingApproval:     rt.WaitingApproval,
		Approved:            rt.Approved,
		ApprovalAnnotations: rt.Annotations,

		Steps: make([]*gwapitypes.RunTaskResponseStep, len(rt.Steps)),

		StartTime: rt.StartTime,
		EndTime:   rt.EndTime,

		TaskTimeoutInterval: rct.TaskTimeoutInterval,
	}

	t.SetupStep = &gwapitypes.RunTaskResponseSetupStep{
		Name:      "Task setup",
		Phase:     rt.SetupStep.Phase,
		StartTime: rt.SetupStep.StartTime,
		EndTime:   rt.SetupStep.EndTime,
	}

	if rct.Runtime != nil {
		for _, rctContainer := range rct.Runtime.Containers {
			container := gwapitypes.RunTaskResponseContainer{}
			if rctContainer != nil {
				container.Image = rctContainer.Image
			}
			t.Containers = append(t.Containers, container)
		}
	}

	for i := 0; i < len(t.Steps); i++ {
		s := &gwapitypes.RunTaskResponseStep{
			Phase:     rt.Steps[i].Phase,
			StartTime: rt.Steps[i].StartTime,
			EndTime:   rt.Steps[i].EndTime,
		}
		rcts := rct.Steps[i]
		rts := rt.Steps[i]

		if rts.LogPhase == rstypes.RunTaskFetchPhaseFinished {
			s.LogArchived = true
		}

		switch rcts := rcts.(type) {
		case *rstypes.RunStep:
			s.Type = "run"
			s.Name = rcts.Name
			s.Command = rcts.Command

			shell := rcts.Shell
			if shell == "" {
				shell = rct.Shell
			}
			s.Shell = shell

			s.ExitStatus = rts.ExitStatus
		case *rstypes.SaveToWorkspaceStep:
			s.Type = "save_to_workspace"
			s.Name = "save to workspace"
		case *rstypes.RestoreWorkspaceStep:
			s.Type = "restore_workspace"
			s.Name = "restore workspace"
		case *rstypes.SaveCacheStep:
			s.Type = "save_cache"
			s.Name = "save cache"
		case *rstypes.RestoreCacheStep:
			s.Type = "restore_cache"
			s.Name = "restore cache"
		}

		t.Steps[i] = s
	}

	return t
}

type GroupRunHandler struct {
	log       zerolog.Logger
	ah        *action.ActionHandler
	groupType common.GroupType
}

func NewGroupRunHandler(log zerolog.Logger, ah *action.ActionHandler, groupType common.GroupType) *GroupRunHandler {
	return &GroupRunHandler{log: log, ah: ah, groupType: groupType}
}

func (h *GroupRunHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *GroupRunHandler) do(r *http.Request) (*gwapitypes.RunResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)

	var err error
	var ref string
	switch h.groupType {
	case common.GroupTypeProject:
		ref, err = url.PathUnescape(vars["projectref"])
		if err != nil {
			return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("projectref is empty"))
		}
	case common.GroupTypeUser:
		ref = vars["userref"]
	}

	runNumberStr := vars["runnumber"]

	var runNumber uint64
	if runNumberStr != "" {
		var err error
		runNumber, err = strconv.ParseUint(runNumberStr, 10, 64)
		if err != nil {
			return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err, util.WithAPIErrorMsg("cannot parse run number"), serrors.InvalidRunNumber())
		}
	}

	runResp, err := h.ah.GetRun(ctx, h.groupType, ref, runNumber)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := createRunResponse(runResp.Run, runResp.RunConfig)

	return res, nil
}

type RuntaskHandler struct {
	log       zerolog.Logger
	ah        *action.ActionHandler
	groupType common.GroupType
}

func NewRuntaskHandler(log zerolog.Logger, ah *action.ActionHandler, groupType common.GroupType) *RuntaskHandler {
	return &RuntaskHandler{log: log, ah: ah, groupType: groupType}
}

func (h *RuntaskHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *RuntaskHandler) do(r *http.Request) (*gwapitypes.RunTaskResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)

	var err error
	var ref string
	switch h.groupType {
	case common.GroupTypeProject:
		ref, err = url.PathUnescape(vars["projectref"])
		if err != nil {
			return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("projectref is empty"))
		}
	case common.GroupTypeUser:
		ref = vars["userref"]
	}

	runNumberStr := vars["runnumber"]

	var runNumber uint64
	if runNumberStr != "" {
		var err error
		runNumber, err = strconv.ParseUint(runNumberStr, 10, 64)
		if err != nil {
			return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err, util.WithAPIErrorMsg("cannot parse run number"), serrors.InvalidRunNumber())
		}
	}

	taskID := vars["taskid"]

	runResp, err := h.ah.GetRun(ctx, h.groupType, ref, runNumber)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	run := runResp.Run
	rc := runResp.RunConfig

	rt, ok := run.Tasks[taskID]
	if !ok {
		return nil, util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("run %q task %q not found", runNumber, taskID))
	}
	rct := rc.Tasks[rt.ID]

	res := createRunTaskResponse(rt, rct)

	return res, nil
}

func createRunsResponse(r *rstypes.Run) *gwapitypes.RunsResponse {
	run := &gwapitypes.RunsResponse{
		Number:      r.Counter,
		Name:        r.Name,
		Annotations: r.Annotations,
		Phase:       r.Phase,
		Result:      r.Result,

		TasksWaitingApproval: r.TasksWaitingApproval(),

		EnqueueTime: r.EnqueueTime,
		StartTime:   r.StartTime,
		EndTime:     r.EndTime,
	}

	return run
}

type GroupRunsHandler struct {
	log       zerolog.Logger
	ah        *action.ActionHandler
	groupType common.GroupType
}

func NewGroupRunsHandler(log zerolog.Logger, ah *action.ActionHandler, groupType common.GroupType) *GroupRunsHandler {
	return &GroupRunsHandler{log: log, ah: ah, groupType: groupType}
}

func (h *GroupRunsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(w, r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *GroupRunsHandler) do(w http.ResponseWriter, r *http.Request) ([]*gwapitypes.RunsResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)

	ropts, err := parseGroupRunsRequestOptions(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var ref string
	switch h.groupType {
	case common.GroupTypeProject:
		ref, err = url.PathUnescape(vars["projectref"])
		if err != nil {
			return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("projectref is empty"))
		}
	case common.GroupTypeUser:
		ref = vars["userref"]
	}

	areq := &action.GetGroupRunsRequest{
		GroupType: h.groupType,
		Ref:       ref,

		Cursor: ropts.Cursor,

		Limit:         ropts.Limit,
		SortDirection: action.SortDirection(ropts.SortDirection),

		StartRunCounter: ropts.StartRunCounter,
		SubGroup:        ropts.SubGroup,
		PhaseFilter:     ropts.PhaseFilter,
		ResultFilter:    ropts.ResultFilter,
	}

	ares, err := h.ah.GetGroupRuns(ctx, areq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := make([]*gwapitypes.RunsResponse, len(ares.Runs))
	for i, r := range ares.Runs {
		res[i] = createRunsResponse(r)
	}

	addCursorHeader(w, ares.Cursor)

	return res, nil
}

type RunActionsHandler struct {
	log       zerolog.Logger
	ah        *action.ActionHandler
	groupType common.GroupType
}

func NewRunActionsHandler(log zerolog.Logger, ah *action.ActionHandler, groupType common.GroupType) *RunActionsHandler {
	return &RunActionsHandler{log: log, ah: ah, groupType: groupType}
}

func (h *RunActionsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *RunActionsHandler) do(r *http.Request) (*gwapitypes.RunResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)

	var err error
	var ref string
	switch h.groupType {
	case common.GroupTypeProject:
		ref, err = url.PathUnescape(vars["projectref"])
		if err != nil {
			return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("projectref is empty"))
		}
	case common.GroupTypeUser:
		ref = vars["userref"]
	}

	runNumberStr := vars["runnumber"]

	var runNumber uint64
	if runNumberStr != "" {
		var err error
		runNumber, err = strconv.ParseUint(runNumberStr, 10, 64)
		if err != nil {
			return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err, util.WithAPIErrorMsg("cannot parse run number"), serrors.InvalidRunNumber())
		}
	}

	var req gwapitypes.RunActionsRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	areq := &action.RunActionsRequest{
		GroupType:  h.groupType,
		Ref:        ref,
		RunNumber:  runNumber,
		ActionType: action.RunActionType(req.ActionType),
		FromStart:  req.FromStart,
	}

	runResp, err := h.ah.RunAction(ctx, areq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := createRunResponse(runResp.Run, runResp.RunConfig)

	return res, nil
}

type RunTaskActionsHandler struct {
	log       zerolog.Logger
	ah        *action.ActionHandler
	groupType common.GroupType
}

func NewRunTaskActionsHandler(log zerolog.Logger, ah *action.ActionHandler, groupType common.GroupType) *RunTaskActionsHandler {
	return &RunTaskActionsHandler{log: log, ah: ah, groupType: groupType}
}

func (h *RunTaskActionsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

}

func (h *RunTaskActionsHandler) do(r *http.Request) error {
	ctx := r.Context()
	vars := mux.Vars(r)

	var err error
	var ref string
	switch h.groupType {
	case common.GroupTypeProject:
		ref, err = url.PathUnescape(vars["projectref"])
		if err != nil {
			return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("projectref is empty"))
		}
	case common.GroupTypeUser:
		ref = vars["userref"]
	}

	runNumberStr := vars["runnumber"]

	var runNumber uint64
	if runNumberStr != "" {
		var err error
		runNumber, err = strconv.ParseUint(runNumberStr, 10, 64)
		if err != nil {
			return util.NewAPIErrorWrap(util.ErrBadRequest, err, util.WithAPIErrorMsg("cannot parse run number"), serrors.InvalidRunNumber())
		}
	}
	taskID := vars["taskid"]

	var req gwapitypes.RunTaskActionsRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	areq := &action.RunTaskActionsRequest{
		GroupType:  h.groupType,
		Ref:        ref,
		RunNumber:  runNumber,
		TaskID:     taskID,
		ActionType: action.RunTaskActionType(req.ActionType),
	}

	err = h.ah.RunTaskAction(ctx, areq)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

type LogsHandler struct {
	log       zerolog.Logger
	ah        *action.ActionHandler
	groupType common.GroupType
}

func NewLogsHandler(log zerolog.Logger, ah *action.ActionHandler, groupType common.GroupType) *LogsHandler {
	return &LogsHandler{log: log, ah: ah, groupType: groupType}
}

func (h *LogsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(w, r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}
}

func (h *LogsHandler) do(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	vars := mux.Vars(r)

	q := r.URL.Query()

	var err error
	var ref string
	switch h.groupType {
	case common.GroupTypeProject:
		ref, err = url.PathUnescape(vars["projectref"])
		if err != nil {
			return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("projectref is empty"))
		}
	case common.GroupTypeUser:
		ref = vars["userref"]
	}

	runNumberStr := vars["runnumber"]

	var runNumber uint64
	if runNumberStr != "" {
		var err error
		runNumber, err = strconv.ParseUint(runNumberStr, 10, 64)
		if err != nil {
			return util.NewAPIErrorWrap(util.ErrBadRequest, err, util.WithAPIErrorMsg("cannot parse run number"), serrors.InvalidRunNumber())
		}
	}

	taskID := vars["taskid"]

	_, setup := q["setup"]
	stepStr := q.Get("step")
	if !setup && stepStr == "" {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("no setup or step number provided"))
	}
	if setup && stepStr != "" {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("both setup and step number provided"))
	}

	var step int
	if stepStr != "" {
		var err error
		step, err = strconv.Atoi(stepStr)
		if err != nil {
			return util.NewAPIErrorWrap(util.ErrBadRequest, err, util.WithAPIErrorMsg("cannot parse step number"), serrors.InvalidRunTaskStepNumber())
		}
	}

	follow := false
	if _, ok := q["follow"]; ok {
		follow = true
	}

	areq := &action.GetLogsRequest{
		GroupType: h.groupType,
		Ref:       ref,
		RunNumber: runNumber,
		TaskID:    taskID,
		Setup:     setup,
		Step:      step,
		Follow:    follow,
	}

	resp, err := h.ah.GetLogs(ctx, areq)
	if err != nil {
		return errors.WithStack(err)
	}

	// write and flush the headers so the client will receive the response
	// header also if there're currently no lines to send
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Content-Type", "text/plain;charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	var flusher http.Flusher
	if fl, ok := w.(http.Flusher); ok {
		flusher = fl
	}
	if flusher != nil {
		flusher.Flush()
	}

	defer resp.Body.Close()
	if err := sendLogs(w, resp.Body); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// sendLogs streams received logs lines and flushes them
func sendLogs(w io.Writer, r io.Reader) error {
	buf := make([]byte, 4096)

	var flusher http.Flusher
	if fl, ok := w.(http.Flusher); ok {
		flusher = fl
	}
	stop := false
	for {
		if stop {
			return nil
		}
		n, err := r.Read(buf)
		if err != nil {
			if err != io.EOF {
				return errors.WithStack(err)
			}
			if n == 0 {
				return nil
			}
			stop = true
		}
		if _, err := w.Write(buf[:n]); err != nil {
			return errors.WithStack(err)
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

type LogsDeleteHandler struct {
	log       zerolog.Logger
	ah        *action.ActionHandler
	groupType common.GroupType
}

func NewLogsDeleteHandler(log zerolog.Logger, ah *action.ActionHandler, groupType common.GroupType) *LogsDeleteHandler {
	return &LogsDeleteHandler{log: log, ah: ah, groupType: groupType}
}

func (h *LogsDeleteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *LogsDeleteHandler) do(r *http.Request) error {
	ctx := r.Context()
	vars := mux.Vars(r)

	q := r.URL.Query()

	var err error
	var ref string
	switch h.groupType {
	case common.GroupTypeProject:
		ref, err = url.PathUnescape(vars["projectref"])
		if err != nil {
			return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("projectref is empty"))
		}
	case common.GroupTypeUser:
		ref = vars["userref"]
	}

	runNumberStr := vars["runnumber"]

	var runNumber uint64
	if runNumberStr != "" {
		var err error
		runNumber, err = strconv.ParseUint(runNumberStr, 10, 64)
		if err != nil {
			return util.NewAPIErrorWrap(util.ErrBadRequest, err, util.WithAPIErrorMsg("cannot parse run number"), serrors.InvalidRunNumber())
		}
	}

	taskID := vars["taskid"]

	_, setup := q["setup"]
	stepStr := q.Get("step")
	if !setup && stepStr == "" {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("no setup or step number provided"))
	}
	if setup && stepStr != "" {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("both setup and step number provided"))
	}

	var step int
	if stepStr != "" {
		var err error
		step, err = strconv.Atoi(stepStr)
		if err != nil {
			return util.NewAPIErrorWrap(util.ErrBadRequest, err, util.WithAPIErrorMsg("cannot parse step number"), serrors.InvalidRunTaskStepNumber())
		}
	}

	areq := &action.DeleteLogsRequest{
		GroupType: h.groupType,
		Ref:       ref,
		RunNumber: runNumber,
		TaskID:    taskID,
		Setup:     setup,
		Step:      step,
	}

	if err := h.ah.DeleteLogs(ctx, areq); err != nil {
		return errors.WithStack(err)
	}

	return nil
}
