// This file is part of Agola
//
// Copyright (C) 2019 Sorint.lab
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package api

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/pkg/errors"
	rsapi "github.com/sorintlab/agola/internal/services/runservice/scheduler/api"
	rstypes "github.com/sorintlab/agola/internal/services/runservice/types"
	"github.com/sorintlab/agola/internal/util"
	"go.uber.org/zap"

	"github.com/gorilla/mux"
)

type RunsResponse struct {
	ID          string            `json:"id"`
	Counter     uint64            `json:"counter"`
	Name        string            `json:"name"`
	Annotations map[string]string `json:"annotations"`
	Phase       rstypes.RunPhase  `json:"phase"`
	Result      rstypes.RunResult `json:"result"`

	TasksWaitingApproval []string `json:"tasks_waiting_approval"`

	EnqueueTime *time.Time `json:"enqueue_time"`
	StartTime   *time.Time `json:"start_time"`
	EndTime     *time.Time `json:"end_time"`
}

type RunResponse struct {
	ID          string            `json:"id"`
	Counter     uint64            `json:"counter"`
	Name        string            `json:"name"`
	Annotations map[string]string `json:"annotations"`
	Phase       rstypes.RunPhase  `json:"phase"`
	Result      rstypes.RunResult `json:"result"`
	SetupErrors []string          `json:"setup_errors"`

	Tasks                map[string]*RunResponseTask `json:"tasks"`
	TasksWaitingApproval []string                    `json:"tasks_waiting_approval"`

	EnqueueTime *time.Time `json:"enqueue_time"`
	StartTime   *time.Time `json:"start_time"`
	EndTime     *time.Time `json:"end_time"`

	CanRestartFromScratch     bool `json:"can_restart_from_scratch"`
	CanRestartFromFailedTasks bool `json:"can_restart_from_failed_tasks"`
}

type RunResponseTask struct {
	ID      string                                  `json:"id"`
	Name    string                                  `json:"name"`
	Status  rstypes.RunTaskStatus                   `json:"status"`
	Level   int                                     `json:"level"`
	Depends map[string]*rstypes.RunConfigTaskDepend `json:"depends"`

	WaitingApproval     bool              `json:"waiting_approval"`
	Approved            bool              `json:"approved"`
	ApprovalAnnotations map[string]string `json:"approval_annotations"`

	StartTime *time.Time `json:"start_time"`
	EndTime   *time.Time `json:"end_time"`
}

type RunTaskResponse struct {
	ID     string                `json:"id"`
	Name   string                `json:"name"`
	Status rstypes.RunTaskStatus `json:"status"`

	WaitingApproval     bool              `json:"waiting_approval"`
	Approved            bool              `json:"approved"`
	ApprovalAnnotations map[string]string `json:"approval_annotations"`

	SetupStep *RunTaskResponseSetupStep `json:"setup_step"`
	Steps     []*RunTaskResponseStep    `json:"steps"`

	StartTime *time.Time `json:"start_time"`
	EndTime   *time.Time `json:"end_time"`
}

type RunTaskResponseSetupStep struct {
	Phase rstypes.ExecutorTaskPhase `json:"phase"`
	Name  string                    `json:"name"`

	StartTime *time.Time `json:"start_time"`
	EndTime   *time.Time `json:"end_time"`
}

type RunTaskResponseStep struct {
	Phase   rstypes.ExecutorTaskPhase `json:"phase"`
	Name    string                    `json:"name"`
	Command string                    `json:"command"`

	StartTime *time.Time `json:"start_time"`
	EndTime   *time.Time `json:"end_time"`
}

func createRunResponse(r *rstypes.Run, rc *rstypes.RunConfig) *RunResponse {
	run := &RunResponse{
		ID:                   r.ID,
		Counter:              r.Counter,
		Name:                 r.Name,
		Annotations:          r.Annotations,
		Phase:                r.Phase,
		Result:               r.Result,
		SetupErrors:          rc.SetupErrors,
		Tasks:                make(map[string]*RunResponseTask),
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

func createRunResponseTask(r *rstypes.Run, rt *rstypes.RunTask, rct *rstypes.RunConfigTask) *RunResponseTask {
	t := &RunResponseTask{
		ID:     rt.ID,
		Name:   rct.Name,
		Status: rt.Status,

		StartTime: rt.StartTime,
		EndTime:   rt.EndTime,

		WaitingApproval:     rt.WaitingApproval,
		Approved:            rt.Approved,
		ApprovalAnnotations: rt.ApprovalAnnotations,

		Level:   rct.Level,
		Depends: rct.Depends,
	}

	return t
}

func createRunTaskResponse(rt *rstypes.RunTask, rct *rstypes.RunConfigTask) *RunTaskResponse {
	t := &RunTaskResponse{
		ID:     rt.ID,
		Name:   rct.Name,
		Status: rt.Status,

		WaitingApproval:     rt.WaitingApproval,
		Approved:            rt.Approved,
		ApprovalAnnotations: rt.ApprovalAnnotations,

		Steps: make([]*RunTaskResponseStep, len(rt.Steps)),

		StartTime: rt.StartTime,
		EndTime:   rt.EndTime,
	}

	t.SetupStep = &RunTaskResponseSetupStep{
		Name:      "Task setup",
		Phase:     rt.SetupStep.Phase,
		StartTime: rt.SetupStep.StartTime,
		EndTime:   rt.SetupStep.EndTime,
	}

	for i := 0; i < len(t.Steps); i++ {
		s := &RunTaskResponseStep{
			Phase:     rt.Steps[i].Phase,
			StartTime: rt.Steps[i].StartTime,
			EndTime:   rt.Steps[i].EndTime,
		}
		rcts := rct.Steps[i]
		switch rcts := rcts.(type) {
		case *rstypes.RunStep:
			s.Name = rcts.Name
			s.Command = rcts.Command
		case *rstypes.SaveToWorkspaceStep:
			s.Name = "save to workspace"
		case *rstypes.RestoreWorkspaceStep:
			s.Name = "restore workspace"
		}

		t.Steps[i] = s
	}

	return t
}

type RunHandler struct {
	log              *zap.SugaredLogger
	runserviceClient *rsapi.Client
}

func NewRunHandler(logger *zap.Logger, runserviceClient *rsapi.Client) *RunHandler {
	return &RunHandler{log: logger.Sugar(), runserviceClient: runserviceClient}
}

func (h *RunHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	runID := vars["runid"]

	runResp, resp, err := h.runserviceClient.GetRun(ctx, runID)
	if httpErrorFromRemote(w, resp, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := createRunResponse(runResp.Run, runResp.RunConfig)
	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type RuntaskHandler struct {
	log              *zap.SugaredLogger
	runserviceClient *rsapi.Client
}

func NewRuntaskHandler(logger *zap.Logger, runserviceClient *rsapi.Client) *RuntaskHandler {
	return &RuntaskHandler{log: logger.Sugar(), runserviceClient: runserviceClient}
}

func (h *RuntaskHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	runID := vars["runid"]
	taskID := vars["taskid"]

	runResp, resp, err := h.runserviceClient.GetRun(ctx, runID)
	if httpErrorFromRemote(w, resp, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	run := runResp.Run
	rc := runResp.RunConfig

	rt, ok := run.Tasks[taskID]
	if !ok {
		httpError(w, util.NewErrNotFound(errors.Errorf("run %q task %q not found", runID, taskID)))
		return
	}
	rct := rc.Tasks[rt.ID]

	res := createRunTaskResponse(rt, rct)
	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

const (
	DefaultRunsLimit = 25
	MaxRunsLimit     = 40
)

func createRunsResponse(r *rstypes.Run) *RunsResponse {
	run := &RunsResponse{
		ID:          r.ID,
		Counter:     r.Counter,
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

type RunsHandler struct {
	log              *zap.SugaredLogger
	runserviceClient *rsapi.Client
}

func NewRunsHandler(logger *zap.Logger, runserviceClient *rsapi.Client) *RunsHandler {
	return &RunsHandler{log: logger.Sugar(), runserviceClient: runserviceClient}
}

func (h *RunsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	q := r.URL.Query()

	groups := q["group"]
	// we require that groups are specified to not return all runs
	if len(groups) == 0 {
		httpError(w, util.NewErrBadRequest(errors.Errorf("no groups specified")))
		return
	}

	phaseFilter := q["phase"]
	changeGroups := q["changegroup"]
	_, lastRun := q["lastrun"]

	limitS := q.Get("limit")
	limit := DefaultRunsLimit
	if limitS != "" {
		var err error
		limit, err = strconv.Atoi(limitS)
		if err != nil {
			httpError(w, util.NewErrBadRequest(errors.Wrapf(err, "cannot parse limit")))
			return
		}
	}
	if limit < 0 {
		httpError(w, util.NewErrBadRequest(errors.Errorf("limit must be greater or equal than 0")))
		return
	}
	if limit > MaxRunsLimit {
		limit = MaxRunsLimit
	}
	asc := false
	if _, ok := q["asc"]; ok {
		asc = true
	}

	start := q.Get("start")

	runsResp, resp, err := h.runserviceClient.GetRuns(ctx, phaseFilter, groups, lastRun, changeGroups, start, limit, asc)
	if httpErrorFromRemote(w, resp, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	runs := make([]*RunsResponse, len(runsResp.Runs))
	for i, r := range runsResp.Runs {
		runs[i] = createRunsResponse(r)
	}
	if err := httpResponse(w, http.StatusOK, runs); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type RunActionType string

const (
	RunActionTypeRestart RunActionType = "restart"
	RunActionTypeStop    RunActionType = "stop"
)

type RunActionsRequest struct {
	ActionType RunActionType `json:"action_type"`

	// Restart
	FromStart bool `json:"from_start"`
}

type RunActionsHandler struct {
	log              *zap.SugaredLogger
	runserviceClient *rsapi.Client
}

func NewRunActionsHandler(logger *zap.Logger, runserviceClient *rsapi.Client) *RunActionsHandler {
	return &RunActionsHandler{log: logger.Sugar(), runserviceClient: runserviceClient}
}

func (h *RunActionsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	runID := vars["runid"]

	var req RunActionsRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	switch req.ActionType {
	case RunActionTypeRestart:
		rsreq := &rsapi.RunCreateRequest{
			RunID:     runID,
			FromStart: req.FromStart,
		}

		resp, err := h.runserviceClient.CreateRun(ctx, rsreq)
		if httpErrorFromRemote(w, resp, err) {
			h.log.Errorf("err: %+v", err)
			return
		}

	case RunActionTypeStop:
		rsreq := &rsapi.RunActionsRequest{
			ActionType: rsapi.RunActionTypeStop,
		}

		resp, err := h.runserviceClient.RunActions(ctx, runID, rsreq)
		if httpErrorFromRemote(w, resp, err) {
			h.log.Errorf("err: %+v", err)
			return
		}
	}
}

type RunTaskActionType string

const (
	RunTaskActionTypeApprove RunTaskActionType = "approve"
)

type RunTaskActionsRequest struct {
	ActionType          RunTaskActionType `json:"action_type"`
	ApprovalAnnotations map[string]string `json:"approval_annotations,omitempty"`
}

type RunTaskActionsHandler struct {
	log              *zap.SugaredLogger
	runserviceClient *rsapi.Client
}

func NewRunTaskActionsHandler(logger *zap.Logger, runserviceClient *rsapi.Client) *RunTaskActionsHandler {
	return &RunTaskActionsHandler{log: logger.Sugar(), runserviceClient: runserviceClient}
}

func (h *RunTaskActionsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	runID := vars["runid"]
	taskID := vars["taskid"]

	var req RunTaskActionsRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	switch req.ActionType {
	case RunTaskActionTypeApprove:
		rsreq := &rsapi.RunTaskActionsRequest{
			ActionType:          rsapi.RunTaskActionTypeApprove,
			ApprovalAnnotations: req.ApprovalAnnotations,
		}

		resp, err := h.runserviceClient.RunTaskActions(ctx, runID, taskID, rsreq)
		if httpErrorFromRemote(w, resp, err) {
			h.log.Errorf("err: %+v", err)
			return
		}

	default:
		httpError(w, util.NewErrBadRequest(errors.Errorf("wrong action type %q", req.ActionType)))
		return
	}
}

type LogsHandler struct {
	log              *zap.SugaredLogger
	runserviceClient *rsapi.Client
}

func NewLogsHandler(logger *zap.Logger, runserviceClient *rsapi.Client) *LogsHandler {
	return &LogsHandler{log: logger.Sugar(), runserviceClient: runserviceClient}
}

func (h *LogsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	q := r.URL.Query()

	runID := q.Get("runID")
	if runID == "" {
		httpError(w, util.NewErrBadRequest(errors.Errorf("empty run id")))
		return
	}
	taskID := q.Get("taskID")
	if taskID == "" {
		httpError(w, util.NewErrBadRequest(errors.Errorf("empty task id")))
		return
	}

	_, setup := q["setup"]
	stepStr := q.Get("step")
	if !setup && stepStr == "" {
		httpError(w, util.NewErrBadRequest(errors.Errorf("no setup or step number provided")))
		return
	}
	if setup && stepStr != "" {
		httpError(w, util.NewErrBadRequest(errors.Errorf("both setup and step number provided")))
		return
	}

	var step int
	if stepStr != "" {
		var err error
		step, err = strconv.Atoi(stepStr)
		if err != nil {
			httpError(w, util.NewErrBadRequest(errors.Wrapf(err, "cannot parse step number")))
			return
		}
	}

	follow := false
	if _, ok := q["follow"]; ok {
		follow = true
	}
	stream := false
	if _, ok := q["stream"]; ok {
		stream = true
	}
	if follow {
		stream = true
	}

	resp, err := h.runserviceClient.GetLogs(ctx, runID, taskID, setup, step, follow, stream)
	if httpErrorFromRemote(w, resp, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if stream {
		w.Header().Set("Content-Type", "text/event-stream")
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	defer resp.Body.Close()
	if stream {
		if err := sendLogs(w, resp.Body); err != nil {
			h.log.Errorf("err: %+v", err)
			return
		}
	} else {
		if _, err := io.Copy(w, resp.Body); err != nil {
			h.log.Errorf("err: %+v", err)
			return
		}
	}
}

// sendLogs is used during streaming to flush logs lines
// TODO(sgotti) there's no need to do br.ReadBytes since the response is
// already flushed by the runservice.
func sendLogs(w io.Writer, r io.Reader) error {
	br := bufio.NewReader(r)

	var flusher http.Flusher
	if fl, ok := w.(http.Flusher); ok {
		flusher = fl
	}
	stop := false
	for {
		if stop {
			return nil
		}
		data, err := br.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				return err
			}
			if len(data) == 0 {
				return nil
			}
			stop = true
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}
