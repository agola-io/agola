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
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"github.com/sorintlab/agola/internal/services/gateway/action"
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
		case *rstypes.SaveCacheStep:
			s.Name = "save cache"
		case *rstypes.RestoreCacheStep:
			s.Name = "restore cache"
		}

		t.Steps[i] = s
	}

	return t
}

type RunHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewRunHandler(logger *zap.Logger, ah *action.ActionHandler) *RunHandler {
	return &RunHandler{log: logger.Sugar(), ah: ah}
}

func (h *RunHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	runID := vars["runid"]

	runResp, err := h.ah.GetRun(ctx, runID)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := createRunResponse(runResp.Run, runResp.RunConfig)
	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type RuntaskHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewRuntaskHandler(logger *zap.Logger, ah *action.ActionHandler) *RuntaskHandler {
	return &RuntaskHandler{log: logger.Sugar(), ah: ah}
}

func (h *RuntaskHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	runID := vars["runid"]
	taskID := vars["taskid"]

	runResp, err := h.ah.GetRun(ctx, runID)
	if httpError(w, err) {
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
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewRunsHandler(logger *zap.Logger, ah *action.ActionHandler) *RunsHandler {
	return &RunsHandler{log: logger.Sugar(), ah: ah}
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

	areq := &action.GetRunsRequest{
		PhaseFilter:  phaseFilter,
		Groups:       groups,
		LastRun:      lastRun,
		ChangeGroups: changeGroups,
		StartRunID:   start,
		Limit:        limit,
		Asc:          asc,
	}
	runsResp, err := h.ah.GetRuns(ctx, areq)
	if httpError(w, err) {
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

type RunActionsRequest struct {
	ActionType action.RunActionType `json:"action_type"`

	// Restart
	FromStart bool `json:"from_start"`
}

type RunActionsHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewRunActionsHandler(logger *zap.Logger, ah *action.ActionHandler) *RunActionsHandler {
	return &RunActionsHandler{log: logger.Sugar(), ah: ah}
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

	areq := &action.RunActionsRequest{
		RunID:      runID,
		ActionType: req.ActionType,
		FromStart:  req.FromStart,
	}

	err := h.ah.RunAction(ctx, areq)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}
}

type RunTaskActionsRequest struct {
	ActionType          action.RunTaskActionType `json:"action_type"`
	ApprovalAnnotations map[string]string        `json:"approval_annotations,omitempty"`
}

type RunTaskActionsHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewRunTaskActionsHandler(logger *zap.Logger, ah *action.ActionHandler) *RunTaskActionsHandler {
	return &RunTaskActionsHandler{log: logger.Sugar(), ah: ah}
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

	areq := &action.RunTaskActionsRequest{
		RunID:               runID,
		TaskID:              taskID,
		ActionType:          req.ActionType,
		ApprovalAnnotations: req.ApprovalAnnotations,
	}

	err := h.ah.RunTaskAction(ctx, areq)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}
}

type LogsHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewLogsHandler(logger *zap.Logger, ah *action.ActionHandler) *LogsHandler {
	return &LogsHandler{log: logger.Sugar(), ah: ah}
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

	areq := &action.GetLogsRequest{
		RunID:  runID,
		TaskID: taskID,
		Setup:  setup,
		Step:   step,
		Follow: follow,
		Stream: stream,
	}

	resp, err := h.ah.GetLogs(ctx, areq)
	if httpError(w, err) {
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
