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

	rsapi "github.com/sorintlab/agola/internal/services/runservice/scheduler/api"
	rstypes "github.com/sorintlab/agola/internal/services/runservice/types"
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

	Tasks                map[string]*RunResponseTask `json:"tasks"`
	TasksWaitingApproval []string                    `json:"tasks_waiting_approval"`

	EnqueueTime *time.Time `json:"enqueue_time"`
	StartTime   *time.Time `json:"start_time"`
	EndTime     *time.Time `json:"end_time"`
}

type RunResponseTask struct {
	ID      string                         `json:"id"`
	Name    string                         `json:"name"`
	Status  rstypes.RunTaskStatus          `json:"status"`
	Level   int                            `json:"level"`
	Depends []*rstypes.RunConfigTaskDepend `json:"depends"`

	StartTime *time.Time `json:"start_time"`
	EndTime   *time.Time `json:"end_time"`
}

type RunTaskResponse struct {
	ID     string                `json:"id"`
	Name   string                `json:"name"`
	Status rstypes.RunTaskStatus `json:"status"`

	Steps []*RunTaskResponseStep `json:"steps"`

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
		Tasks:                make(map[string]*RunResponseTask),
		TasksWaitingApproval: r.TasksWaitingApproval(),

		EnqueueTime: r.EnqueueTime,
		StartTime:   r.StartTime,
		EndTime:     r.EndTime,
	}

	for name, rt := range r.RunTasks {
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
		Steps:  make([]*RunTaskResponseStep, len(rt.Steps)),

		StartTime: rt.StartTime,
		EndTime:   rt.EndTime,
	}

	for i := 0; i < len(t.Steps); i++ {
		s := &RunTaskResponseStep{
			StartTime: rt.Steps[i].StartTime,
			EndTime:   rt.Steps[i].EndTime,
		}
		rcts := rct.Steps[i]
		s.Phase = rt.Steps[i].Phase
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
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	res := createRunResponse(runResp.Run, runResp.RunConfig)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	run := runResp.Run
	rc := runResp.RunConfig

	rt, ok := run.RunTasks[taskID]
	if !ok {
		http.Error(w, "", http.StatusNotFound)
		return
	}
	rct := rc.Tasks[rt.ID]

	res := createRunTaskResponse(rt, rct)

	if err := json.NewEncoder(w).Encode(res); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

const (
	DefaultRunsLimit = 25
	MaxRunsLimit     = 40
)

type GetRunsResponse struct {
	Runs []*RunsResponse `json:"runs"`
}

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

	query := r.URL.Query()
	phaseFilter := query["phase"]
	groups := query["group"]
	changeGroups := query["changegroup"]

	limitS := query.Get("limit")
	limit := DefaultRunsLimit
	if limitS != "" {
		var err error
		limit, err = strconv.Atoi(limitS)
		if err != nil {
			http.Error(w, "", http.StatusBadRequest)
			return
		}
	}
	if limit < 0 {
		http.Error(w, "limit must be greater or equal than 0", http.StatusBadRequest)
		return
	}
	if limit > MaxRunsLimit {
		limit = MaxRunsLimit
	}
	asc := false
	if _, ok := query["asc"]; ok {
		asc = true
	}

	start := query.Get("start")

	runsResp, resp, err := h.runserviceClient.GetRuns(ctx, phaseFilter, groups, changeGroups, start, limit, asc)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	runs := make([]*RunsResponse, len(runsResp.Runs))
	for i, r := range runsResp.Runs {
		runs[i] = createRunsResponse(r)
	}
	getRunsResponse := &GetRunsResponse{
		Runs: runs,
	}

	if err := json.NewEncoder(w).Encode(getRunsResponse); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch req.ActionType {
	case RunActionTypeRestart:
		req := &rsapi.RunCreateRequest{
			RunID:     runID,
			FromStart: req.FromStart,
		}

		resp, err := h.runserviceClient.CreateRun(ctx, req)
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	case RunActionTypeStop:
		req := &rsapi.RunActionsRequest{
			ActionType: rsapi.RunActionTypeStop,
		}

		resp, err := h.runserviceClient.RunActions(ctx, runID, req)
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
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

	// TODO(sgotti) Check authorized call from client

	runID := r.URL.Query().Get("runID")
	if runID == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	taskID := r.URL.Query().Get("taskID")
	if taskID == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	s := r.URL.Query().Get("step")
	if s == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	step, err := strconv.Atoi(s)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	follow := false
	if _, ok := r.URL.Query()["follow"]; ok {
		follow = true
	}
	stream := false
	if _, ok := r.URL.Query()["stream"]; ok {
		stream = true
	}
	if follow {
		stream = true
	}

	resp, err := h.runserviceClient.GetLogs(ctx, runID, taskID, step, follow, stream)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, "", http.StatusInternalServerError)
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
