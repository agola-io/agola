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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/objectstorage"
	"agola.io/agola/internal/services/runservice/action"
	"agola.io/agola/internal/services/runservice/db"
	"agola.io/agola/internal/services/runservice/store"
	"agola.io/agola/internal/sql"
	"agola.io/agola/internal/util"
	rsapitypes "agola.io/agola/services/runservice/api/types"
	"agola.io/agola/services/runservice/types"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

type LogsHandler struct {
	log zerolog.Logger
	d   *db.DB
	ost *objectstorage.ObjStorage
}

func NewLogsHandler(log zerolog.Logger, d *db.DB, ost *objectstorage.ObjStorage) *LogsHandler {
	return &LogsHandler{
		log: log,
		d:   d,
		ost: ost,
	}
}

func (h *LogsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	q := r.URL.Query()

	runID := q.Get("runid")
	if runID == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	taskID := q.Get("taskid")
	if taskID == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	_, setup := q["setup"]
	stepStr := q.Get("step")
	if !setup && stepStr == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	if setup && stepStr != "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	var step int
	if stepStr != "" {
		var err error
		step, err = strconv.Atoi(stepStr)
		if err != nil {
			http.Error(w, "", http.StatusBadRequest)
			return
		}
	}

	follow := false
	if _, ok := q["follow"]; ok {
		follow = true
	}

	if sendError, err := h.readTaskLogs(ctx, runID, taskID, setup, step, w, follow); err != nil {
		h.log.Err(err).Send()
		if sendError {
			switch {
			case util.APIErrorIs(err, util.ErrNotExist):
				util.HTTPError(w, util.NewAPIError(util.ErrNotExist, errors.Wrapf(err, "log doesn't exist")))
			default:
				util.HTTPError(w, err)
			}
		}
	}
}

func (h *LogsHandler) readTaskLogs(ctx context.Context, runID, taskID string, setup bool, step int, w http.ResponseWriter, follow bool) (bool, error) {
	var r *types.Run
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		r, err = h.d.GetRun(tx, runID)
		if err != nil {
			return errors.WithStack(err)
		}
		return nil
	})
	if err != nil {
		return true, errors.WithStack(err)
	}

	if r == nil {
		return true, util.NewAPIError(util.ErrNotExist, errors.Errorf("no such run with id: %s", runID))
	}

	task, ok := r.Tasks[taskID]
	if !ok {
		return true, util.NewAPIError(util.ErrNotExist, errors.Errorf("no such task with ID %s in run %s", taskID, runID))
	}
	if len(task.Steps) <= step {
		return true, util.NewAPIError(util.ErrNotExist, errors.Errorf("no such step for task %s in run %s", taskID, runID))
	}

	// if the log has been already fetched use it, otherwise fetch it from the executor
	if task.Steps[step].LogPhase == types.RunTaskFetchPhaseFinished {
		var logPath string
		if setup {
			logPath = store.OSTRunTaskSetupLogPath(task.ID)
		} else {
			logPath = store.OSTRunTaskStepLogPath(task.ID, step)
		}
		f, err := h.ost.ReadObject(logPath)
		if err != nil {
			if objectstorage.IsNotExist(err) {
				return true, util.NewAPIError(util.ErrNotExist, err)
			}
			return true, errors.WithStack(err)
		}
		defer f.Close()
		return false, sendLogs(w, f)
	}

	var et *types.ExecutorTask
	var executor *types.Executor
	err = h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error

		et, err = h.d.GetExecutorTaskByRunTask(tx, runID, task.ID)
		if err != nil {
			return errors.WithStack(err)
		}
		if et == nil {
			return util.NewAPIError(util.ErrNotExist, errors.Errorf("executor task for run task with id %q doesn't exist", task.ID))
		}

		executor, err = h.d.GetExecutorByExecutorID(tx, et.Spec.ExecutorID)
		if err != nil {
			return errors.WithStack(err)
		}
		if executor == nil {
			return util.NewAPIError(util.ErrNotExist, errors.Errorf("executor with id %q doesn't exist", et.Spec.ExecutorID))
		}

		return nil
	})
	if err != nil {
		return true, errors.WithStack(err)
	}

	var url string
	if setup {
		url = fmt.Sprintf("%s/api/v1alpha/executor/logs?taskid=%s&setup", executor.ListenURL, et.ID)
	} else {
		url = fmt.Sprintf("%s/api/v1alpha/executor/logs?taskid=%s&step=%d", executor.ListenURL, et.ID, step)
	}
	if follow {
		url += "&follow"
	}
	req, err := http.Get(url)
	if err != nil {
		return true, errors.WithStack(err)
	}
	defer req.Body.Close()
	if req.StatusCode != http.StatusOK {
		if req.StatusCode == http.StatusNotFound {
			return true, util.NewAPIError(util.ErrNotExist, errors.New("no log on executor"))
		}
		return true, errors.Errorf("received http status: %d", req.StatusCode)
	}

	// write and flush the headers so the client will receive the response
	// header also if there're currently no lines to send
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	var flusher http.Flusher
	if fl, ok := w.(http.Flusher); ok {
		flusher = fl
	}
	if flusher != nil {
		flusher.Flush()
	}

	return false, sendLogs(w, req.Body)
}

func sendLogs(w http.ResponseWriter, r io.Reader) error {
	buf := make([]byte, 406)

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
		//data, err := br.ReadBytes('\n')
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
	log zerolog.Logger
	d   *db.DB
	ost *objectstorage.ObjStorage
}

func NewLogsDeleteHandler(log zerolog.Logger, d *db.DB, ost *objectstorage.ObjStorage) *LogsDeleteHandler {
	return &LogsDeleteHandler{
		log: log,
		d:   d,
		ost: ost,
	}
}

func (h *LogsDeleteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	q := r.URL.Query()

	runID := q.Get("runid")
	if runID == "" {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Errorf("runid is empty")))
		return
	}
	taskID := q.Get("taskid")
	if taskID == "" {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Errorf("taskid is empty")))
		return
	}

	_, setup := q["setup"]
	stepStr := q.Get("step")
	if !setup && stepStr == "" {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Errorf("setup is false and step is empty")))
		return
	}
	if setup && stepStr != "" {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Errorf("setup is true and step is %s", stepStr)))
		return
	}

	var step int
	if stepStr != "" {
		var err error
		step, err = strconv.Atoi(stepStr)
		if err != nil {
			util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Errorf("step %s is not a valid number", stepStr)))
			return
		}
	}

	if err := h.deleteTaskLogs(ctx, runID, taskID, setup, step, w); err != nil {
		h.log.Err(err).Send()
		switch {
		case util.APIErrorIs(err, util.ErrNotExist):
			util.HTTPError(w, util.NewAPIError(util.ErrNotExist, errors.Wrapf(err, "log doesn't exist")))
		default:
			util.HTTPError(w, err)
		}
	}
}

func (h *LogsDeleteHandler) deleteTaskLogs(ctx context.Context, runID, taskID string, setup bool, step int, w http.ResponseWriter) error {
	var r *types.Run
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		r, err = h.d.GetRun(tx, runID)
		if err != nil {
			return errors.WithStack(err)
		}
		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	if r == nil {
		return util.NewAPIError(util.ErrNotExist, errors.Errorf("no such run with id: %s", runID))
	}

	task, ok := r.Tasks[taskID]
	if !ok {
		return util.NewAPIError(util.ErrNotExist, errors.Errorf("no such task with ID %s in run %s", taskID, runID))
	}
	if len(task.Steps) <= step {
		return util.NewAPIError(util.ErrNotExist, errors.Errorf("no such step for task %s in run %s", taskID, runID))
	}

	if task.Steps[step].LogPhase == types.RunTaskFetchPhaseFinished {
		var logPath string
		if setup {
			logPath = store.OSTRunTaskSetupLogPath(task.ID)
		} else {
			logPath = store.OSTRunTaskStepLogPath(task.ID, step)
		}
		err := h.ost.DeleteObject(logPath)
		if err != nil {
			if objectstorage.IsNotExist(err) {
				return util.NewAPIError(util.ErrNotExist, err)
			}
			return errors.WithStack(err)
		}
		return nil
	}
	return util.NewAPIError(util.ErrBadRequest, errors.Errorf("Log for task %s in run %s is not yet archived", taskID, runID))
}

type ChangeGroupsUpdateTokensHandler struct {
	log zerolog.Logger
	d   *db.DB
	ah  *action.ActionHandler
}

func NewChangeGroupsUpdateTokensHandler(log zerolog.Logger, d *db.DB, ah *action.ActionHandler) *ChangeGroupsUpdateTokensHandler {
	return &ChangeGroupsUpdateTokensHandler{
		log: log,
		d:   d,
		ah:  ah,
	}
}

func (h *ChangeGroupsUpdateTokensHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	groups := query["changegroup"]

	var cgt *types.ChangeGroupsUpdateToken

	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		cgt, err = h.ah.GetChangeGroupsUpdateTokens(tx, groups)
		return errors.WithStack(err)
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cgts, err := types.MarshalChangeGroupsUpdateToken(cgt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, cgts); err != nil {
		h.log.Err(err).Send()
	}
}

type RunHandler struct {
	log zerolog.Logger
	d   *db.DB
	ah  *action.ActionHandler
}

func NewRunHandler(log zerolog.Logger, d *db.DB, ah *action.ActionHandler) *RunHandler {
	return &RunHandler{
		log: log,
		d:   d,
		ah:  ah,
	}
}

func (h *RunHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	runRef := vars["runid"]

	query := r.URL.Query()
	changeGroups := query["changegroup"]

	var run *types.Run
	var rc *types.RunConfig
	var cgt *types.ChangeGroupsUpdateToken

	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		run, err = h.d.GetRun(tx, runRef)
		if err != nil {
			return errors.WithStack(err)
		}

		if run == nil {
			return nil
		}

		rc, err = h.d.GetRunConfig(tx, run.RunConfigID)
		if err != nil {
			return errors.WithStack(err)
		}

		cgt, err = h.ah.GetChangeGroupsUpdateTokens(tx, changeGroups)
		return errors.WithStack(err)
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if run == nil {
		util.HTTPError(w, util.NewAPIError(util.ErrNotExist, errors.Errorf("run with id %q doesn't exist", runRef)))
		return
	}

	if rc == nil {
		util.HTTPError(w, util.NewAPIError(util.ErrNotExist, errors.Errorf("run config for run with id %q doesn't exist", runRef)))
		return
	}

	cgts, err := types.MarshalChangeGroupsUpdateToken(cgt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	res := &rsapitypes.RunResponse{
		Run:                     run,
		RunConfig:               rc,
		ChangeGroupsUpdateToken: cgts,
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

type RunByGroupHandler struct {
	log zerolog.Logger
	d   *db.DB
	ah  *action.ActionHandler
}

func NewRunByGroupHandler(log zerolog.Logger, d *db.DB, ah *action.ActionHandler) *RunByGroupHandler {
	return &RunByGroupHandler{
		log: log,
		d:   d,
		ah:  ah,
	}
}

func (h *RunByGroupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)

	query := r.URL.Query()
	changeGroups := query["changegroup"]

	group, err := url.PathUnescape(vars["group"])
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Errorf("group is empty")))
		return
	}

	runCounterStr := vars["runcounter"]

	var runCounter uint64
	if runCounterStr == "" {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Errorf("runcounter is empty")))
	}
	if runCounterStr != "" {
		var err error
		runCounter, err = strconv.ParseUint(runCounterStr, 10, 64)
		if err != nil {
			util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "cannot parse runcounter")))
			return
		}
	}

	var run *types.Run
	var rc *types.RunConfig
	var cgt *types.ChangeGroupsUpdateToken

	err = h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		run, err = h.d.GetRunByGroup(tx, group, runCounter)
		if err != nil {
			return errors.WithStack(err)
		}

		if run == nil {
			return nil
		}

		rc, err = h.d.GetRunConfig(tx, run.RunConfigID)
		if err != nil {
			return errors.WithStack(err)
		}

		cgt, err = h.ah.GetChangeGroupsUpdateTokens(tx, changeGroups)
		return errors.WithStack(err)
	})
	if err != nil {
		h.log.Err(err).Send()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if run == nil {
		util.HTTPError(w, util.NewAPIError(util.ErrNotExist, errors.Errorf("run for group %q with counter %d doesn't exist", group, runCounter)))
	}

	if rc == nil {
		util.HTTPError(w, util.NewAPIError(util.ErrNotExist, errors.Errorf("run config for run with id %q doesn't exist", run.ID)))
		return
	}

	cgts, err := types.MarshalChangeGroupsUpdateToken(cgt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	res := &rsapitypes.RunResponse{
		Run:                     run,
		RunConfig:               rc,
		ChangeGroupsUpdateToken: cgts,
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}

}

const (
	DefaultRunsLimit  = 25
	MaxRunsLimit      = 40
	MaxRunEventsLimit = 40
)

type RunsHandler struct {
	log zerolog.Logger
	d   *db.DB

	ah *action.ActionHandler
}

func NewRunsHandler(log zerolog.Logger, d *db.DB, ah *action.ActionHandler) *RunsHandler {
	return &RunsHandler{
		log: log,
		d:   d,
		ah:  ah,
	}
}

func (h *RunsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	phaseFilter := types.RunPhaseFromStringSlice(query["phase"])
	resultFilter := types.RunResultFromStringSlice(query["result"])

	changeGroups := query["changegroup"]
	groups := query["group"]
	_, lastRun := query["lastrun"]

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
	sortOrder := types.SortOrderDesc
	if _, ok := query["asc"]; ok {
		sortOrder = types.SortOrderAsc
	}

	var startRunSequence uint64
	startRunSequenceStr := query.Get("start")
	if startRunSequenceStr != "" {
		var err error
		startRunSequence, err = strconv.ParseUint(startRunSequenceStr, 10, 64)
		if err != nil {
			util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "cannot parse run sequence")))
			return
		}
	}

	var runs []*types.Run
	var cgt *types.ChangeGroupsUpdateToken

	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		runs, err = h.d.GetRuns(tx, groups, lastRun, phaseFilter, resultFilter, startRunSequence, limit, sortOrder)
		if err != nil {
			return errors.WithStack(err)
		}

		cgt, err = h.ah.GetChangeGroupsUpdateTokens(tx, changeGroups)
		return errors.WithStack(err)
	})
	if err != nil {
		h.log.Err(err).Send()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cgts, err := types.MarshalChangeGroupsUpdateToken(cgt)
	if err != nil {
		h.log.Err(err).Send()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	res := &rsapitypes.GetRunsResponse{
		Runs:                    runs,
		ChangeGroupsUpdateToken: cgts,
	}
	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

type RunsByGroupHandler struct {
	log zerolog.Logger
	d   *db.DB
	ah  *action.ActionHandler
}

func NewRunsByGroupHandler(log zerolog.Logger, d *db.DB, ah *action.ActionHandler) *RunsByGroupHandler {
	return &RunsByGroupHandler{
		log: log,
		d:   d,
		ah:  ah,
	}
}

func (h *RunsByGroupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	query := r.URL.Query()
	phaseFilter := types.RunPhaseFromStringSlice(query["phase"])
	resultFilter := types.RunResultFromStringSlice(query["result"])

	changeGroups := query["changegroup"]

	group, err := url.PathUnescape(vars["group"])
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Errorf("group is empty")))
		return
	}

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
	sortOrder := types.SortOrderDesc
	if _, ok := query["asc"]; ok {
		sortOrder = types.SortOrderAsc
	}

	var startRunCounter uint64
	startRunCounterStr := query.Get("start")
	if startRunCounterStr != "" {
		var err error
		startRunCounter, err = strconv.ParseUint(startRunCounterStr, 10, 64)
		if err != nil {
			util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "cannot parse runcounter")))
			return
		}
	}

	var runs []*types.Run
	var cgt *types.ChangeGroupsUpdateToken

	err = h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		runs, err = h.d.GetGroupRuns(tx, group, phaseFilter, resultFilter, startRunCounter, limit, sortOrder)
		if err != nil {
			h.log.Err(err).Send()
			return errors.WithStack(err)
		}

		cgt, err = h.ah.GetChangeGroupsUpdateTokens(tx, changeGroups)
		return errors.WithStack(err)
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cgts, err := types.MarshalChangeGroupsUpdateToken(cgt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	res := &rsapitypes.GetRunsResponse{
		Runs:                    runs,
		ChangeGroupsUpdateToken: cgts,
	}
	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

type RunCreateHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewRunCreateHandler(log zerolog.Logger, ah *action.ActionHandler) *RunCreateHandler {
	return &RunCreateHandler{
		log: log,
		ah:  ah,
	}
}

func (h *RunCreateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req rsapitypes.RunCreateRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	creq := &action.RunCreateRequest{
		RunConfigTasks:    req.RunConfigTasks,
		Name:              req.Name,
		Group:             req.Group,
		SetupErrors:       req.SetupErrors,
		StaticEnvironment: req.StaticEnvironment,
		CacheGroup:        req.CacheGroup,

		RunID:      req.RunID,
		FromStart:  req.FromStart,
		ResetTasks: req.ResetTasks,

		Environment:             req.Environment,
		Annotations:             req.Annotations,
		ChangeGroupsUpdateToken: req.ChangeGroupsUpdateToken,
	}
	rb, err := h.ah.CreateRun(ctx, creq)
	if err != nil {
		h.log.Err(err).Send()
		util.HTTPError(w, err)
		return
	}

	res := &rsapitypes.RunResponse{
		Run:       rb.Run,
		RunConfig: rb.Rc,
	}

	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

type RunActionsHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewRunActionsHandler(log zerolog.Logger, ah *action.ActionHandler) *RunActionsHandler {
	return &RunActionsHandler{
		log: log,
		ah:  ah,
	}
}

func (h *RunActionsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	runID := vars["runid"]

	var req rsapitypes.RunActionsRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch req.ActionType {
	case rsapitypes.RunActionTypeChangePhase:
		creq := &action.RunChangePhaseRequest{
			RunID:                   runID,
			Phase:                   req.Phase,
			ChangeGroupsUpdateToken: req.ChangeGroupsUpdateToken,
		}
		if err := h.ah.ChangeRunPhase(ctx, creq); err != nil {
			h.log.Err(err).Send()
			util.HTTPError(w, err)
			return
		}
	case rsapitypes.RunActionTypeStop:
		creq := &action.RunStopRequest{
			RunID:                   runID,
			ChangeGroupsUpdateToken: req.ChangeGroupsUpdateToken,
		}
		if err := h.ah.StopRun(ctx, creq); err != nil {
			h.log.Err(err).Send()
			util.HTTPError(w, err)
			return
		}
	default:
		http.Error(w, "", http.StatusBadRequest)
		return
	}
}

type RunTaskActionsHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewRunTaskActionsHandler(log zerolog.Logger, ah *action.ActionHandler) *RunTaskActionsHandler {
	return &RunTaskActionsHandler{
		log: log,
		ah:  ah,
	}
}

func (h *RunTaskActionsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	runID := vars["runid"]
	taskID := vars["taskid"]

	var req rsapitypes.RunTaskActionsRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch req.ActionType {
	case rsapitypes.RunTaskActionTypeSetAnnotations:
		creq := &action.RunTaskSetAnnotationsRequest{
			RunID:                   runID,
			TaskID:                  taskID,
			Annotations:             req.Annotations,
			ChangeGroupsUpdateToken: req.ChangeGroupsUpdateToken,
		}
		if err := h.ah.RunTaskSetAnnotations(ctx, creq); err != nil {
			h.log.Err(err).Send()
			util.HTTPError(w, err)
			return
		}

	case rsapitypes.RunTaskActionTypeApprove:
		creq := &action.RunTaskApproveRequest{
			RunID:                   runID,
			TaskID:                  taskID,
			ChangeGroupsUpdateToken: req.ChangeGroupsUpdateToken,
		}
		if err := h.ah.ApproveRunTask(ctx, creq); err != nil {
			h.log.Err(err).Send()
			util.HTTPError(w, err)
			return
		}

	default:
		http.Error(w, "", http.StatusBadRequest)
		return
	}
}

type RunEventsHandler struct {
	log zerolog.Logger
	d   *db.DB
	ost *objectstorage.ObjStorage
}

func NewRunEventsHandler(log zerolog.Logger, d *db.DB, ost *objectstorage.ObjStorage) *RunEventsHandler {
	return &RunEventsHandler{
		log: log,
		d:   d,
		ost: ost,
	}
}

//
func (h *RunEventsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	q := r.URL.Query()

	// TODO(sgotti) handle additional events filtering (by type, etc...)
	var startRunEventSequence uint64
	startRunEventSequenceStr := q.Get("startsequence")
	if startRunEventSequenceStr != "" {
		var err error
		startRunEventSequence, err = strconv.ParseUint(startRunEventSequenceStr, 10, 64)
		if err != nil {
			util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "cannot parse startsequence")))
			return
		}
	}

	if err := h.sendRunEvents(ctx, startRunEventSequence, w); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *RunEventsHandler) sendRunEvents(ctx context.Context, startRunEventSequence uint64, w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	var flusher http.Flusher
	if fl, ok := w.(http.Flusher); ok {
		flusher = fl
	}

	// TODO(sgotti) use a notify system instead of polling the database

	curEventSequence := startRunEventSequence

	if startRunEventSequence == 0 {
		err := h.d.Do(ctx, func(tx *sql.Tx) error {
			// start from last event
			runEvent, err := h.d.GetLastRunEvent(tx)
			if err != nil {
				return errors.WithStack(err)
			}
			if runEvent == nil {
				return nil
			}

			curEventSequence = runEvent.Sequence

			return nil
		})
		if err != nil {
			return errors.WithStack(err)
		}
	}

	for {
		var runEvents []*types.RunEvent
		err := h.d.Do(ctx, func(tx *sql.Tx) error {
			var err error
			runEvents, err = h.d.GetRunEventsFromSequence(tx, curEventSequence, MaxRunEventsLimit)
			if err != nil {
				return errors.WithStack(err)
			}

			return nil
		})
		if err != nil {
			return errors.WithStack(err)
		}

		for _, runEvent := range runEvents {
			curEventSequence = runEvent.Sequence

			runEventj, err := json.Marshal(runEvent)
			if err != nil {
				return errors.WithStack(err)
			}

			if _, err := w.Write([]byte(fmt.Sprintf("data: %s\n\n", runEventj))); err != nil {
				return errors.WithStack(err)
			}

			curEventSequence = runEvent.Sequence
		}

		if flusher != nil {
			flusher.Flush()
		}

		if len(runEvents) < MaxRunEventsLimit {
			time.Sleep(1 * time.Second)
		}
	}
}
