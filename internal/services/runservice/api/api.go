// Copyright 2024 Sorint.lab
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

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/objectstorage"
	serrors "agola.io/agola/internal/services/errors"
	"agola.io/agola/internal/services/runservice/action"
	"agola.io/agola/internal/services/runservice/db"
	"agola.io/agola/internal/services/runservice/store"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/internal/util"
	rsapitypes "agola.io/agola/services/runservice/api/types"
	"agola.io/agola/services/runservice/types"
)

const (
	agolaHasMoreHeader = "X-Agola-HasMore"
)

type requestOptions struct {
	Limit         int
	SortDirection types.SortDirection
}

func parseRequestOptions(r *http.Request) (*requestOptions, error) {
	query := r.URL.Query()

	limit := 0
	limitS := query.Get("limit")
	if limitS != "" {
		var err error
		limit, err = strconv.Atoi(limitS)
		if err != nil {
			return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err, util.WithAPIErrorMsg("cannot parse limit"), serrors.InvalidLimit())
		}
	}
	if limit < 0 {
		return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("limit must be greater or equal than 0"), serrors.InvalidLimit())
	}

	sortDirection := types.SortDirection(query.Get("sortdirection"))
	if sortDirection != "" {
		switch sortDirection {
		case types.SortDirectionAsc:
		case types.SortDirectionDesc:
		default:
			return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("wrong sort direction %q", sortDirection), serrors.InvalidSortDirection())
		}
	}

	return &requestOptions{
		Limit:         limit,
		SortDirection: sortDirection,
	}, nil
}

func addHasMoreHeader(w http.ResponseWriter, hasMore bool) {
	w.Header().Add(agolaHasMoreHeader, strconv.FormatBool(hasMore))
}

type LogsHandler struct {
	log zerolog.Logger
	d   *db.DB
	ost objectstorage.ObjStorage
}

func NewLogsHandler(log zerolog.Logger, d *db.DB, ost objectstorage.ObjStorage) *LogsHandler {
	return &LogsHandler{
		log: log,
		d:   d,
		ost: ost,
	}
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

	q := r.URL.Query()

	runID := q.Get("runid")
	if runID == "" {
		return util.NewAPIError(util.ErrBadRequest)
	}
	taskID := q.Get("taskid")
	if taskID == "" {
		return util.NewAPIError(util.ErrBadRequest)
	}

	_, setup := q["setup"]
	stepStr := q.Get("step")
	if !setup && stepStr == "" {
		return util.NewAPIError(util.ErrBadRequest)
	}
	if setup && stepStr != "" {
		return util.NewAPIError(util.ErrBadRequest)
	}

	var step int
	if stepStr != "" {
		var err error
		step, err = strconv.Atoi(stepStr)
		if err != nil {
			return util.NewAPIErrorWrap(util.ErrBadRequest, err)
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
				return util.NewAPIErrorWrap(util.ErrNotExist, err, util.WithAPIErrorMsg("log doesn't exist"))
			default:
				return errors.WithStack(err)
			}
		}
	}

	return nil
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
		return true, util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("no such run with id: %s", runID), serrors.RunDoesNotExist())
	}

	task, ok := r.Tasks[taskID]
	if !ok {
		return true, util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("no such task with ID %s in run %s", taskID, runID), serrors.RunTaskDoesNotExist())
	}
	if len(task.Steps) <= step {
		return true, util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("no such step for task %s in run %s", taskID, runID), serrors.RunTaskStepDoesNotExist())
	}

	// if the log has been already fetched use it, otherwise fetch it from the executor
	if task.Steps[step].LogPhase == types.RunTaskFetchPhaseFinished {
		var logPath string
		if setup {
			logPath = store.OSTRunTaskSetupLogPath(task.ID)
		} else {
			logPath = store.OSTRunTaskStepLogPath(task.ID, step)
		}
		f, err := h.ost.ReadObject(ctx, logPath)
		if err != nil {
			if objectstorage.IsNotExist(err) {
				return true, util.NewAPIErrorWrap(util.ErrNotExist, err)
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
			return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("executor task for run task with id %q doesn't exist", task.ID))
		}

		executor, err = h.d.GetExecutorByExecutorID(tx, et.ExecutorID)
		if err != nil {
			return errors.WithStack(err)
		}
		if executor == nil {
			return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("executor with id %q doesn't exist", et.ExecutorID))
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
			return true, util.NewAPIErrorWrap(util.ErrNotExist, errors.New("no log on executor"))
		}
		return true, errors.Errorf("received http status: %d", req.StatusCode)
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
	ost objectstorage.ObjStorage
}

func NewLogsDeleteHandler(log zerolog.Logger, d *db.DB, ost objectstorage.ObjStorage) *LogsDeleteHandler {
	return &LogsDeleteHandler{
		log: log,
		d:   d,
		ost: ost,
	}
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

	q := r.URL.Query()

	runID := q.Get("runid")
	if runID == "" {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("runid is empty"))
	}
	taskID := q.Get("taskid")
	if taskID == "" {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("taskid is empty"))
	}

	_, setup := q["setup"]
	stepStr := q.Get("step")
	if !setup && stepStr == "" {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("setup is false and step is empty"))
	}
	if setup && stepStr != "" {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("setup is true and step is %s", stepStr))
	}

	var step int
	if stepStr != "" {
		var err error
		step, err = strconv.Atoi(stepStr)
		if err != nil {
			return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("step %s is not a valid number", stepStr))
		}
	}

	if err := h.deleteTaskLogs(ctx, runID, taskID, setup, step); err != nil {
		h.log.Err(err).Send()
		switch {
		case util.APIErrorIs(err, util.ErrNotExist):
			return util.NewAPIErrorWrap(util.ErrNotExist, err, util.WithAPIErrorMsg("log doesn't exist"))
		default:
			return errors.WithStack(err)
		}
	}

	return nil
}

func (h *LogsDeleteHandler) deleteTaskLogs(ctx context.Context, runID, taskID string, setup bool, step int) error {
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
		return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("no such run with id: %s", runID))
	}

	task, ok := r.Tasks[taskID]
	if !ok {
		return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("no such task with ID %s in run %s", taskID, runID))
	}
	if len(task.Steps) <= step {
		return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("no such step for task %s in run %s", taskID, runID))
	}

	if task.Steps[step].LogPhase == types.RunTaskFetchPhaseFinished {
		var logPath string
		if setup {
			logPath = store.OSTRunTaskSetupLogPath(task.ID)
		} else {
			logPath = store.OSTRunTaskStepLogPath(task.ID, step)
		}
		err := h.ost.DeleteObject(ctx, logPath)
		if err != nil {
			if objectstorage.IsNotExist(err) {
				return util.NewAPIErrorWrap(util.ErrNotExist, err)
			}
			return errors.WithStack(err)
		}
		return nil
	}
	return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("Log for task %s in run %s is not yet archived", taskID, runID))
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
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *ChangeGroupsUpdateTokensHandler) do(r *http.Request) (string, error) {
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
		return "", errors.WithStack(err)
	}

	cgts, err := types.MarshalChangeGroupsUpdateToken(cgt)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return cgts, nil
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
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *RunHandler) do(r *http.Request) (*rsapitypes.RunResponse, error) {
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
		return nil, errors.WithStack(err)
	}

	if run == nil {
		return nil, util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("run with id %q doesn't exist", runRef), serrors.RunDoesNotExist())
	}

	if rc == nil {
		return nil, util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("run config for run with id %q doesn't exist", runRef), serrors.RunDoesNotExist())
	}

	cgts, err := types.MarshalChangeGroupsUpdateToken(cgt)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := &rsapitypes.RunResponse{
		Run:                     run,
		RunConfig:               rc,
		ChangeGroupsUpdateToken: cgts,
	}

	return res, nil
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
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *RunByGroupHandler) do(r *http.Request) (*rsapitypes.RunResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)

	query := r.URL.Query()
	changeGroups := query["changegroup"]

	group, err := url.PathUnescape(vars["group"])
	if err != nil {
		return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("group is empty"), serrors.InvalidRunGroup())
	}

	runCounterStr := vars["runcounter"]

	var runCounter uint64
	if runCounterStr == "" {
		return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("runcounter is empty"), serrors.InvalidRunNumber())
	}
	if runCounterStr != "" {
		var err error
		runCounter, err = strconv.ParseUint(runCounterStr, 10, 64)
		if err != nil {
			return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err, util.WithAPIErrorMsg("cannot parse runcounter"), serrors.InvalidRunNumber())
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
		return nil, errors.WithStack(err)
	}
	if run == nil {
		return nil, util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("run for group %q with counter %d doesn't exist", group, runCounter), serrors.RunDoesNotExist())
	}

	if rc == nil {
		return nil, util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("run config for run with id %q doesn't exist", run.ID), serrors.RunDoesNotExist())
	}

	cgts, err := types.MarshalChangeGroupsUpdateToken(cgt)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := &rsapitypes.RunResponse{
		Run:                     run,
		RunConfig:               rc,
		ChangeGroupsUpdateToken: cgts,
	}

	return res, nil
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
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *RunsHandler) do(r *http.Request) (*rsapitypes.GetRunsResponse, error) {
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
			return nil, util.NewAPIError(util.ErrBadRequest)
		}
	}
	if limit < 0 {
		return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("limit must be greater or equal than 0"))
	}
	if limit > MaxRunsLimit {
		limit = MaxRunsLimit
	}
	sortDirection := types.SortDirectionDesc
	if _, ok := query["asc"]; ok {
		sortDirection = types.SortDirectionAsc
	}

	var startRunSequence uint64
	startRunSequenceStr := query.Get("start")
	if startRunSequenceStr != "" {
		var err error
		startRunSequence, err = strconv.ParseUint(startRunSequenceStr, 10, 64)
		if err != nil {
			return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err, util.WithAPIErrorMsg("cannot parse run sequence"), serrors.InvalidStartSequence())
		}
	}

	var runs []*types.Run
	var cgt *types.ChangeGroupsUpdateToken

	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		runs, err = h.d.GetRuns(tx, groups, lastRun, phaseFilter, resultFilter, startRunSequence, limit, sortDirection)
		if err != nil {
			return errors.WithStack(err)
		}

		cgt, err = h.ah.GetChangeGroupsUpdateTokens(tx, changeGroups)
		return errors.WithStack(err)
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	cgts, err := types.MarshalChangeGroupsUpdateToken(cgt)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := &rsapitypes.GetRunsResponse{
		Runs:                    runs,
		ChangeGroupsUpdateToken: cgts,
	}

	return res, nil
}

type GroupRunsHandler struct {
	log zerolog.Logger
	d   *db.DB
	ah  *action.ActionHandler
}

func NewGroupRunsHandler(log zerolog.Logger, d *db.DB, ah *action.ActionHandler) *GroupRunsHandler {
	return &GroupRunsHandler{
		log: log,
		d:   d,
		ah:  ah,
	}
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

func (h *GroupRunsHandler) do(w http.ResponseWriter, r *http.Request) (*rsapitypes.GetRunsResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	query := r.URL.Query()

	ropts, err := parseRequestOptions(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	phaseFilter := types.RunPhaseFromStringSlice(query["phase"])
	resultFilter := types.RunResultFromStringSlice(query["result"])

	changeGroups := query["changegroup"]

	group, err := url.PathUnescape(vars["group"])
	if err != nil {
		return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("group is empty"), serrors.InvalidRunGroup())
	}

	var startRunCounter uint64
	startRunCounterStr := query.Get("start")
	if startRunCounterStr != "" {
		var err error
		startRunCounter, err = strconv.ParseUint(startRunCounterStr, 10, 64)
		if err != nil {
			return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err, util.WithAPIErrorMsg("cannot parse runcounter"), serrors.InvalidRunNumber())
		}
	}

	ares, err := h.ah.GetGroupRuns(ctx, &action.GetGroupRunsRequest{Group: group, Limit: ropts.Limit, SortDirection: ropts.SortDirection, ChangeGroups: changeGroups, StartRunCounter: startRunCounter, PhaseFilter: phaseFilter, ResultFilter: resultFilter})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := &rsapitypes.GetRunsResponse{
		Runs:                    ares.Runs,
		ChangeGroupsUpdateToken: ares.ChangeGroupsUpdateToken,
	}

	addHasMoreHeader(w, ares.HasMore)

	return res, nil
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
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *RunCreateHandler) do(r *http.Request) (*rsapitypes.RunResponse, error) {
	ctx := r.Context()

	var req rsapitypes.RunCreateRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
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
		return nil, errors.WithStack(err)
	}

	res := &rsapitypes.RunResponse{
		Run:       rb.Run,
		RunConfig: rb.Rc,
	}

	return res, nil
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
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}
}

func (h *RunActionsHandler) do(r *http.Request) error {
	ctx := r.Context()
	vars := mux.Vars(r)
	runID := vars["runid"]

	var req rsapitypes.RunActionsRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	switch req.ActionType {
	case rsapitypes.RunActionTypeChangePhase:
		creq := &action.RunChangePhaseRequest{
			RunID:                   runID,
			Phase:                   req.Phase,
			ChangeGroupsUpdateToken: req.ChangeGroupsUpdateToken,
		}
		if err := h.ah.ChangeRunPhase(ctx, creq); err != nil {
			return errors.WithStack(err)
		}
	case rsapitypes.RunActionTypeStop:
		creq := &action.RunStopRequest{
			RunID:                   runID,
			ChangeGroupsUpdateToken: req.ChangeGroupsUpdateToken,
		}
		if err := h.ah.StopRun(ctx, creq); err != nil {
			return errors.WithStack(err)
		}
	default:
		return util.NewAPIError(util.ErrBadRequest)
	}

	return nil
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
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}
}

func (h *RunTaskActionsHandler) do(r *http.Request) error {
	ctx := r.Context()
	vars := mux.Vars(r)
	runID := vars["runid"]
	taskID := vars["taskid"]

	var req rsapitypes.RunTaskActionsRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return util.NewAPIErrorWrap(util.ErrBadRequest, err)
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
			return errors.WithStack(err)
		}

	case rsapitypes.RunTaskActionTypeApprove:
		creq := &action.RunTaskApproveRequest{
			RunID:                   runID,
			TaskID:                  taskID,
			ChangeGroupsUpdateToken: req.ChangeGroupsUpdateToken,
		}
		if err := h.ah.ApproveRunTask(ctx, creq); err != nil {
			return errors.WithStack(err)
		}

	default:
		return util.NewAPIError(util.ErrBadRequest)
	}

	return nil
}

type RunEventsHandler struct {
	log zerolog.Logger
	d   *db.DB
	ost objectstorage.ObjStorage
}

func NewRunEventsHandler(log zerolog.Logger, d *db.DB, ost objectstorage.ObjStorage) *RunEventsHandler {
	return &RunEventsHandler{
		log: log,
		d:   d,
		ost: ost,
	}
}

func (h *RunEventsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(w, r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}
}

func (h *RunEventsHandler) do(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	q := r.URL.Query()

	// TODO(sgotti) handle additional events filtering (by type, etc...)
	var afterRunEventSequence uint64
	afterRunEventSequenceStr := q.Get("afterSequence")
	if afterRunEventSequenceStr != "" {
		var err error
		afterRunEventSequence, err = strconv.ParseUint(afterRunEventSequenceStr, 10, 64)
		if err != nil {
			return util.NewAPIErrorWrap(util.ErrBadRequest, err, util.WithAPIErrorMsg("cannot parse afterSequence"), serrors.InvalidStartSequence())
		}
	}

	if err := h.sendRunEvents(ctx, afterRunEventSequence, w); err != nil {
		h.log.Err(err).Send()
		return nil
	}

	return nil
}

func (h *RunEventsHandler) sendRunEvents(ctx context.Context, afterRunEventSequence uint64, w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	var flusher http.Flusher
	if fl, ok := w.(http.Flusher); ok {
		flusher = fl
	}

	// TODO(sgotti) use a notify system instead of polling the database

	curEventSequence := afterRunEventSequence

	if afterRunEventSequence == 0 {
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
