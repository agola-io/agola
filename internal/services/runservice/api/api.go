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
	"strconv"

	"agola.io/agola/internal/datamanager"
	"agola.io/agola/internal/db"
	"agola.io/agola/internal/etcd"
	"agola.io/agola/internal/objectstorage"
	"agola.io/agola/internal/services/runservice/action"
	"agola.io/agola/internal/services/runservice/common"
	"agola.io/agola/internal/services/runservice/readdb"
	"agola.io/agola/internal/services/runservice/store"
	"agola.io/agola/internal/util"
	rsapitypes "agola.io/agola/services/runservice/api/types"
	"agola.io/agola/services/runservice/types"

	"github.com/gorilla/mux"
	etcdclientv3 "go.etcd.io/etcd/clientv3"
	etcdclientv3rpc "go.etcd.io/etcd/etcdserver/api/v3rpc/rpctypes"
	"go.etcd.io/etcd/mvcc/mvccpb"
	"go.uber.org/zap"
	errors "golang.org/x/xerrors"
)

type ErrorResponse struct {
	Message string `json:"message"`
}

func ErrorResponseFromError(err error) *ErrorResponse {
	var aerr error
	// use inner errors if of these types
	switch {
	case util.IsBadRequest(err):
		var cerr *util.ErrBadRequest
		errors.As(err, &cerr)
		aerr = cerr
	case util.IsNotExist(err):
		var cerr *util.ErrNotExist
		errors.As(err, &cerr)
		aerr = cerr
	case util.IsForbidden(err):
		var cerr *util.ErrForbidden
		errors.As(err, &cerr)
		aerr = cerr
	case util.IsUnauthorized(err):
		var cerr *util.ErrUnauthorized
		errors.As(err, &cerr)
		aerr = cerr
	case util.IsInternal(err):
		var cerr *util.ErrInternal
		errors.As(err, &cerr)
		aerr = cerr
	}

	if aerr != nil {
		return &ErrorResponse{Message: aerr.Error()}
	}

	// on generic error return an generic message to not leak the real error
	return &ErrorResponse{Message: "internal server error"}
}

func httpError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}

	response := ErrorResponseFromError(err)
	resj, merr := json.Marshal(response)
	if merr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return true
	}
	switch {
	case util.IsBadRequest(err):
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(resj)
	case util.IsNotExist(err):
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write(resj)
	case util.IsForbidden(err):
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write(resj)
	case util.IsUnauthorized(err):
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write(resj)
	case util.IsInternal(err):
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(resj)
	default:
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(resj)
	}
	return true
}

func httpResponse(w http.ResponseWriter, code int, res interface{}) error {
	w.Header().Set("Content-Type", "application/json")

	if res != nil {
		resj, err := json.Marshal(res)
		if err != nil {
			httpError(w, err)
			return err
		}
		w.WriteHeader(code)
		_, err = w.Write(resj)
		return err
	}

	w.WriteHeader(code)
	return nil
}

type LogsHandler struct {
	log *zap.SugaredLogger
	e   *etcd.Store
	ost *objectstorage.ObjStorage
	dm  *datamanager.DataManager
}

func NewLogsHandler(logger *zap.Logger, e *etcd.Store, ost *objectstorage.ObjStorage, dm *datamanager.DataManager) *LogsHandler {
	return &LogsHandler{
		log: logger.Sugar(),
		e:   e,
		ost: ost,
		dm:  dm,
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

	if err, sendError := h.readTaskLogs(ctx, runID, taskID, setup, step, w, follow); err != nil {
		h.log.Errorf("err: %+v", err)
		if sendError {
			switch {
			case util.IsNotExist(err):
				httpError(w, util.NewErrNotExist(errors.Errorf("log doesn't exist: %w", err)))
			default:
				httpError(w, err)
			}
		}
	}
}

func (h *LogsHandler) readTaskLogs(ctx context.Context, runID, taskID string, setup bool, step int, w http.ResponseWriter, follow bool) (error, bool) {
	r, err := store.GetRunEtcdOrOST(ctx, h.e, h.dm, runID)
	if err != nil {
		return err, true
	}
	if r == nil {
		return util.NewErrNotExist(errors.Errorf("no such run with id: %s", runID)), true
	}

	task, ok := r.Tasks[taskID]
	if !ok {
		return util.NewErrNotExist(errors.Errorf("no such task with ID %s in run %s", taskID, runID)), true
	}
	if len(task.Steps) <= step {
		return util.NewErrNotExist(errors.Errorf("no such step for task %s in run %s", taskID, runID)), true
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
				return util.NewErrNotExist(err), true
			}
			return err, true
		}
		defer f.Close()
		return sendLogs(w, f), false
	}

	et, err := store.GetExecutorTask(ctx, h.e, task.ID)
	if err != nil {
		if err == etcd.ErrKeyNotFound {
			return util.NewErrNotExist(errors.Errorf("executor task with id %q doesn't exist", task.ID)), true
		}
		return err, true
	}
	executor, err := store.GetExecutor(ctx, h.e, et.Spec.ExecutorID)
	if err != nil {
		if err == etcd.ErrKeyNotFound {
			return util.NewErrNotExist(errors.Errorf("executor with id %q doesn't exist", et.Spec.ExecutorID)), true
		}
		return err, true
	}

	var url string
	if setup {
		url = fmt.Sprintf("%s/api/v1alpha/executor/logs?taskid=%s&setup", executor.ListenURL, taskID)
	} else {
		url = fmt.Sprintf("%s/api/v1alpha/executor/logs?taskid=%s&step=%d", executor.ListenURL, taskID, step)
	}
	if follow {
		url += "&follow"
	}
	req, err := http.Get(url)
	if err != nil {
		return err, true
	}
	defer req.Body.Close()
	if req.StatusCode != http.StatusOK {
		if req.StatusCode == http.StatusNotFound {
			return util.NewErrNotExist(errors.New("no log on executor")), true
		}
		return errors.Errorf("received http status: %d", req.StatusCode), true
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

	return sendLogs(w, req.Body), false
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
				return err
			}
			if n == 0 {
				return nil
			}
			stop = true
		}
		if _, err := w.Write(buf[:n]); err != nil {
			return err
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

type LogsDeleteHandler struct {
	log *zap.SugaredLogger
	e   *etcd.Store
	ost *objectstorage.ObjStorage
	dm  *datamanager.DataManager
}

func NewLogsDeleteHandler(logger *zap.Logger, e *etcd.Store, ost *objectstorage.ObjStorage, dm *datamanager.DataManager) *LogsDeleteHandler {
	return &LogsDeleteHandler{
		log: logger.Sugar(),
		e:   e,
		ost: ost,
		dm:  dm,
	}
}

func (h *LogsDeleteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	q := r.URL.Query()

	runID := q.Get("runid")
	if runID == "" {
		httpError(w, util.NewErrBadRequest(errors.Errorf("runid is empty")))
		return
	}
	taskID := q.Get("taskid")
	if taskID == "" {
		httpError(w, util.NewErrBadRequest(errors.Errorf("taskid is empty")))
		return
	}

	_, setup := q["setup"]
	stepStr := q.Get("step")
	if !setup && stepStr == "" {
		httpError(w, util.NewErrBadRequest(errors.Errorf("setup is false and step is empty")))
		return
	}
	if setup && stepStr != "" {
		httpError(w, util.NewErrBadRequest(errors.Errorf("setup is true and step is %s", stepStr)))
		return
	}

	var step int
	if stepStr != "" {
		var err error
		step, err = strconv.Atoi(stepStr)
		if err != nil {
			httpError(w, util.NewErrBadRequest(errors.Errorf("step %s is not a valid number", stepStr)))
			return
		}
	}

	if err := h.deleteTaskLogs(ctx, runID, taskID, setup, step, w); err != nil {
		h.log.Errorf("err: %+v", err)
		switch {
		case util.IsNotExist(err):
			httpError(w, util.NewErrNotExist(errors.Errorf("log doesn't exist: %w", err)))
		default:
			httpError(w, err)
		}
	}
}

func (h *LogsDeleteHandler) deleteTaskLogs(ctx context.Context, runID, taskID string, setup bool, step int, w http.ResponseWriter) error {
	r, err := store.GetRunEtcdOrOST(ctx, h.e, h.dm, runID)
	if err != nil {
		return err
	}
	if r == nil {
		return util.NewErrNotExist(errors.Errorf("no such run with id: %s", runID))
	}

	task, ok := r.Tasks[taskID]
	if !ok {
		return util.NewErrNotExist(errors.Errorf("no such task with ID %s in run %s", taskID, runID))
	}
	if len(task.Steps) <= step {
		return util.NewErrNotExist(errors.Errorf("no such step for task %s in run %s", taskID, runID))
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
				return util.NewErrNotExist(err)
			}
			return err
		}
		return nil
	}
	return util.NewErrBadRequest(errors.Errorf("Log for task %s in run %s is not yet archived", taskID, runID))
}

type ChangeGroupsUpdateTokensHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewChangeGroupsUpdateTokensHandler(logger *zap.Logger, readDB *readdb.ReadDB) *ChangeGroupsUpdateTokensHandler {
	return &ChangeGroupsUpdateTokensHandler{
		log:    logger.Sugar(),
		readDB: readDB,
	}
}

func (h *ChangeGroupsUpdateTokensHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	groups := query["changegroup"]

	var cgt *types.ChangeGroupsUpdateToken

	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, groups)
		return err
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

	if err := httpResponse(w, http.StatusOK, cgts); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type RunHandler struct {
	log    *zap.SugaredLogger
	e      *etcd.Store
	dm     *datamanager.DataManager
	readDB *readdb.ReadDB
}

func NewRunHandler(logger *zap.Logger, e *etcd.Store, dm *datamanager.DataManager, readDB *readdb.ReadDB) *RunHandler {
	return &RunHandler{
		log:    logger.Sugar(),
		e:      e,
		dm:     dm,
		readDB: readDB,
	}
}

func (h *RunHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	runID := vars["runid"]

	query := r.URL.Query()
	changeGroups := query["changegroup"]

	var run *types.Run
	var cgt *types.ChangeGroupsUpdateToken

	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		run, err = h.readDB.GetRun(tx, runID)
		if err != nil {
			h.log.Errorf("err: %+v", err)
			return err
		}

		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, changeGroups)
		return err
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if run == nil {
		httpError(w, util.NewErrNotExist(errors.Errorf("run %q doesn't exist", runID)))
		return
	}

	cgts, err := types.MarshalChangeGroupsUpdateToken(cgt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rc, err := store.OSTGetRunConfig(h.dm, run.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	res := &rsapitypes.RunResponse{
		Run:                     run,
		RunConfig:               rc,
		ChangeGroupsUpdateToken: cgts,
	}

	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

const (
	DefaultRunsLimit = 25
	MaxRunsLimit     = 40
)

type RunsHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewRunsHandler(logger *zap.Logger, readDB *readdb.ReadDB) *RunsHandler {
	return &RunsHandler{
		log:    logger.Sugar(),
		readDB: readDB,
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

	start := query.Get("start")

	var runs []*types.Run
	var cgt *types.ChangeGroupsUpdateToken

	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		runs, err = h.readDB.GetRuns(tx, groups, lastRun, phaseFilter, resultFilter, start, limit, sortOrder)
		if err != nil {
			h.log.Errorf("err: %+v", err)
			return err
		}

		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, changeGroups)
		return err
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
	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type RunCreateHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewRunCreateHandler(logger *zap.Logger, ah *action.ActionHandler) *RunCreateHandler {
	return &RunCreateHandler{
		log: logger.Sugar(),
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
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	res := &rsapitypes.RunResponse{
		Run:       rb.Run,
		RunConfig: rb.Rc,
	}

	if err := httpResponse(w, http.StatusCreated, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type RunActionsHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewRunActionsHandler(logger *zap.Logger, ah *action.ActionHandler) *RunActionsHandler {
	return &RunActionsHandler{
		log: logger.Sugar(),
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
			h.log.Errorf("err: %+v", err)
			httpError(w, err)
			return
		}
	case rsapitypes.RunActionTypeStop:
		creq := &action.RunStopRequest{
			RunID:                   runID,
			ChangeGroupsUpdateToken: req.ChangeGroupsUpdateToken,
		}
		if err := h.ah.StopRun(ctx, creq); err != nil {
			h.log.Errorf("err: %+v", err)
			httpError(w, err)
			return
		}
	default:
		http.Error(w, "", http.StatusBadRequest)
		return
	}
}

type RunTaskActionsHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewRunTaskActionsHandler(logger *zap.Logger, ah *action.ActionHandler) *RunTaskActionsHandler {
	return &RunTaskActionsHandler{
		log: logger.Sugar(),
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
			h.log.Errorf("err: %+v", err)
			httpError(w, err)
			return
		}

	case rsapitypes.RunTaskActionTypeApprove:
		creq := &action.RunTaskApproveRequest{
			RunID:                   runID,
			TaskID:                  taskID,
			ChangeGroupsUpdateToken: req.ChangeGroupsUpdateToken,
		}
		if err := h.ah.ApproveRunTask(ctx, creq); err != nil {
			h.log.Errorf("err: %+v", err)
			httpError(w, err)
			return
		}

	default:
		http.Error(w, "", http.StatusBadRequest)
		return
	}
}

type RunEventsHandler struct {
	log *zap.SugaredLogger
	e   *etcd.Store
	ost *objectstorage.ObjStorage
	dm  *datamanager.DataManager
}

func NewRunEventsHandler(logger *zap.Logger, e *etcd.Store, ost *objectstorage.ObjStorage, dm *datamanager.DataManager) *RunEventsHandler {
	return &RunEventsHandler{
		log: logger.Sugar(),
		e:   e,
		ost: ost,
		dm:  dm,
	}
}

//
func (h *RunEventsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	q := r.URL.Query()

	// TODO(sgotti) handle additional events filtering (by type, etc...)
	startRunEventID := q.Get("startruneventid")

	if err := h.sendRunEvents(ctx, startRunEventID, w); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

func (h *RunEventsHandler) sendRunEvents(ctx context.Context, startRunEventID string, w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	var flusher http.Flusher
	if fl, ok := w.(http.Flusher); ok {
		flusher = fl
	}

	// TODO(sgotti) fetch from previous events (handle startRunEventID).
	// Use the readdb instead of etcd

	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	wctx = etcdclientv3.WithRequireLeader(wctx)
	wch := h.e.WatchKey(wctx, common.EtcdRunEventKey, 0)
	for wresp := range wch {
		if wresp.Canceled {
			err := wresp.Err()
			if err == etcdclientv3rpc.ErrCompacted {
				h.log.Errorf("required events already compacted")
			}
			return errors.Errorf("watch error: %w", err)
		}

		for _, ev := range wresp.Events {
			switch ev.Type {
			case mvccpb.PUT:
				var runEvent *types.RunEvent
				if err := json.Unmarshal(ev.Kv.Value, &runEvent); err != nil {
					return errors.Errorf("failed to unmarshal run: %w", err)
				}
				if _, err := w.Write([]byte(fmt.Sprintf("data: %s\n\n", ev.Kv.Value))); err != nil {
					return err
				}
			}
		}
		if flusher != nil {
			flusher.Flush()
		}
	}

	return nil
}
