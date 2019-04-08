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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/etcd"
	"github.com/sorintlab/agola/internal/objectstorage"
	"github.com/sorintlab/agola/internal/services/runservice/scheduler/command"
	"github.com/sorintlab/agola/internal/services/runservice/scheduler/common"
	"github.com/sorintlab/agola/internal/services/runservice/scheduler/readdb"
	"github.com/sorintlab/agola/internal/services/runservice/scheduler/store"
	"github.com/sorintlab/agola/internal/services/runservice/types"
	"github.com/sorintlab/agola/internal/wal"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type LogsHandler struct {
	log *zap.SugaredLogger
	e   *etcd.Store
	lts *objectstorage.ObjStorage
	wal *wal.WalManager
}

func NewLogsHandler(logger *zap.Logger, e *etcd.Store, lts *objectstorage.ObjStorage, wal *wal.WalManager) *LogsHandler {
	return &LogsHandler{
		log: logger.Sugar(),
		e:   e,
		lts: lts,
		wal: wal,
	}
}

func (h *LogsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// TODO(sgotti) Check authorized call from client
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
	stream := false
	if _, ok := q["stream"]; ok {
		stream = true
	}
	if follow {
		stream = true
	}

	if err, sendError := h.readTaskLogs(ctx, runID, taskID, setup, step, w, follow, stream); err != nil {
		h.log.Errorf("err: %+v", err)
		if sendError {
			switch err.(type) {
			case common.ErrNotExist:
				http.Error(w, err.Error(), http.StatusNotFound)
			default:
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	}
}

func (h *LogsHandler) readTaskLogs(ctx context.Context, runID, taskID string, setup bool, step int, w http.ResponseWriter, follow, stream bool) (error, bool) {
	r, err := store.GetRunEtcdOrLTS(ctx, h.e, h.wal, runID)
	if err != nil {
		return err, true
	}
	if r == nil {
		return errors.Errorf("no such run with id: %s", runID), true
	}

	task, ok := r.RunTasks[taskID]
	if !ok {
		return errors.Errorf("no such task with ID %s in run %s", taskID, runID), true
	}
	if len(task.Steps) <= step {
		return errors.Errorf("no such step for task %s in run %s", taskID, runID), true
	}

	// if the log has been already fetched use it, otherwise fetch it from the executor
	if task.Steps[step].LogPhase == types.RunTaskFetchPhaseFinished {
		var logPath string
		if setup {
			logPath = store.LTSRunTaskSetupLogPath(task.ID)
		} else {
			logPath = store.LTSRunTaskStepLogPath(task.ID, step)
		}
		f, err := h.lts.ReadObject(logPath)
		if err != nil {
			if err == objectstorage.ErrNotExist {
				return common.NewErrNotExist(err), true
			}
			return err, true
		}
		defer f.Close()
		return sendLogs(w, f, stream), false
	}

	et, err := store.GetExecutorTask(ctx, h.e, task.ID)
	if err != nil {
		return err, true
	}
	executor, err := store.GetExecutor(ctx, h.e, et.Status.ExecutorID)
	if err != nil && err != etcd.ErrKeyNotFound {
		return err, true
	}
	if executor == nil {
		return common.NewErrNotExist(errors.Errorf("executor with id %q doesn't exist", et.Status.ExecutorID)), true
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
			return common.NewErrNotExist(errors.New("no log on executor")), true
		}
		return errors.Errorf("received http status: %d", req.StatusCode), true
	}

	return sendLogs(w, req.Body, stream), false
}

func sendLogs(w http.ResponseWriter, r io.Reader, stream bool) error {
	if stream {
		w.Header().Set("Content-Type", "text/event-stream")
	}

	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

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
		if stream {
			if _, err := w.Write([]byte(fmt.Sprintf("data: %s\n", data))); err != nil {
				return err
			}
		} else {
			if _, err := w.Write(data); err != nil {
				return err
			}
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
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
	query := r.URL.Query()
	groups := query["changegroup"]

	var cgt *types.ChangeGroupsUpdateToken

	err := h.readDB.Do(func(tx *db.Tx) error {
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

	if err := json.NewEncoder(w).Encode(cgts); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type RunResponse struct {
	Run       *types.Run       `json:"run"`
	RunConfig *types.RunConfig `json:"run_config"`
}

type RunHandler struct {
	log    *zap.SugaredLogger
	e      *etcd.Store
	wal    *wal.WalManager
	readDB *readdb.ReadDB
}

func NewRunHandler(logger *zap.Logger, e *etcd.Store, wal *wal.WalManager, readDB *readdb.ReadDB) *RunHandler {
	return &RunHandler{
		log:    logger.Sugar(),
		e:      e,
		wal:    wal,
		readDB: readDB,
	}
}

func (h *RunHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	runID := vars["runid"]

	run, _, err := store.GetRun(ctx, h.e, runID)
	if err != nil && err != etcd.ErrKeyNotFound {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if run == nil {
		run, err = store.LTSGetRun(h.wal, runID)
		if err != nil && err != objectstorage.ErrNotExist {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if run == nil {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	rc, err := store.LTSGetRunConfig(h.wal, run.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	res := &RunResponse{
		Run:       run,
		RunConfig: rc,
	}

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
	Runs                    []*types.Run `json:"runs"`
	ChangeGroupsUpdateToken string       `json:"change_groups_update_tokens"`
}

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
	query := r.URL.Query()
	phaseFilter := types.RunPhaseFromStringSlice(query["phase"])

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

	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		runs, err = h.readDB.GetRuns(tx, groups, lastRun, phaseFilter, start, limit, sortOrder)
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

	resp := &GetRunsResponse{
		Runs:                    runs,
		ChangeGroupsUpdateToken: cgts,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type RunCreateRequest struct {
	// new run
	RunConfig *types.RunConfig `json:"run_config"`

	// existing run
	RunID       string   `json:"run_id"`
	RunConfigID string   `json:"run_config_id"`
	FromStart   bool     `json:"from_start"`
	ResetTasks  []string `json:"reset_tasks"`

	Group                   string            `json:"group"`
	Environment             map[string]string `json:"environment"`
	Annotations             map[string]string `json:"annotations"`
	ChangeGroupsUpdateToken string            `json:"changeup_update_tokens"`
}

type RunCreateHandler struct {
	log *zap.SugaredLogger
	ch  *command.CommandHandler
}

func NewRunCreateHandler(logger *zap.Logger, ch *command.CommandHandler) *RunCreateHandler {
	return &RunCreateHandler{
		log: logger.Sugar(),
		ch:  ch,
	}
}

func (h *RunCreateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req RunCreateRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	creq := &command.RunCreateRequest{
		RunConfig:               req.RunConfig,
		RunID:                   req.RunID,
		RunConfigID:             req.RunConfigID,
		FromStart:               req.FromStart,
		ResetTasks:              req.ResetTasks,
		Group:                   req.Group,
		Environment:             req.Environment,
		Annotations:             req.Annotations,
		ChangeGroupsUpdateToken: req.ChangeGroupsUpdateToken,
	}
	rb, err := h.ch.CreateRun(ctx, creq)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	res := &RunResponse{
		Run:       rb.Run,
		RunConfig: rb.Rc,
	}

	if err := json.NewEncoder(w).Encode(res); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type RunActionType string

const (
	RunActionTypeChangePhase RunActionType = "changephase"
	RunActionTypeStop        RunActionType = "stop"
)

type RunActionsRequest struct {
	ActionType RunActionType `json:"action_type"`

	Phase                   types.RunPhase `json:"phase"`
	ChangeGroupsUpdateToken string         `json:"change_groups_update_tokens"`
}

type RunActionsHandler struct {
	log    *zap.SugaredLogger
	ch     *command.CommandHandler
	readDB *readdb.ReadDB
}

func NewRunActionsHandler(logger *zap.Logger, ch *command.CommandHandler) *RunActionsHandler {
	return &RunActionsHandler{
		log: logger.Sugar(),
		ch:  ch,
	}
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
	case RunActionTypeChangePhase:
		creq := &command.RunChangePhaseRequest{
			RunID:                   runID,
			Phase:                   req.Phase,
			ChangeGroupsUpdateToken: req.ChangeGroupsUpdateToken,
		}
		if err := h.ch.ChangeRunPhase(ctx, creq); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	case RunActionTypeStop:
		creq := &command.RunStopRequest{
			RunID:                   runID,
			ChangeGroupsUpdateToken: req.ChangeGroupsUpdateToken,
		}
		if err := h.ch.StopRun(ctx, creq); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "", http.StatusBadRequest)
		return
	}
}

type RunTaskActionType string

const (
	RunTaskActionTypeApprove RunTaskActionType = "approve"
)

type RunTaskActionsRequest struct {
	ActionType              RunTaskActionType `json:"action_type"`
	ApprovalAnnotations     map[string]string `json:"approval_annotations,omitempty"`
	ChangeGroupsUpdateToken string            `json:"change_groups_update_tokens"`
}

type RunTaskActionsHandler struct {
	log    *zap.SugaredLogger
	ch     *command.CommandHandler
	readDB *readdb.ReadDB
}

func NewRunTaskActionsHandler(logger *zap.Logger, ch *command.CommandHandler) *RunTaskActionsHandler {
	return &RunTaskActionsHandler{
		log: logger.Sugar(),
		ch:  ch,
	}
}

func (h *RunTaskActionsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	runID := vars["runid"]
	taskID := vars["taskid"]

	var req RunTaskActionsRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch req.ActionType {
	case RunTaskActionTypeApprove:
		creq := &command.RunTaskApproveRequest{
			RunID:                   runID,
			TaskID:                  taskID,
			ChangeGroupsUpdateToken: req.ChangeGroupsUpdateToken,
		}
		if err := h.ch.ApproveRunTask(ctx, creq); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "", http.StatusBadRequest)
		return
	}
}
