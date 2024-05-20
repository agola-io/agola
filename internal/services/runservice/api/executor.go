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
	"io"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/objectstorage"
	"agola.io/agola/internal/services/runservice/action"
	"agola.io/agola/internal/services/runservice/common"
	"agola.io/agola/internal/services/runservice/db"
	"agola.io/agola/internal/services/runservice/store"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/internal/util"
	rsapitypes "agola.io/agola/services/runservice/api/types"
	"agola.io/agola/services/runservice/types"
)

func GenExecutorTaskResponse(et *types.ExecutorTask, etSpecData *types.ExecutorTaskSpecData) *rsapitypes.ExecutorTask {
	apiet := &rsapitypes.ExecutorTask{
		ID:         et.ID,
		ExecutorID: et.ExecutorID,

		Stop: et.Stop,

		Status: &rsapitypes.ExecutorTaskStatus{
			Phase:     et.Phase,
			Timedout:  et.Timedout,
			FailError: et.FailError,
			Steps:     make([]*rsapitypes.ExecutorTaskStepStatus, len(et.Steps)),
			StartTime: et.StartTime,
			EndTime:   et.EndTime,
		},

		Spec: (*rsapitypes.ExecutorTaskSpecData)(etSpecData),
	}

	apiet.Status.SetupStep = rsapitypes.ExecutorTaskStepStatus{
		Phase:      et.SetupStep.Phase,
		StartTime:  et.SetupStep.StartTime,
		EndTime:    et.SetupStep.EndTime,
		ExitStatus: et.SetupStep.ExitStatus,
	}

	for i, s := range et.Steps {
		apiet.Status.Steps[i] = &rsapitypes.ExecutorTaskStepStatus{
			Phase:      s.Phase,
			StartTime:  s.StartTime,
			EndTime:    s.EndTime,
			ExitStatus: s.ExitStatus,
		}
	}

	return apiet
}

type ExecutorStatusHandler struct {
	log zerolog.Logger
	d   *db.DB
	ah  *action.ActionHandler
}

func NewExecutorStatusHandler(log zerolog.Logger, d *db.DB, ah *action.ActionHandler) *ExecutorStatusHandler {
	return &ExecutorStatusHandler{log: log, d: d, ah: ah}
}

func (h *ExecutorStatusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}
}

func (h *ExecutorStatusHandler) do(r *http.Request) error {
	ctx := r.Context()
	vars := mux.Vars(r)
	executorID := vars["executorid"]

	// TODO(sgotti) Check authorized call from executors
	var executorStatus *rsapitypes.ExecutorStatus
	d := json.NewDecoder(r.Body)
	defer r.Body.Close()

	if err := d.Decode(&executorStatus); err != nil {
		return util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	var executor *types.Executor
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		// TODO(sgotti) validate executor sent data
		executor, err = h.d.GetExecutorByExecutorID(tx, executorID)
		if err != nil {
			return errors.WithStack(err)
		}

		if executor == nil {
			executor = types.NewExecutor(tx)
		}

		executor.ExecutorID = executorID
		executor.ListenURL = executorStatus.ListenURL
		executor.Archs = executorStatus.Archs
		executor.Labels = executorStatus.Labels
		executor.AllowPrivilegedContainers = executorStatus.AllowPrivilegedContainers
		executor.ActiveTasksLimit = executorStatus.ActiveTasksLimit
		executor.ActiveTasks = executorStatus.ActiveTasks
		executor.Dynamic = executorStatus.Dynamic
		executor.ExecutorGroup = executorStatus.ExecutorGroup
		executor.SiblingsExecutors = executorStatus.SiblingsExecutors

		if err := h.d.InsertOrUpdateExecutor(tx, executor); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	if err = h.deleteStaleExecutors(ctx, executor); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (h *ExecutorStatusHandler) deleteStaleExecutors(ctx context.Context, curExecutor *types.Executor) error {
	var executors []*types.Executor
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		executors, err = h.d.GetExecutors(tx)
		if err != nil {
			return errors.WithStack(err)
		}

		for _, executor := range executors {
			if executor.ExecutorID == curExecutor.ExecutorID {
				continue
			}
			if !executor.Dynamic {
				continue
			}
			if executor.ExecutorGroup != curExecutor.ExecutorGroup {
				continue
			}
			// executor is dynamic and in the same executor group
			active := false
			for _, seID := range curExecutor.SiblingsExecutors {
				if executor.ExecutorID == seID {
					active = true
					break
				}
			}
			if active {
				continue
			}

			if err := h.d.DeleteExecutor(tx, executor.ID); err != nil {
				return errors.WithStack(err)
			}
		}
		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

type ExecutorTaskStatusHandler struct {
	log zerolog.Logger
	d   *db.DB
	c   chan<- string
}

func NewExecutorTaskStatusHandler(log zerolog.Logger, d *db.DB, c chan<- string) *ExecutorTaskStatusHandler {
	return &ExecutorTaskStatusHandler{log: log, d: d, c: c}
}

func (h *ExecutorTaskStatusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}
}

func (h *ExecutorTaskStatusHandler) do(r *http.Request) error {
	ctx := r.Context()
	vars := mux.Vars(r)
	// executorID := vars["executorid"]
	etID := vars["taskid"]

	// TODO(sgotti) Check authorized call from executors
	var etStatus *rsapitypes.ExecutorTaskStatus
	d := json.NewDecoder(r.Body)
	defer r.Body.Close()

	if err := d.Decode(&etStatus); err != nil {
		return util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		curEt, err := h.d.GetExecutorTask(tx, etID)
		if err != nil {
			return errors.WithStack(err)
		}

		if curEt == nil {
			return nil
		}

		curEt.Phase = etStatus.Phase
		curEt.Timedout = etStatus.Timedout
		curEt.FailError = etStatus.FailError
		curEt.Steps = make([]*types.ExecutorTaskStepStatus, len(etStatus.Steps))
		curEt.StartTime = etStatus.StartTime
		curEt.EndTime = etStatus.EndTime

		curEt.SetupStep = types.ExecutorTaskStepStatus{
			Phase:      etStatus.SetupStep.Phase,
			StartTime:  etStatus.SetupStep.StartTime,
			EndTime:    etStatus.SetupStep.EndTime,
			ExitStatus: etStatus.SetupStep.ExitStatus,
		}
		for i, s := range etStatus.Steps {
			curEt.Steps[i] = &types.ExecutorTaskStepStatus{
				Phase:      s.Phase,
				StartTime:  s.StartTime,
				EndTime:    s.EndTime,
				ExitStatus: s.ExitStatus,
			}
		}

		if err := h.d.UpdateExecutorTask(tx, curEt); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	go func() { h.c <- etID }()

	return nil
}

type ExecutorTaskHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewExecutorTaskHandler(log zerolog.Logger, ah *action.ActionHandler) *ExecutorTaskHandler {
	return &ExecutorTaskHandler{log: log, ah: ah}
}

func (h *ExecutorTaskHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *ExecutorTaskHandler) do(r *http.Request) (*rsapitypes.ExecutorTask, error) {
	ctx := r.Context()
	vars := mux.Vars(r)

	// TODO(sgotti) Check authorized call from executors
	etID := vars["taskid"]
	if etID == "" {
		return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("taskid is empty"))
	}

	ares, err := h.ah.GetExecutorTask(ctx, etID)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := GenExecutorTaskResponse(ares.Et, ares.EtSpecData)

	return res, nil
}

type ExecutorTasksHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewExecutorTasksHandler(log zerolog.Logger, ah *action.ActionHandler) *ExecutorTasksHandler {
	return &ExecutorTasksHandler{log: log, ah: ah}
}

func (h *ExecutorTasksHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *ExecutorTasksHandler) do(r *http.Request) ([]*rsapitypes.ExecutorTask, error) {
	ctx := r.Context()
	vars := mux.Vars(r)

	// TODO(sgotti) Check authorized call from executors
	executorID := vars["executorid"]
	if executorID == "" {
		return nil, util.NewAPIError(util.ErrBadRequest)
	}

	ares, err := h.ah.GetExecutorTasks(ctx, executorID)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := []*rsapitypes.ExecutorTask{}

	for _, ar := range ares {
		res = append(res, GenExecutorTaskResponse(ar.Et, ar.EtSpecData))
	}

	return res, nil
}

type ArchivesHandler struct {
	log zerolog.Logger
	ost objectstorage.ObjStorage
}

func NewArchivesHandler(log zerolog.Logger, ost objectstorage.ObjStorage) *ArchivesHandler {
	return &ArchivesHandler{
		log: log,
		ost: ost,
	}
}

func (h *ArchivesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(w, r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}
}

func (h *ArchivesHandler) do(w http.ResponseWriter, r *http.Request) error {
	// TODO(sgotti) Check authorized call from executors
	ctx := r.Context()

	taskID := r.URL.Query().Get("taskid")
	if taskID == "" {
		return util.NewAPIError(util.ErrBadRequest)
	}
	s := r.URL.Query().Get("step")
	if s == "" {
		return util.NewAPIError(util.ErrBadRequest)
	}
	step, err := strconv.Atoi(s)
	if err != nil {
		return util.NewAPIError(util.ErrBadRequest)
	}

	w.Header().Set("Cache-Control", "no-cache")

	if err := h.readArchive(ctx, taskID, step, w); err != nil {
		switch {
		case util.APIErrorIs(err, util.ErrNotExist):
			return util.NewAPIErrorWrap(util.ErrNotExist, err)
		default:
			return errors.WithStack(err)
		}
	}

	return nil
}

func (h *ArchivesHandler) readArchive(ctx context.Context, rtID string, step int, w io.Writer) error {
	archivePath := store.OSTRunTaskArchivePath(rtID, step)
	f, err := h.ost.ReadObject(ctx, archivePath)
	if err != nil {
		if objectstorage.IsNotExist(err) {
			return util.NewAPIErrorWrap(util.ErrNotExist, err)
		}
		return errors.WithStack(err)
	}
	defer f.Close()

	br := bufio.NewReader(f)

	_, err = io.Copy(w, br)
	return errors.WithStack(err)
}

type CacheHandler struct {
	log zerolog.Logger
	ost objectstorage.ObjStorage
}

func NewCacheHandler(log zerolog.Logger, ost objectstorage.ObjStorage) *CacheHandler {
	return &CacheHandler{
		log: log,
		ost: ost,
	}
}

func (h *CacheHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(w, r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}
}

func (h *CacheHandler) do(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	vars := mux.Vars(r)
	// TODO(sgotti) Check authorized call from executors

	// keep and use the escaped path
	key := vars["key"]
	if key == "" {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("empty cache key"))
	}
	if len(key) > common.MaxCacheKeyLength {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("cache key too long"))
	}
	query := r.URL.Query()
	_, prefix := query["prefix"]

	matchedKey, err := matchCache(ctx, h.ost, key, prefix)
	if err != nil {
		return errors.WithStack(err)
	}
	if matchedKey == "" {
		return util.NewAPIError(util.ErrNotExist)
	}

	if r.Method == "HEAD" {
		return nil
	}

	w.Header().Set("Cache-Control", "no-cache")

	if err := h.readCache(ctx, matchedKey, w); err != nil {
		switch {
		case util.APIErrorIs(err, util.ErrNotExist):
			return util.NewAPIErrorWrap(util.ErrNotExist, err)
		default:
			return errors.WithStack(err)
		}
	}

	return nil
}

func matchCache(ctx context.Context, ost objectstorage.ObjStorage, key string, prefix bool) (string, error) {
	cachePath := store.OSTCachePath(key)

	if prefix {
		// get the latest modified object
		var lastObject *objectstorage.ObjectInfo
		for object := range ost.List(ctx, store.OSTCacheDir()+"/"+key, "", false) {
			if object.Err != nil {
				return "", errors.WithStack(object.Err)
			}

			if (lastObject == nil) || (lastObject.LastModified.Before(object.LastModified)) {
				lastObject = &object
			}

		}
		if lastObject == nil {
			return "", nil

		}
		return store.OSTCacheKey(lastObject.Path), nil
	}

	_, err := ost.Stat(ctx, cachePath)
	if objectstorage.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", errors.WithStack(err)
	}
	return key, nil
}

func (h *CacheHandler) readCache(ctx context.Context, key string, w io.Writer) error {
	cachePath := store.OSTCachePath(key)
	f, err := h.ost.ReadObject(ctx, cachePath)
	if err != nil {
		if objectstorage.IsNotExist(err) {
			return util.NewAPIErrorWrap(util.ErrNotExist, err)
		}
		return errors.WithStack(err)
	}
	defer f.Close()

	br := bufio.NewReader(f)

	_, err = io.Copy(w, br)
	return errors.WithStack(err)
}

type CacheCreateHandler struct {
	log zerolog.Logger
	ost objectstorage.ObjStorage
}

func NewCacheCreateHandler(log zerolog.Logger, ost objectstorage.ObjStorage) *CacheCreateHandler {
	return &CacheCreateHandler{
		log: log,
		ost: ost,
	}
}

func (h *CacheCreateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(w, r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}
}

func (h *CacheCreateHandler) do(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	vars := mux.Vars(r)
	// TODO(sgotti) Check authorized call from executors

	// keep and use the escaped path
	key := vars["key"]
	if key == "" {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("empty cache key"))
	}
	if len(key) > common.MaxCacheKeyLength {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("cache key too long"))
	}

	w.Header().Set("Cache-Control", "no-cache")

	matchedKey, err := matchCache(ctx, h.ost, key, false)
	if err != nil {
		return errors.WithStack(err)
	}
	if matchedKey != "" {
		http.Error(w, "", http.StatusNotModified)
		return nil
	}

	size := int64(-1)
	sizeStr := r.Header.Get("Content-Length")
	if sizeStr != "" {
		size, err = strconv.ParseInt(sizeStr, 10, 64)
		if err != nil {
			return util.NewAPIError(util.ErrBadRequest)
		}
	}

	cachePath := store.OSTCachePath(key)
	if err := h.ost.WriteObject(ctx, cachePath, r.Body, size, false); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

type ExecutorDeleteHandler struct {
	log zerolog.Logger
	d   *db.DB
}

func NewExecutorDeleteHandler(log zerolog.Logger, d *db.DB) *ExecutorDeleteHandler {
	return &ExecutorDeleteHandler{
		log: log,
		d:   d,
	}
}

func (h *ExecutorDeleteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *ExecutorDeleteHandler) do(r *http.Request) error {
	ctx := r.Context()
	vars := mux.Vars(r)

	// TODO(sgotti) Check authorized call from executors
	executorID := vars["executorid"]
	if executorID == "" {
		return util.NewAPIError(util.ErrBadRequest)
	}

	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		executor, err := h.d.GetExecutorByExecutorID(tx, executorID)
		if err != nil {
			return errors.WithStack(err)
		}
		if executor == nil {
			return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("executor with executor id %s doesn't exist", executorID))
		}

		if err := h.d.DeleteExecutor(tx, executor.ID); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
