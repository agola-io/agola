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

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/objectstorage"
	"agola.io/agola/internal/services/runservice/action"
	"agola.io/agola/internal/services/runservice/common"
	"agola.io/agola/internal/services/runservice/db"
	"agola.io/agola/internal/services/runservice/store"
	"agola.io/agola/internal/sql"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/runservice/types"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

type ExecutorStatusHandler struct {
	log zerolog.Logger
	d   *db.DB
	ah  *action.ActionHandler
}

func NewExecutorStatusHandler(log zerolog.Logger, d *db.DB, ah *action.ActionHandler) *ExecutorStatusHandler {
	return &ExecutorStatusHandler{log: log, d: d, ah: ah}
}

func (h *ExecutorStatusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// TODO(sgotti) Check authorized call from executors
	var recExecutor *types.Executor
	d := json.NewDecoder(r.Body)
	defer r.Body.Close()

	if err := d.Decode(&recExecutor); err != nil {
		h.log.Err(err).Send()
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	var executor *types.Executor
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		// TODO(sgotti) validate executor sent data
		executor, err = h.d.GetExecutorByExecutorID(tx, recExecutor.ExecutorID)
		if err != nil {
			return errors.WithStack(err)
		}

		if executor == nil {
			executor = types.NewExecutor()
		}

		executor.ExecutorID = recExecutor.ExecutorID
		executor.ListenURL = recExecutor.ListenURL
		executor.Archs = recExecutor.Archs
		executor.Labels = recExecutor.Labels
		executor.AllowPrivilegedContainers = recExecutor.AllowPrivilegedContainers
		executor.ActiveTasksLimit = recExecutor.ActiveTasksLimit
		executor.ActiveTasks = recExecutor.ActiveTasks
		executor.Dynamic = recExecutor.Dynamic
		executor.ExecutorGroup = recExecutor.ExecutorGroup
		executor.SiblingsExecutors = recExecutor.SiblingsExecutors

		if err := h.d.InsertOrUpdateExecutor(tx, executor); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	err = h.deleteStaleExecutors(ctx, executor)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}
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
	ctx := r.Context()

	// TODO(sgotti) Check authorized call from executors
	var et *types.ExecutorTask
	d := json.NewDecoder(r.Body)
	defer r.Body.Close()

	if err := d.Decode(&et); err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		curEt, err := h.d.GetExecutorTask(tx, et.ID)
		if err != nil {
			return errors.WithStack(err)
		}

		//if curET.Revision >= et.Revision {
		//	return nil, errors.Errorf("concurrency exception")
		//}

		if curEt == nil {
			return nil
		}

		curEt.Status = et.Status

		if err := h.d.UpdateExecutorTask(tx, curEt); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	go func() { h.c <- et.ID }()
}

type ExecutorTaskHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewExecutorTaskHandler(log zerolog.Logger, ah *action.ActionHandler) *ExecutorTaskHandler {
	return &ExecutorTaskHandler{log: log, ah: ah}
}

func (h *ExecutorTaskHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)

	// TODO(sgotti) Check authorized call from executors
	etID := vars["taskid"]
	if etID == "" {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Errorf("taskid is empty")))
		return
	}

	et, err := h.ah.GetExecutorTask(ctx, etID)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, et); err != nil {
		h.log.Err(err).Send()
	}
}

type ExecutorTasksHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewExecutorTasksHandler(log zerolog.Logger, ah *action.ActionHandler) *ExecutorTasksHandler {
	return &ExecutorTasksHandler{log: log, ah: ah}
}

func (h *ExecutorTasksHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)

	// TODO(sgotti) Check authorized call from executors
	executorID := vars["executorid"]
	if executorID == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	ets, err := h.ah.GetExecutorTasks(ctx, executorID)
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(ets); err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
}

type ArchivesHandler struct {
	log zerolog.Logger
	ost *objectstorage.ObjStorage
}

func NewArchivesHandler(log zerolog.Logger, ost *objectstorage.ObjStorage) *ArchivesHandler {
	return &ArchivesHandler{
		log: log,
		ost: ost,
	}
}

func (h *ArchivesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// TODO(sgotti) Check authorized call from executors

	taskID := r.URL.Query().Get("taskid")
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

	w.Header().Set("Cache-Control", "no-cache")

	if err := h.readArchive(taskID, step, w); err != nil {
		switch {
		case util.APIErrorIs(err, util.ErrNotExist):
			http.Error(w, err.Error(), http.StatusNotFound)
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
}

func (h *ArchivesHandler) readArchive(rtID string, step int, w io.Writer) error {
	archivePath := store.OSTRunTaskArchivePath(rtID, step)
	f, err := h.ost.ReadObject(archivePath)
	if err != nil {
		if objectstorage.IsNotExist(err) {
			return util.NewAPIError(util.ErrNotExist, err)
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
	ost *objectstorage.ObjStorage
}

func NewCacheHandler(log zerolog.Logger, ost *objectstorage.ObjStorage) *CacheHandler {
	return &CacheHandler{
		log: log,
		ost: ost,
	}
}

func (h *CacheHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	// TODO(sgotti) Check authorized call from executors

	// keep and use the escaped path
	key := vars["key"]
	if key == "" {
		http.Error(w, "empty cache key", http.StatusBadRequest)
		return
	}
	if len(key) > common.MaxCacheKeyLength {
		http.Error(w, "cache key too long", http.StatusBadRequest)
		return
	}
	query := r.URL.Query()
	_, prefix := query["prefix"]

	matchedKey, err := matchCache(h.ost, key, prefix)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if matchedKey == "" {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	if r.Method == "HEAD" {
		return
	}

	w.Header().Set("Cache-Control", "no-cache")

	if err := h.readCache(matchedKey, w); err != nil {
		switch {
		case util.APIErrorIs(err, util.ErrNotExist):
			http.Error(w, err.Error(), http.StatusNotFound)
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
}

func matchCache(ost *objectstorage.ObjStorage, key string, prefix bool) (string, error) {
	cachePath := store.OSTCachePath(key)

	if prefix {
		doneCh := make(chan struct{})
		defer close(doneCh)

		// get the latest modified object
		var lastObject *objectstorage.ObjectInfo
		for object := range ost.List(store.OSTCacheDir()+"/"+key, "", false, doneCh) {
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

	_, err := ost.Stat(cachePath)
	if objectstorage.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", errors.WithStack(err)
	}
	return key, nil
}

func (h *CacheHandler) readCache(key string, w io.Writer) error {
	cachePath := store.OSTCachePath(key)
	f, err := h.ost.ReadObject(cachePath)
	if err != nil {
		if objectstorage.IsNotExist(err) {
			return util.NewAPIError(util.ErrNotExist, err)
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
	ost *objectstorage.ObjStorage
}

func NewCacheCreateHandler(log zerolog.Logger, ost *objectstorage.ObjStorage) *CacheCreateHandler {
	return &CacheCreateHandler{
		log: log,
		ost: ost,
	}
}

func (h *CacheCreateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	// TODO(sgotti) Check authorized call from executors

	// keep and use the escaped path
	key := vars["key"]
	if key == "" {
		http.Error(w, "empty cache key", http.StatusBadRequest)
		return
	}
	if len(key) > common.MaxCacheKeyLength {
		http.Error(w, "cache key too long", http.StatusBadRequest)
		return
	}

	w.Header().Set("Cache-Control", "no-cache")

	matchedKey, err := matchCache(h.ost, key, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if matchedKey != "" {
		http.Error(w, "", http.StatusNotModified)
		return
	}

	size := int64(-1)
	sizeStr := r.Header.Get("Content-Length")
	if sizeStr != "" {
		size, err = strconv.ParseInt(sizeStr, 10, 64)
		if err != nil {
			http.Error(w, "", http.StatusBadRequest)
			return
		}
	}

	cachePath := store.OSTCachePath(key)
	if err := h.ost.WriteObject(cachePath, r.Body, size, false); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
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
	ctx := r.Context()
	vars := mux.Vars(r)

	// TODO(sgotti) Check authorized call from executors
	executorID := vars["executorid"]
	if executorID == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		executor, err := h.d.GetExecutorByExecutorID(tx, executorID)
		if err != nil {
			return errors.WithStack(err)
		}
		if executor == nil {
			return util.NewAPIError(util.ErrNotExist, errors.Errorf("executor with executor id %s doesn't exist", executorID))
		}

		if err := h.d.DeleteExecutor(tx, executor.ID); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}
}
