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
	"time"

	"agola.io/agola/internal/etcd"
	"agola.io/agola/internal/objectstorage"
	"agola.io/agola/internal/services/runservice/action"
	"agola.io/agola/internal/services/runservice/common"
	"agola.io/agola/internal/services/runservice/store"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/runservice/types"
	errors "golang.org/x/xerrors"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type ExecutorStatusHandler struct {
	log *zap.SugaredLogger
	e   *etcd.Store
	ah  *action.ActionHandler
}

func NewExecutorStatusHandler(logger *zap.Logger, e *etcd.Store, ah *action.ActionHandler) *ExecutorStatusHandler {
	return &ExecutorStatusHandler{log: logger.Sugar(), e: e, ah: ah}
}

func (h *ExecutorStatusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// TODO(sgotti) Check authorized call from executors
	var executor *types.Executor
	d := json.NewDecoder(r.Body)
	defer r.Body.Close()

	if err := d.Decode(&executor); err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	// set last status update time
	executor.LastStatusUpdateTime = time.Now()

	if _, err := store.PutExecutor(ctx, h.e, executor); err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	if err := h.deleteStaleExecutors(ctx, executor); err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
}

func (h *ExecutorStatusHandler) deleteStaleExecutors(ctx context.Context, curExecutor *types.Executor) error {
	executors, err := store.GetExecutors(ctx, h.e)
	if err != nil {
		return err
	}

	for _, executor := range executors {
		if executor.ID == curExecutor.ID {
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
			if executor.ID == seID {
				active = true
				break
			}
		}
		if !active {
			if err := h.ah.DeleteExecutor(ctx, executor.ID); err != nil {
				h.log.Errorf("failed to delete executor %q: %v", executor.ID, err)
			}
		}
	}

	return nil
}

type ExecutorTaskStatusHandler struct {
	e *etcd.Store
	c chan<- *types.ExecutorTask
}

func NewExecutorTaskStatusHandler(e *etcd.Store, c chan<- *types.ExecutorTask) *ExecutorTaskStatusHandler {
	return &ExecutorTaskStatusHandler{e: e, c: c}
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

	if _, err := store.UpdateExecutorTaskStatus(ctx, h.e, et); err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	go func() { h.c <- et }()
}

type ExecutorTaskHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewExecutorTaskHandler(logger *zap.Logger, ah *action.ActionHandler) *ExecutorTaskHandler {
	return &ExecutorTaskHandler{log: logger.Sugar(), ah: ah}
}

func (h *ExecutorTaskHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)

	// TODO(sgotti) Check authorized call from executors
	etID := vars["taskid"]
	if etID == "" {
		httpError(w, util.NewErrBadRequest(errors.Errorf("taskid is empty")))
		return
	}

	et, err := h.ah.GetExecutorTask(ctx, etID)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusOK, et); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type ExecutorTasksHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewExecutorTasksHandler(logger *zap.Logger, ah *action.ActionHandler) *ExecutorTasksHandler {
	return &ExecutorTasksHandler{log: logger.Sugar(), ah: ah}
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
	log *zap.SugaredLogger
	ost *objectstorage.ObjStorage
}

func NewArchivesHandler(logger *zap.Logger, ost *objectstorage.ObjStorage) *ArchivesHandler {
	return &ArchivesHandler{
		log: logger.Sugar(),
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
		case util.IsNotExist(err):
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
			return util.NewErrNotExist(err)
		}
		return err
	}
	defer f.Close()

	br := bufio.NewReader(f)

	_, err = io.Copy(w, br)
	return err
}

type CacheHandler struct {
	log *zap.SugaredLogger
	ost *objectstorage.ObjStorage
}

func NewCacheHandler(logger *zap.Logger, ost *objectstorage.ObjStorage) *CacheHandler {
	return &CacheHandler{
		log: logger.Sugar(),
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
		case util.IsNotExist(err):
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
				return "", object.Err
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
		return "", err
	}
	return key, nil
}

func (h *CacheHandler) readCache(key string, w io.Writer) error {
	cachePath := store.OSTCachePath(key)
	f, err := h.ost.ReadObject(cachePath)
	if err != nil {
		if objectstorage.IsNotExist(err) {
			return util.NewErrNotExist(err)
		}
		return err
	}
	defer f.Close()

	br := bufio.NewReader(f)

	_, err = io.Copy(w, br)
	return err
}

type CacheCreateHandler struct {
	log *zap.SugaredLogger
	ost *objectstorage.ObjStorage
}

func NewCacheCreateHandler(logger *zap.Logger, ost *objectstorage.ObjStorage) *CacheCreateHandler {
	return &CacheCreateHandler{
		log: logger.Sugar(),
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
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewExecutorDeleteHandler(logger *zap.Logger, ah *action.ActionHandler) *ExecutorDeleteHandler {
	return &ExecutorDeleteHandler{
		log: logger.Sugar(),
		ah:  ah,
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

	if err := h.ah.DeleteExecutor(ctx, executorID); err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
}
