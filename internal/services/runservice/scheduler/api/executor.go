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
	"net/url"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/sorintlab/agola/internal/etcd"
	"github.com/sorintlab/agola/internal/objectstorage"
	"github.com/sorintlab/agola/internal/services/runservice/scheduler/command"
	"github.com/sorintlab/agola/internal/services/runservice/scheduler/common"
	"github.com/sorintlab/agola/internal/services/runservice/scheduler/store"
	"github.com/sorintlab/agola/internal/services/runservice/types"
	"go.uber.org/zap"
)

type ExecutorStatusHandler struct {
	e *etcd.Store
	c chan<- *types.ExecutorTask
}

func NewExecutorStatusHandler(e *etcd.Store, c chan<- *types.ExecutorTask) *ExecutorStatusHandler {
	return &ExecutorStatusHandler{e: e, c: c}
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

	if _, err := store.PutExecutor(ctx, h.e, executor); err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
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
	e *etcd.Store
}

func NewExecutorTaskHandler(e *etcd.Store) *ExecutorTaskHandler {
	return &ExecutorTaskHandler{e: e}
}

func (h *ExecutorTaskHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)

	// TODO(sgotti) Check authorized call from executors
	etID := vars["taskid"]
	if etID == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	et, err := store.GetExecutorTask(ctx, h.e, etID)
	if err != nil && err != etcd.ErrKeyNotFound {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	if et == nil {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	if err := json.NewEncoder(w).Encode(et); err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
}

type ExecutorTasksHandler struct {
	e *etcd.Store
}

func NewExecutorTasksHandler(e *etcd.Store) *ExecutorTasksHandler {
	return &ExecutorTasksHandler{e: e}
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

	ets, err := store.GetExecutorTasks(ctx, h.e, executorID)
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
	lts *objectstorage.ObjStorage
}

func NewArchivesHandler(logger *zap.Logger, lts *objectstorage.ObjStorage) *ArchivesHandler {
	return &ArchivesHandler{
		log: logger.Sugar(),
		lts: lts,
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
		switch err.(type) {
		case common.ErrNotExist:
			http.Error(w, err.Error(), http.StatusNotFound)
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
}

func (h *ArchivesHandler) readArchive(rtID string, step int, w io.Writer) error {
	archivePath := store.LTSRunArchivePath(rtID, step)
	f, err := h.lts.ReadObject(archivePath)
	if err != nil {
		if err == objectstorage.ErrNotExist {
			return common.NewErrNotExist(err)
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
	lts *objectstorage.ObjStorage
}

func NewCacheHandler(logger *zap.Logger, lts *objectstorage.ObjStorage) *CacheHandler {
	return &CacheHandler{
		log: logger.Sugar(),
		lts: lts,
	}
}

func (h *CacheHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	// TODO(sgotti) Check authorized call from executors
	key, err := url.PathUnescape(vars["key"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
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

	matchedKey, err := matchCache(h.lts, key, prefix)
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
		switch err.(type) {
		case common.ErrNotExist:
			http.Error(w, err.Error(), http.StatusNotFound)
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
}

func matchCache(lts *objectstorage.ObjStorage, key string, prefix bool) (string, error) {
	cachePath := store.LTSCachePath(key)

	if prefix {
		doneCh := make(chan struct{})
		defer close(doneCh)

		// get the latest modified object
		var lastObject *objectstorage.ObjectInfo
		for object := range lts.List(store.LTSCacheDir()+"/"+key, "", false, doneCh) {
			if object.Err != nil {
				return "", object.Err
			}

			if (lastObject == nil) || (lastObject != nil && lastObject.LastModified.Before(object.LastModified)) {
				lastObject = &object
			}

		}
		if lastObject == nil {
			return "", nil

		}
		return store.LTSCacheKey(lastObject.Path), nil
	}

	_, err := lts.Stat(cachePath)
	if err == objectstorage.ErrNotExist {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return key, nil
}

func (h *CacheHandler) readCache(key string, w io.Writer) error {
	cachePath := store.LTSCachePath(key)
	f, err := h.lts.ReadObject(cachePath)
	if err != nil {
		if err == objectstorage.ErrNotExist {
			return common.NewErrNotExist(err)
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
	lts *objectstorage.ObjStorage
}

func NewCacheCreateHandler(logger *zap.Logger, lts *objectstorage.ObjStorage) *CacheCreateHandler {
	return &CacheCreateHandler{
		log: logger.Sugar(),
		lts: lts,
	}
}

func (h *CacheCreateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	// TODO(sgotti) Check authorized call from executors
	key, err := url.PathUnescape(vars["key"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if key == "" {
		http.Error(w, "empty cache key", http.StatusBadRequest)
		return
	}
	if len(key) > common.MaxCacheKeyLength {
		http.Error(w, "cache key too long", http.StatusBadRequest)
		return
	}

	w.Header().Set("Cache-Control", "no-cache")

	matchedKey, err := matchCache(h.lts, key, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if matchedKey != "" {
		http.Error(w, "", http.StatusNotModified)
		return
	}

	cachePath := store.LTSCachePath(key)
	if err := h.lts.WriteObject(cachePath, r.Body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type ExecutorDeleteHandler struct {
	log *zap.SugaredLogger
	ch  *command.CommandHandler
}

func NewExecutorDeleteHandler(logger *zap.Logger, ch *command.CommandHandler) *ExecutorDeleteHandler {
	return &ExecutorDeleteHandler{
		log: logger.Sugar(),
		ch:  ch,
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

	if err := h.ch.DeleteExecutor(ctx, executorID); err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
}
