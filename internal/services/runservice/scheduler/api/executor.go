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
	// TODO(sgotti) Check authorized call from scheduler

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
