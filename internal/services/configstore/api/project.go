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
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/configstore/command"
	"github.com/sorintlab/agola/internal/services/configstore/readdb"
	"github.com/sorintlab/agola/internal/services/types"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type ProjectHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewProjectHandler(logger *zap.Logger, readDB *readdb.ReadDB) *ProjectHandler {
	return &ProjectHandler{log: logger.Sugar(), readDB: readDB}
}

func (h *ProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectID := vars["projectid"]

	var project *types.Project
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		project, err = h.readDB.GetProject(tx, projectID)
		return err
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if project == nil {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	if err := json.NewEncoder(w).Encode(project); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type ProjectByNameHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewProjectByNameHandler(logger *zap.Logger, readDB *readdb.ReadDB) *ProjectByNameHandler {
	return &ProjectByNameHandler{log: logger.Sugar(), readDB: readDB}
}

func (h *ProjectByNameHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ownerID := vars["ownerid"]
	projectName := vars["projectname"]

	var project *types.Project
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		project, err = h.readDB.GetOwnerProjectByName(tx, ownerID, projectName)
		return err
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if project == nil {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	if err := json.NewEncoder(w).Encode(project); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type CreateProjectHandler struct {
	log    *zap.SugaredLogger
	ch     *command.CommandHandler
	readDB *readdb.ReadDB
}

func NewCreateProjectHandler(logger *zap.Logger, ch *command.CommandHandler) *CreateProjectHandler {
	return &CreateProjectHandler{log: logger.Sugar(), ch: ch}
}

func (h *CreateProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req types.Project
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	project, err := h.ch.CreateProject(ctx, &req)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := json.NewEncoder(w).Encode(project); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type DeleteProjectHandler struct {
	log *zap.SugaredLogger
	ch  *command.CommandHandler
}

func NewDeleteProjectHandler(logger *zap.Logger, ch *command.CommandHandler) *DeleteProjectHandler {
	return &DeleteProjectHandler{log: logger.Sugar(), ch: ch}
}

func (h *DeleteProjectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	projectID := vars["projectid"]

	if err := h.ch.DeleteProject(ctx, projectID); err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
}

const (
	DefaultProjectsLimit = 10
	MaxProjectsLimit     = 20
)

type ProjectsHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewProjectsHandler(logger *zap.Logger, readDB *readdb.ReadDB) *ProjectsHandler {
	return &ProjectsHandler{log: logger.Sugar(), readDB: readDB}
}

func (h *ProjectsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ownerID := vars["ownerid"]

	query := r.URL.Query()

	limitS := query.Get("limit")
	limit := DefaultProjectsLimit
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
	if limit > MaxProjectsLimit {
		limit = MaxProjectsLimit
	}
	asc := false
	if _, ok := query["asc"]; ok {
		asc = true
	}

	start := query.Get("start")

	var projects []*types.Project
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		projects, err = h.readDB.GetOwnerProjects(tx, ownerID, start, limit, asc)
		return err
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(projects); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
